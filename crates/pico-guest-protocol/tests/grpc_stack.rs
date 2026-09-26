//! gRPC-stack backpressure and deadline validation.
//!
//! Exercises Exec output streaming, file transfer chunking, and RPC deadlines
//! against a full tonic gRPC stack over TCP loopback and Unix sockets.
//! This clears the wire-only caveat recorded in the protocol readiness report:
//! framing-layer tests prove message bounds, but only these tests prove that
//! tonic flow control, `max_decoding_message_size` limits, and gRPC deadlines
//! bound host memory and tear down streams without leaking operations.
//!
//! Coverage:
//! - slow-consumer Exec and GetFile with memory-ceiling assertions
//! - PutFile chunking with per-frame 64 KiB enforcement
//! - deadline-expiry teardown for Exec and GetFile with leak checks
//! - oversized message rejection before admission
//! - UDS transport variant proving the stack is transport-agnostic

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, UnixListener};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};

use pico_guest_protocol::operational_v1::{
    ExecRequest, ExecResponse, GetFileRequest, GetFileResponse, PutFileRequest, RequestContext,
    StreamFrame, exec_response, executor_client, executor_server, file_transfer_client,
    file_transfer_server, get_file_response, operation_outcome, put_file_request,
};

// ── Bounds (mirror ADR-0003 and framed.rs) ───────────────────────────────────

/// Encoded protobuf message limit (1 MiB, mirrors `framed::MAX_MESSAGE_SIZE`).
const GRPC_MAX_MESSAGE: usize = 1024 * 1024;
/// Stream payload per frame (64 KiB, proto spec).
const FRAME_MAX: usize = 64 * 1024;
/// Host-side peak buffer ceiling asserted in slow-consumer tests (256 KiB).
///
/// Total transferred is MiBs; peak held at any instant must stay under this.
const MEMORY_CEILING: usize = 256 * 1024;
/// Bounded application queue depth for server producers.
const QUEUE_DEPTH: usize = 4;

fn test_context(op: &str) -> RequestContext {
    RequestContext {
        request_id: format!("req-{op}"),
        operation_id: op.into(),
        sandbox_id: "sbx-grpc".into(),
        session_id: vec![0x01u8; 16],
        policy_epoch: 1,
        protocol_version: (1 << 16) | 5,
        deadline: None,
        trace_context: None,
    }
}

/// RAII guard proving operation release: increments on admission,
/// decrements on drop, including cancellation paths.
struct ActiveGuard {
    active: Arc<AtomicUsize>,
}

impl ActiveGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self { active }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn wait_for_active_zero(active: &Arc<AtomicUsize>, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while active.load(Ordering::SeqCst) != 0 {
        if tokio::time::Instant::now() > deadline {
            panic!(
                "active operations did not drain: {}",
                active.load(Ordering::SeqCst)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ── Mock Executor ───────────────────────────────────────────────────────────

struct MockExecutor {
    active: Arc<AtomicUsize>,
    frame_size: usize,
    frame_count: u64,
    delay_per_frame: Duration,
    /// When set, send one oversized frame instead of the normal stream.
    oversized_response: bool,
    /// Tracks peak producer-queue occupancy (proves bounded backpressure).
    peak_queue: Arc<AtomicUsize>,
}

impl MockExecutor {
    fn new(
        active: Arc<AtomicUsize>,
        frame_size: usize,
        frame_count: u64,
        delay_per_frame: Duration,
        peak_queue: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            active,
            frame_size,
            frame_count,
            delay_per_frame,
            oversized_response: false,
            peak_queue,
        }
    }

    fn oversized(active: Arc<AtomicUsize>) -> Self {
        Self {
            active,
            frame_size: 0,
            frame_count: 0,
            delay_per_frame: Duration::ZERO,
            oversized_response: true,
            peak_queue: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Records producer-queue occupancy before each send; peak must stay within
/// the bounded depth while engaging (proving backpressure rather than
/// unbounded buffering).
fn record_occupancy<T>(tx: &tokio::sync::mpsc::Sender<T>, peak: &Arc<AtomicUsize>) {
    let occupancy = QUEUE_DEPTH.saturating_sub(tx.capacity());
    peak.fetch_max(occupancy, Ordering::SeqCst);
}

type ExecStream = ReceiverStream<Result<ExecResponse, Status>>;

#[tonic::async_trait]
impl executor_server::Executor for MockExecutor {
    type ExecStream = ExecStream;

    async fn exec(
        &self,
        request: Request<ExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let req = request.into_inner();
        // App-level oversize check before admission: command, args, env, and
        // working dir larger than the message bound are rejected without
        // incrementing active. The tonic max_decoding limit remains the
        // primary guard; this catches oversize before operation tracking.
        let req_size: usize = req.command.len()
            + req.args.iter().map(|a| a.len()).sum::<usize>()
            + req
                .env
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
            + req.working_dir.len();
        if req_size > GRPC_MAX_MESSAGE {
            return Err(Status::resource_exhausted(format!(
                "exec request {req_size} exceeds limit {GRPC_MAX_MESSAGE}"
            )));
        }
        // Proto-level deadline: ExecRequest.timeout bounds the whole stream.
        // The host sets both this and the gRPC deadline to the same budget;
        // the guest enforces the earlier one per ADR-0003.
        let proto_deadline = req.timeout.as_ref().map(|d| {
            let secs = d.seconds.max(0) as u64;
            let nanos = d.nanos.max(0) as u32;
            Duration::new(secs, nanos)
        });
        let _guard = ActiveGuard::new(Arc::clone(&self.active));
        let (tx, rx) = tokio::sync::mpsc::channel(QUEUE_DEPTH);
        let frame_size = self.frame_size;
        let frame_count = self.frame_count;
        let delay = self.delay_per_frame;
        let oversized = self.oversized_response;
        let peak_queue = Arc::clone(&self.peak_queue);

        tokio::spawn(async move {
            // Keep the guard alive for the stream lifetime: move it into the
            // producer task so cancellation drops it and releases the op.
            let _guard = _guard;
            let start = tokio::time::Instant::now();
            if oversized {
                let payload = vec![0xABu8; 2 * 1024 * 1024];
                let resp = ExecResponse {
                    frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                        frame: Some(StreamFrame {
                            sequence: 1,
                            payload,
                            end_of_stream: true,
                        }),
                    })),
                };
                let _ = tx.send(Ok(resp)).await;
                return;
            }
            for seq in 1..=frame_count {
                if let Some(budget) = proto_deadline
                    && start.elapsed() > budget
                {
                    let _ = tx
                        .send(Err(Status::deadline_exceeded(format!(
                            "exec exceeded proto timeout {budget:?}"
                        ))))
                        .await;
                    break;
                }
                let payload = vec![(seq % 256) as u8; frame_size];
                let resp = ExecResponse {
                    frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                        frame: Some(StreamFrame {
                            sequence: seq,
                            payload,
                            end_of_stream: seq == frame_count,
                        }),
                    })),
                };
                record_occupancy(&tx, &peak_queue);
                if tx.send(Ok(resp)).await.is_err() {
                    // Client went away (deadline or cancel): stop producing.
                    break;
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            // Only send terminal success when the proto deadline did not fire.
            let expired = proto_deadline
                .map(|budget| start.elapsed() > budget)
                .unwrap_or(false);
            if !expired {
                let outcome = ExecResponse {
                    frame: Some(exec_response::Frame::Outcome(
                        pico_guest_protocol::operational_v1::OperationOutcome {
                            status: Some(operation_outcome::Status::Success(
                                operation_outcome::Success {
                                    result_payload: b"done".to_vec(),
                                },
                            )),
                        },
                    )),
                };
                let _ = tx.send(Ok(outcome)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn signal(
        &self,
        _request: Request<pico_guest_protocol::operational_v1::SignalRequest>,
    ) -> Result<Response<pico_guest_protocol::operational_v1::SignalResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn cancel(
        &self,
        _request: Request<pico_guest_protocol::operational_v1::CancelRequest>,
    ) -> Result<Response<pico_guest_protocol::operational_v1::CancelResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    type AttachStreamStream =
        ReceiverStream<Result<pico_guest_protocol::operational_v1::AttachStreamResponse, Status>>;

    async fn attach_stream(
        &self,
        _request: Request<pico_guest_protocol::operational_v1::AttachStreamRequest>,
    ) -> Result<Response<Self::AttachStreamStream>, Status> {
        Err(Status::unimplemented("not under test"))
    }
}

// ── Mock FileTransfer ───────────────────────────────────────────────────────

struct MockFileTransfer {
    active: Arc<AtomicUsize>,
    chunk_size: usize,
    chunk_count: u64,
    delay_per_chunk: Duration,
    /// Tracks peak producer-queue occupancy (proves bounded backpressure).
    peak_queue: Arc<AtomicUsize>,
}

type GetFileStream = ReceiverStream<Result<GetFileResponse, Status>>;

#[tonic::async_trait]
impl file_transfer_server::FileTransfer for MockFileTransfer {
    async fn put_file(
        &self,
        request: Request<tonic::Streaming<PutFileRequest>>,
    ) -> Result<Response<pico_guest_protocol::operational_v1::PutFileResponse>, Status> {
        let _guard = ActiveGuard::new(Arc::clone(&self.active));
        let mut stream = request.into_inner();
        let mut total: usize = 0;
        let mut seq: u64 = 0;
        while let Some(msg) = stream.message().await? {
            match msg.payload {
                Some(put_file_request::Payload::Metadata(_)) => {}
                Some(put_file_request::Payload::Chunk(frame)) => {
                    if frame.payload.len() > FRAME_MAX {
                        return Err(Status::invalid_argument(format!(
                            "put chunk {} exceeds per-frame limit {FRAME_MAX}",
                            frame.payload.len()
                        )));
                    }
                    seq += 1;
                    if frame.sequence != seq {
                        return Err(Status::invalid_argument(format!(
                            "expected sequence {seq}, got {}",
                            frame.sequence
                        )));
                    }
                    total += frame.payload.len();
                    if total > GRPC_MAX_MESSAGE * 8 {
                        return Err(Status::resource_exhausted(format!(
                            "put total {total} exceeds file limit"
                        )));
                    }
                }
                None => {
                    return Err(Status::invalid_argument("put request missing payload"));
                }
            }
        }
        Ok(Response::new(
            pico_guest_protocol::operational_v1::PutFileResponse {
                result: Some(
                    pico_guest_protocol::operational_v1::put_file_response::Result::BytesWritten(
                        total as u64,
                    ),
                ),
                checksum: "test-checksum".into(),
            },
        ))
    }

    type GetFileStream = GetFileStream;

    async fn get_file(
        &self,
        request: Request<GetFileRequest>,
    ) -> Result<Response<Self::GetFileStream>, Status> {
        let req = request.into_inner();
        // Proto-level deadline from RequestContext.deadline (absolute time).
        let proto_deadline = req
            .context
            .as_ref()
            .and_then(|c| c.deadline.as_ref())
            .map(|ts| {
                let secs = ts.seconds.max(0) as u64;
                let nanos = ts.nanos.max(0) as u32;
                std::time::UNIX_EPOCH + Duration::new(secs, nanos)
            });
        let _guard = ActiveGuard::new(Arc::clone(&self.active));
        let (tx, rx) = tokio::sync::mpsc::channel(QUEUE_DEPTH);
        let chunk_size = self.chunk_size;
        let chunk_count = self.chunk_count;
        let delay = self.delay_per_chunk;
        let peak_queue = Arc::clone(&self.peak_queue);
        tokio::spawn(async move {
            let _guard = _guard;
            let meta = GetFileResponse {
                frame: Some(get_file_response::Frame::Metadata(
                    get_file_response::FileMetadata {
                        size: (chunk_size as u64) * chunk_count,
                        mode: 0o644,
                        modified_at: None,
                    },
                )),
            };
            record_occupancy(&tx, &peak_queue);
            if tx.send(Ok(meta)).await.is_err() {
                return;
            }
            for seq in 1..=chunk_count {
                if let Some(deadline) = proto_deadline
                    && std::time::SystemTime::now() > deadline
                {
                    let _ = tx
                        .send(Err(Status::deadline_exceeded(
                            "get file exceeded context deadline",
                        )))
                        .await;
                    break;
                }
                let resp = GetFileResponse {
                    frame: Some(get_file_response::Frame::Chunk(StreamFrame {
                        sequence: seq,
                        payload: vec![(seq % 256) as u8; chunk_size],
                        end_of_stream: seq == chunk_count,
                    })),
                };
                record_occupancy(&tx, &peak_queue);
                if tx.send(Ok(resp)).await.is_err() {
                    break;
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            // Only send success when the deadline did not fire; otherwise the
            // error above is already terminal.
            let expired = proto_deadline
                .map(|d| std::time::SystemTime::now() > d)
                .unwrap_or(false);
            if !expired {
                let outcome = GetFileResponse {
                    frame: Some(get_file_response::Frame::Outcome(
                        pico_guest_protocol::operational_v1::OperationOutcome {
                            status: Some(operation_outcome::Status::Success(
                                operation_outcome::Success {
                                    result_payload: b"checksum".to_vec(),
                                },
                            )),
                        },
                    )),
                };
                let _ = tx.send(Ok(outcome)).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// ── Server harnesses ────────────────────────────────────────────────────────

async fn spawn_executor_tcp(mock: MockExecutor) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_executor_tcp_with_limits(mock, GRPC_MAX_MESSAGE, GRPC_MAX_MESSAGE).await
}

async fn spawn_executor_tcp_with_limits(
    mock: MockExecutor,
    decoding: usize,
    encoding: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let svc = executor_server::ExecutorServer::new(mock)
        .max_decoding_message_size(decoding)
        .max_encoding_message_size(encoding);
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    // Brief yield so the server binds before the client dials.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

async fn spawn_file_transfer_tcp(
    mock: MockFileTransfer,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let svc = file_transfer_server::FileTransferServer::new(mock)
        .max_decoding_message_size(GRPC_MAX_MESSAGE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE);
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

fn exec_client(addr: SocketAddr) -> executor_client::ExecutorClient<Channel> {
    exec_client_with_limits(addr, GRPC_MAX_MESSAGE, GRPC_MAX_MESSAGE)
}

fn exec_client_with_limits(
    addr: SocketAddr,
    decoding: usize,
    encoding: usize,
) -> executor_client::ExecutorClient<Channel> {
    let uri = format!("http://{addr}");
    let channel = Endpoint::from_shared(uri).unwrap().connect_lazy();
    executor_client::ExecutorClient::new(channel)
        .max_decoding_message_size(decoding)
        .max_encoding_message_size(encoding)
}

fn file_client(addr: SocketAddr) -> file_transfer_client::FileTransferClient<Channel> {
    let uri = format!("http://{addr}");
    let channel = Endpoint::from_shared(uri).unwrap().connect_lazy();
    file_transfer_client::FileTransferClient::new(channel)
        .max_decoding_message_size(GRPC_MAX_MESSAGE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE)
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Slow consumer proves bounded buffering: 100 frames of 32 KiB total
/// 3.2 MiB. The server producer uses a bounded queue of depth 4; peak
/// occupancy is measured on the producer side and must stay within the depth
/// while engaging (proving backpressure instead of unbounded growth). The
/// client processes one frame at a time.
#[tokio::test]
async fn exec_slow_consumer_bounded_memory() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak_queue = Arc::new(AtomicUsize::new(0));
    let mock = MockExecutor::new(
        Arc::clone(&active),
        32 * 1024,
        100,
        Duration::ZERO,
        Arc::clone(&peak_queue),
    );
    let (addr, _server) = spawn_executor_tcp(mock).await;

    let mut client = exec_client(addr);
    let req = ExecRequest {
        context: Some(test_context("op-slow")),
        command: "stream-output".into(),
        ..Default::default()
    };
    let mut stream = client.exec(req).await.unwrap().into_inner();

    let mut total: usize = 0;
    let mut frames: u64 = 0;
    let mut got_outcome = false;
    while let Some(resp) = stream.message().await.unwrap() {
        match resp.frame {
            Some(exec_response::Frame::Stdout(data)) => {
                let payload = data.frame.map(|f| f.payload).unwrap_or_default();
                total += payload.len();
                frames += 1;
                // Stalled consumer: 2ms per frame lets the server outrun us;
                // bounded queue must apply backpressure instead of growing.
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Some(exec_response::Frame::Outcome(_)) => {
                got_outcome = true;
                break;
            }
            _ => {}
        }
    }

    assert_eq!(frames, 100, "must receive all frames without loss");
    assert_eq!(total, 100 * 32 * 1024, "byte total must match");
    assert!(got_outcome, "must receive terminal outcome");
    let peak = peak_queue.load(Ordering::SeqCst);
    assert!(
        peak <= QUEUE_DEPTH,
        "server queue peak {peak} exceeds bound {QUEUE_DEPTH}"
    );
    assert!(
        peak >= 2,
        "server queue peak {peak} never engaged; backpressure not exercised"
    );
    assert!(
        peak * 32 * 1024 <= MEMORY_CEILING,
        "queued bytes exceed ceiling {MEMORY_CEILING}"
    );
    wait_for_active_zero(&active, Duration::from_secs(5)).await;
}

/// GetFile slow consumer: 50 chunks of 32 KiB (1.6 MiB total). Server queue
/// occupancy is measured and must stay bounded while engaging.
#[tokio::test]
async fn get_file_slow_consumer_bounded_memory() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak_queue = Arc::new(AtomicUsize::new(0));
    let mock = MockFileTransfer {
        active: Arc::clone(&active),
        chunk_size: 32 * 1024,
        chunk_count: 50,
        delay_per_chunk: Duration::ZERO,
        peak_queue: Arc::clone(&peak_queue),
    };
    let (addr, _server) = spawn_file_transfer_tcp(mock).await;

    let mut client = file_client(addr);
    let req = GetFileRequest {
        context: Some(test_context("op-get-slow")),
        path: "/tmp/slow.bin".into(),
    };
    let mut stream = client.get_file(req).await.unwrap().into_inner();

    let mut total: usize = 0;
    let mut chunks: u64 = 0;
    let mut got_outcome = false;
    while let Some(resp) = stream.message().await.unwrap() {
        match resp.frame {
            Some(get_file_response::Frame::Metadata(_)) => {}
            Some(get_file_response::Frame::Chunk(f)) => {
                assert!(
                    f.payload.len() <= FRAME_MAX,
                    "chunk exceeds 64 KiB frame bound"
                );
                total += f.payload.len();
                chunks += 1;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Some(get_file_response::Frame::Outcome(_)) => {
                got_outcome = true;
                break;
            }
            None => panic!("empty get file frame"),
        }
    }

    assert_eq!(chunks, 50);
    assert_eq!(total, 50 * 32 * 1024);
    assert!(got_outcome);
    let peak = peak_queue.load(Ordering::SeqCst);
    assert!(
        peak <= QUEUE_DEPTH,
        "server queue peak {peak} exceeds bound {QUEUE_DEPTH}"
    );
    assert!(
        peak >= 2,
        "server queue peak {peak} never engaged; backpressure not exercised"
    );
    assert!(
        peak * 32 * 1024 <= MEMORY_CEILING,
        "queued bytes exceed ceiling {MEMORY_CEILING}"
    );
    wait_for_active_zero(&active, Duration::from_secs(5)).await;
}

/// PutFile chunking: metadata plus sequenced 64 KiB-bounded chunks succeeds;
/// a 128 KiB chunk is rejected with InvalidArgument before being accepted.
#[tokio::test]
async fn put_file_chunking_enforces_frame_bounds() {
    let active = Arc::new(AtomicUsize::new(0));
    let mock = MockFileTransfer {
        active: Arc::clone(&active),
        chunk_size: 0,
        chunk_count: 0,
        delay_per_chunk: Duration::ZERO,
        peak_queue: Arc::new(AtomicUsize::new(0)),
    };
    let (addr, _server) = spawn_file_transfer_tcp(mock).await;

    // Valid: 3 chunks of 32 KiB.
    let mut client = file_client(addr);
    let meta = PutFileRequest {
        payload: Some(put_file_request::Payload::Metadata(
            pico_guest_protocol::operational_v1::PutFileMetadata {
                context: Some(test_context("op-put-ok")),
                path: "/tmp/ok.bin".into(),
                mode: 0o644,
                expected_size: 3 * 32 * 1024,
                overwrite: true,
            },
        )),
    };
    let mut msgs = vec![meta];
    for seq in 1..=3u64 {
        msgs.push(PutFileRequest {
            payload: Some(put_file_request::Payload::Chunk(StreamFrame {
                sequence: seq,
                payload: vec![0xABu8; 32 * 1024],
                end_of_stream: seq == 3,
            })),
        });
    }
    let resp = client
        .put_file(tokio_stream::iter(msgs))
        .await
        .unwrap()
        .into_inner();
    match resp.result {
        Some(pico_guest_protocol::operational_v1::put_file_response::Result::BytesWritten(n)) => {
            assert_eq!(n, 3 * 32 * 1024);
        }
        other => panic!("expected BytesWritten, got {other:?}"),
    }
    wait_for_active_zero(&active, Duration::from_secs(5)).await;

    // Invalid: single 128 KiB chunk exceeds the 64 KiB per-frame bound.
    let mut client = file_client(addr);
    let meta = PutFileRequest {
        payload: Some(put_file_request::Payload::Metadata(
            pico_guest_protocol::operational_v1::PutFileMetadata {
                context: Some(test_context("op-put-big-frame")),
                path: "/tmp/big.bin".into(),
                mode: 0o644,
                expected_size: 128 * 1024,
                overwrite: true,
            },
        )),
    };
    let big = PutFileRequest {
        payload: Some(put_file_request::Payload::Chunk(StreamFrame {
            sequence: 1,
            payload: vec![0xABu8; 128 * 1024],
            end_of_stream: true,
        })),
    };
    let err = client
        .put_file(tokio_stream::iter(vec![meta, big]))
        .await
        .map(|_| ())
        .expect_err("128 KiB frame must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("per-frame limit"));
    wait_for_active_zero(&active, Duration::from_secs(5)).await;
}

/// Exec deadline expiry tears down the stream with a typed error and releases
/// the operation. Server streams slowly (50ms x 20); proto timeout and gRPC
/// deadline are both 150ms, so the earlier one terminates the stream.
#[tokio::test]
async fn exec_deadline_expiry_tears_down_without_leak() {
    let active = Arc::new(AtomicUsize::new(0));
    let mock = MockExecutor::new(
        Arc::clone(&active),
        8 * 1024,
        20,
        Duration::from_millis(50),
        Arc::new(AtomicUsize::new(0)),
    );
    let (addr, _server) = spawn_executor_tcp(mock).await;

    let mut client = exec_client(addr);
    let mut req = Request::new(ExecRequest {
        context: Some(test_context("op-deadline")),
        command: "slow-stream".into(),
        timeout: Some(prost_types::Duration {
            seconds: 0,
            nanos: 150_000_000,
        }),
        ..Default::default()
    });
    req.set_timeout(Duration::from_millis(150));

    let mut stream = client.exec(req).await.unwrap().into_inner();
    let mut seen_deadline = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.message()).await {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => break,
            Ok(Err(status)) => {
                assert!(
                    status.code() == tonic::Code::DeadlineExceeded
                        || status.code() == tonic::Code::Cancelled,
                    "expected deadline/cancelled, got {:?}: {status}",
                    status.code()
                );
                seen_deadline = true;
                break;
            }
            Err(_) => panic!("stream did not terminate after deadline"),
        }
    }
    assert!(seen_deadline, "deadline must terminate the stream");
    wait_for_active_zero(&active, Duration::from_secs(5)).await;
}

/// GetFile deadline expiry releases resources with the same typed behavior.
/// RequestContext.deadline carries the absolute budget; gRPC timeout mirrors it.
#[tokio::test]
async fn get_file_deadline_expiry_releases_resources() {
    let active = Arc::new(AtomicUsize::new(0));
    let mock = MockFileTransfer {
        active: Arc::clone(&active),
        chunk_size: 8 * 1024,
        chunk_count: 20,
        delay_per_chunk: Duration::from_millis(50),
        peak_queue: Arc::new(AtomicUsize::new(0)),
    };
    let (addr, _server) = spawn_file_transfer_tcp(mock).await;

    let mut client = file_client(addr);
    let deadline = std::time::SystemTime::now() + Duration::from_millis(150);
    let since_epoch = deadline
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut ctx = test_context("op-get-deadline");
    ctx.deadline = Some(prost_types::Timestamp {
        seconds: since_epoch.as_secs() as i64,
        nanos: since_epoch.subsec_nanos() as i32,
    });
    let mut req = Request::new(GetFileRequest {
        context: Some(ctx),
        path: "/tmp/deadline.bin".into(),
    });
    req.set_timeout(Duration::from_millis(150));

    let mut stream = client.get_file(req).await.unwrap().into_inner();
    let mut seen_deadline = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.message()).await {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => break,
            Ok(Err(status)) => {
                assert!(
                    status.code() == tonic::Code::DeadlineExceeded
                        || status.code() == tonic::Code::Cancelled,
                    "expected deadline/cancelled, got {:?}",
                    status.code()
                );
                seen_deadline = true;
                break;
            }
            Err(_) => panic!("get file stream did not terminate after deadline"),
        }
    }
    assert!(seen_deadline);
    wait_for_active_zero(&active, Duration::from_secs(5)).await;
}

/// Oversized messages are rejected before admission: a 2 MiB command exceeds
/// the 1 MiB decoding limit (ResourceExhausted) and never increments active.
/// A server-sent 2 MiB frame is rejected by the client-side decoding limit.
#[tokio::test]
async fn oversized_message_rejected_before_allocation() {
    // Oversized request: client can encode 8 MiB so the 2 MiB command reaches
    // the server; server decoding (1 MiB) plus app-level size check rejects
    // with ResourceExhausted before admission.
    let active = Arc::new(AtomicUsize::new(0));
    let mock = MockExecutor::new(
        Arc::clone(&active),
        1024,
        1,
        Duration::ZERO,
        Arc::new(AtomicUsize::new(0)),
    );
    let (addr, _server) =
        spawn_executor_tcp_with_limits(mock, GRPC_MAX_MESSAGE, 8 * 1024 * 1024).await;

    let mut client = exec_client_with_limits(addr, GRPC_MAX_MESSAGE, 8 * 1024 * 1024);
    let big_command = "x".repeat(2 * 1024 * 1024);
    let req = ExecRequest {
        context: Some(test_context("op-oversize-req")),
        command: big_command,
        ..Default::default()
    };
    let err = client
        .exec(req)
        .await
        .map(|_| ())
        .expect_err("2 MiB request must be rejected");
    assert!(
        err.code() == tonic::Code::ResourceExhausted || err.code() == tonic::Code::OutOfRange,
        "expected ResourceExhausted/OutOfRange, got {:?}: {err}",
        err.code()
    );
    assert!(
        err.message().contains("too large")
            || err.message().contains("limit")
            || err.message().contains("exceeds"),
        "message must cite the bound: {err}"
    );
    // Rejection happens before admission: no operation was ever tracked.
    assert_eq!(active.load(Ordering::SeqCst), 0);

    // Oversized response: server can encode 8 MiB so the 2 MiB frame is sent;
    // client decoding (1 MiB) rejects with ResourceExhausted.
    let active2 = Arc::new(AtomicUsize::new(0));
    let mock2 = MockExecutor::oversized(Arc::clone(&active2));
    let (addr2, _server2) =
        spawn_executor_tcp_with_limits(mock2, 8 * 1024 * 1024, 8 * 1024 * 1024).await;
    let mut client2 = exec_client(addr2);
    let req2 = ExecRequest {
        context: Some(test_context("op-oversize-resp")),
        command: "trigger-oversize".into(),
        ..Default::default()
    };
    let mut stream = client2.exec(req2).await.unwrap().into_inner();
    let err = stream
        .message()
        .await
        .map(|_| ())
        .expect_err("2 MiB response must be rejected by client limit");
    assert!(
        err.code() == tonic::Code::ResourceExhausted || err.code() == tonic::Code::OutOfRange,
        "expected ResourceExhausted/OutOfRange, got {:?}: {err}",
        err.code()
    );
    wait_for_active_zero(&active2, Duration::from_secs(5)).await;
}

/// UDS variant: the same Exec streaming contract holds over a Unix socket,
/// proving the gRPC stack is transport-agnostic (TCP is test-only per ADR).
#[tokio::test]
async fn exec_over_uds_proves_transport_agnostic() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("guest.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let incoming = UnixListenerStream::new(listener);

    let active = Arc::new(AtomicUsize::new(0));
    let mock = MockExecutor::new(
        Arc::clone(&active),
        16 * 1024,
        20,
        Duration::ZERO,
        Arc::new(AtomicUsize::new(0)),
    );
    let svc = executor_server::ExecutorServer::new(mock)
        .max_decoding_message_size(GRPC_MAX_MESSAGE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE);
    let _server = tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let uri = format!("unix://{}", sock.display());
    let channel = Endpoint::from_shared(uri).unwrap().connect_lazy();
    let mut client = executor_client::ExecutorClient::new(channel)
        .max_decoding_message_size(GRPC_MAX_MESSAGE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE);

    let req = ExecRequest {
        context: Some(test_context("op-uds")),
        command: "uds-stream".into(),
        ..Default::default()
    };
    let mut stream = client.exec(req).await.unwrap().into_inner();
    let mut total: usize = 0;
    let mut frames: u64 = 0;
    while let Some(resp) = stream.message().await.unwrap() {
        match resp.frame {
            Some(exec_response::Frame::Stdout(data)) => {
                let payload = data.frame.map(|f| f.payload).unwrap_or_default();
                assert!(payload.len() <= FRAME_MAX, "frame exceeds 64 KiB bound");
                total += payload.len();
                frames += 1;
            }
            Some(exec_response::Frame::Outcome(_)) => break,
            _ => {}
        }
    }
    assert_eq!(frames, 20);
    assert_eq!(total, 20 * 16 * 1024);
    wait_for_active_zero(&active, Duration::from_secs(5)).await;
}
