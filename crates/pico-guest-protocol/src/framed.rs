//! Length-prefixed protobuf framing over a byte-stream transport.
//!
//! The handshake uses plain framing:
//!   [4-byte big-endian length][protobuf-encoded message]
//!
//! The operational protocol adds a 1-byte message-type tag for
//! request/response dispatch:
//!   [4-byte big-endian length][1-byte message type][protobuf payload]
//!
//! The maximum message size is 1 MiB. Both sides enforce this limit.
//!
//! The framing layer is transport-agnostic: any stream implementing
//! [`AsyncRead`] + [`AsyncWrite`] + [`Unpin`] works (TCP for tests,
//! vsock for production).

use prost::Message;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Any byte stream usable as a guest-protocol transport.
pub trait TransportStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportStream for T {}

/// Maximum message size in bytes (1 MiB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// Operational protocol message type tags.
pub const TAG_EXEC_REQUEST: u8 = 0x01;
pub const TAG_EXEC_RESPONSE: u8 = 0x02;
pub const TAG_CANCEL_REQUEST: u8 = 0x03;
pub const TAG_CANCEL_RESPONSE: u8 = 0x04;
pub const TAG_SIGNAL_REQUEST: u8 = 0x05;
pub const TAG_SIGNAL_RESPONSE: u8 = 0x06;
pub const TAG_ATTACH_STREAM_REQUEST: u8 = 0x07;
pub const TAG_ATTACH_STREAM_RESPONSE: u8 = 0x08;
pub const TAG_QUIESCE_REQUEST: u8 = 0x09;
pub const TAG_QUIESCE_RESPONSE: u8 = 0x0A;
pub const TAG_RESUME_NOTIFY_REQUEST: u8 = 0x0B;
pub const TAG_RESUME_NOTIFY_RESPONSE: u8 = 0x0C;
pub const TAG_PUT_FILE_REQUEST: u8 = 0x0D;
pub const TAG_PUT_FILE_RESPONSE: u8 = 0x0E;
pub const TAG_GET_FILE_REQUEST: u8 = 0x0F;
pub const TAG_GET_FILE_RESPONSE: u8 = 0x10;
pub const TAG_MOUNT_WORKSPACE_REQUEST: u8 = 0x11;
pub const TAG_MOUNT_WORKSPACE_RESPONSE: u8 = 0x12;
pub const TAG_STATS_REQUEST: u8 = 0x13;
pub const TAG_STATS_RESPONSE: u8 = 0x14;
pub const TAG_HEALTH_REQUEST: u8 = 0x15;
pub const TAG_HEALTH_RESPONSE: u8 = 0x16;
pub const TAG_SHUTDOWN_REQUEST: u8 = 0x17;
pub const TAG_SHUTDOWN_RESPONSE: u8 = 0x18;
pub const TAG_INJECT_SECRETS_REQUEST: u8 = 0x19;
pub const TAG_INJECT_SECRETS_RESPONSE: u8 = 0x1A;

/// Send a protobuf message with a 4-byte big-endian length prefix.
///
/// Used during the bootstrap handshake (no type tag). Takes only
/// [`AsyncWrite`] so split write halves can send without a read half.
///
/// # Errors
///
/// Returns an I/O error if the write fails or times out.
pub async fn send_message(
    stream: &mut (impl AsyncWrite + Unpin + Send),
    message: &impl Message,
    timeout: Duration,
) -> IoResult<()> {
    let encoded = message.encode_to_vec();
    let len = encoded.len() as u32;
    let mut framed = Vec::with_capacity(4 + encoded.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&encoded);

    tokio::time::timeout(timeout, stream.write_all(&framed))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "write timed out"))?
}

/// Receive a protobuf message with a 4-byte big-endian length prefix.
///
/// Used during the bootstrap handshake (no type tag). Takes only
/// [`AsyncRead`] so split read halves can receive without a write half.
///
/// # Errors
///
/// Returns an I/O error if the read fails, times out, or the message
/// exceeds [`MAX_MESSAGE_SIZE`].
pub async fn read_message<T: Message + Default>(
    stream: &mut (impl AsyncRead + Unpin + Send),
    timeout: Duration,
) -> IoResult<T> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "read length timed out"))??;

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut payload))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "read payload timed out"))??;

    T::decode(payload.as_slice()).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
}

/// Send a type-tagged operational message.
///
/// Format: `[4-byte len][1-byte tag][protobuf payload]`
/// Takes only [`AsyncWrite`] so a split write half can send while another
/// task owns the read half.
///
/// # Errors
///
/// Returns an I/O error if the write fails or times out.
pub async fn send_tagged(
    stream: &mut (impl AsyncWrite + Unpin + Send),
    tag: u8,
    message: &impl Message,
    timeout: Duration,
) -> IoResult<()> {
    let encoded = message.encode_to_vec();
    let len = (encoded.len() + 1) as u32; // +1 for the tag byte
    let mut framed = Vec::with_capacity(4 + 1 + encoded.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.push(tag);
    framed.extend_from_slice(&encoded);

    tokio::time::timeout(timeout, stream.write_all(&framed))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "write timed out"))?
}

/// Read a type-tagged operational message.
///
/// Returns the tag and the decoded message. Takes only [`AsyncRead`] so a
/// split read half can receive while another task owns the write half.
pub async fn read_tagged<T: Message + Default>(
    stream: &mut (impl AsyncRead + Unpin + Send),
    timeout: Duration,
) -> IoResult<(u8, T)> {
    let (tag, raw) = read_tagged_raw(stream, timeout).await?;
    let msg =
        T::decode(raw.as_slice()).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok((tag, msg))
}

/// Read a type-tagged operational message, returning raw bytes.
///
/// Returns the tag and undecoded protobuf payload. Takes only [`AsyncRead`]
/// so a split read half can receive while another task owns the write half.
pub async fn read_tagged_raw(
    stream: &mut (impl AsyncRead + Unpin + Send),
    timeout: Duration,
) -> IoResult<(u8, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "read length timed out"))??;

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }

    if len < 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "tagged message too short: missing type tag",
        ));
    }

    let payload_len = len - 1;
    let mut tag_buf = [0u8; 1];
    tokio::time::timeout(timeout, stream.read_exact(&mut tag_buf))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "read tag timed out"))??;

    let tag = tag_buf[0];
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        tokio::time::timeout(timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "read payload timed out"))??;
    }

    Ok((tag, payload))
}

/// Wraps a transport stream for bidirectional length-prefixed protobuf
/// message exchange. Defaults to [`TcpStream`] so existing call sites
/// keep working; vsock or other transports plug in via the type parameter.
pub struct FramedConnection<S: TransportStream = TcpStream> {
    stream: S,
    timeout: Duration,
}

impl<S: TransportStream> FramedConnection<S> {
    /// Creates a new [`FramedConnection`] from an existing transport stream.
    pub fn new(stream: S, timeout: Duration) -> Self {
        Self { stream, timeout }
    }

    /// Returns a shared reference to the timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sends a protobuf message (handshake format, no type tag).
    pub async fn send(&mut self, message: &impl Message) -> IoResult<()> {
        send_message(&mut self.stream, message, self.timeout).await
    }

    /// Receives a protobuf message (handshake format, no type tag).
    pub async fn recv<T: Message + Default>(&mut self) -> IoResult<T> {
        read_message(&mut self.stream, self.timeout).await
    }

    /// Sends a type-tagged operational message.
    pub async fn send_tagged(&mut self, tag: u8, message: &impl Message) -> IoResult<()> {
        send_tagged(&mut self.stream, tag, message, self.timeout).await
    }

    /// Reads a type-tagged operational message, returning the tag and
    /// decoded message.
    pub async fn recv_tagged<T: Message + Default>(&mut self) -> IoResult<(u8, T)> {
        read_tagged(&mut self.stream, self.timeout).await
    }

    /// Returns a reference to the inner stream.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the wrapper and returns the inner stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl FramedConnection<TcpStream> {
    /// Splits the TCP connection into read and write halves.
    pub fn into_split(
        self,
    ) -> (
        tokio::net::tcp::OwnedReadHalf,
        tokio::net::tcp::OwnedWriteHalf,
    ) {
        self.stream.into_split()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct TestMessage {
        #[prost(string, tag = "1")]
        content: String,
    }

    #[tokio::test]
    async fn send_and_read_round_trip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let msg = read_message::<TestMessage>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(msg.content, "hello");

            let reply = TestMessage {
                content: "world".into(),
            };
            send_message(&mut stream, &reply, Duration::from_secs(5))
                .await
                .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let msg = TestMessage {
            content: "hello".into(),
        };

        send_message(&mut stream, &msg, Duration::from_secs(5))
            .await
            .unwrap();

        let reply = read_message::<TestMessage>(&mut stream, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(reply.content, "world");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn tagged_message_round_trip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, msg): (u8, TestMessage) = read_tagged(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(tag, 0x01);
            assert_eq!(msg.content, "tagged");

            let reply = TestMessage {
                content: "tagged-reply".into(),
            };
            send_tagged(&mut stream, 0x02, &reply, Duration::from_secs(5))
                .await
                .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let msg = TestMessage {
            content: "tagged".into(),
        };

        send_tagged(&mut stream, 0x01, &msg, Duration::from_secs(5))
            .await
            .unwrap();

        let (tag, reply): (u8, TestMessage) = read_tagged(&mut stream, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(tag, 0x02);
        assert_eq!(reply.content, "tagged-reply");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let oversized_len = (MAX_MESSAGE_SIZE + 1) as u32;
            stream
                .write_all(&oversized_len.to_be_bytes())
                .await
                .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = read_message::<TestMessage>(&mut stream, Duration::from_secs(5)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn connection_wrapper_send_recv() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, Duration::from_secs(5));
            let msg = conn.recv::<TestMessage>().await.unwrap();
            assert_eq!(msg.content, "ping");
            conn.send(&TestMessage {
                content: "pong".into(),
            })
            .await
            .unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = FramedConnection::new(stream, Duration::from_secs(5));
        conn.send(&TestMessage {
            content: "ping".into(),
        })
        .await
        .unwrap();

        let reply = conn.recv::<TestMessage>().await.unwrap();
        assert_eq!(reply.content, "pong");

        server.await.unwrap();
    }
}
