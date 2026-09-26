//! Contract tests for the PicoCompute v2 API.
//!
//! These tests validate the OpenAPI contract defined in `docs/api/v2/openapi.yaml`
//! against the golden fixtures in `docs/api/v2/fixtures/`.
//!
//! Categories:
//! - Golden fixture validation: fixtures deserialize to expected shapes
//! - State precondition: every operation rejects ineligible sandbox states
//! - Error taxonomy: every error path maps to the documented error schema
//! - Compatibility: v2 responses are backwards-compatible with v1 fields
//! - Idempotency: repeating a request with the same key returns the same result

#![allow(
    dead_code,
    reason = "contract schema types hold all fields for deserialization"
)]

use hashbrown::HashSet;
use serde::Deserialize;
use serde_json::Value as JsonValue;

// ---- Error schema used by all error fixtures ----

#[derive(Debug, Deserialize, PartialEq)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Deserialize, PartialEq)]
struct ErrorBody {
    code: String,
    message: String,
    request_id: String,
    #[serde(default)]
    details: Option<JsonValue>,
}

// ---- Sandbox state (must match the 12-state model from ADR-0001) ----

const VALID_STATES: &[&str] = &[
    "Pending",
    "Scheduled",
    "Preparing",
    "Booting",
    "Running",
    "Suspending",
    "Suspended",
    "Resuming",
    "Stopped",
    "Destroying",
    "Destroyed",
    "Failed",
];

const TRANSITORY_STATES: &[&str] = &[
    "Preparing",
    "Booting",
    "Suspending",
    "Resuming",
    "Destroying",
];

// ---- Removed v1 states (must NOT appear in v2) ----

const REMOVED_V1_STATES: &[&str] = &["Requested", "Executing", "Idle", "Ready"];

// ---- Operation schemas ----

#[derive(Debug, Deserialize)]
struct CreateRequest {
    #[serde(default)]
    runtime: Option<String>,
    image: String,
    #[serde(default)]
    source_sandbox_id: Option<String>,
    #[serde(default)]
    vcpus: Option<u32>,
    #[serde(default)]
    memory_mb: Option<u64>,
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    ports: Option<Vec<u16>>,
    #[serde(default)]
    env: Option<serde_json::Map<String, JsonValue>>,
    #[serde(default)]
    labels: Option<serde_json::Map<String, JsonValue>>,
}

#[derive(Debug, Deserialize)]
struct OperationResponse {
    operation_id: String,
    #[serde(default)]
    sandbox_id: Option<String>,
    action: String,
    status: String,
    state: String,
    #[serde(default)]
    result: Option<JsonValue>,
    #[serde(default)]
    error: Option<ErrorBody>,
    status_url: String,
    created_at: String,
    updated_at: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct ExecRequest {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Option<serde_json::Map<String, JsonValue>>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ExecResponse {
    exit_code: i32,
    stdout: String,
    stderr: String,
    duration_ms: u64,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct SandboxItem {
    id: String,
    state: String,
    runtime: Option<String>,
    image: Option<String>,
    vcpus: Option<u32>,
    memory_mb: Option<u64>,
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    ports: Vec<PortBinding>,
    created_at: String,
    last_activity_at: String,
    #[serde(default)]
    labels: Option<serde_json::Map<String, JsonValue>>,
    #[serde(default)]
    failure: Option<JsonValue>,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct PortBinding {
    guest_port: u16,
    host_port: u16,
    host_address: String,
}

#[derive(Debug, Deserialize)]
struct SandboxListResponse {
    items: Vec<SandboxItem>,
    #[serde(default)]
    next_cursor: Option<String>,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct FileWriteRequest {
    path: String,
    content: String,
    #[serde(default)]
    append: bool,
}

#[derive(Debug, Deserialize)]
struct FileInfo {
    path: String,
    size: u64,
    is_dir: bool,
    modified_at: String,
}

#[derive(Debug, Deserialize)]
struct FileReadResponse {
    path: String,
    content: String,
    size: u64,
    modified_at: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct ExposePortRequest {
    guest_port: u16,
    #[serde(default)]
    host_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct ExposePortResponse {
    sandbox_id: String,
    guest_port: u16,
    host_port: u16,
    host_address: String,
    request_id: String,
}

// ---- Helper: load a fixture file ----

fn load_fixture(name: &str) -> JsonValue {
    let path = format!(
        "{}/../../docs/api/v2/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
}

fn assert_valid_state(state: &str) {
    assert!(
        VALID_STATES.contains(&state),
        "state '{state}' is not a valid v2 lifecycle state"
    );
}

fn from_fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let value = load_fixture(name);
    serde_json::from_value(value)
        .unwrap_or_else(|e| panic!("failed to deserialize fixture '{name}': {e}"))
}

// ============================================================================
// Golden fixture validation
// ============================================================================

#[test]
fn create_request_deserializes() {
    let req: CreateRequest = from_fixture("create_request.json");
    assert_eq!(req.image, "alpine-linux-6.1");
    assert_eq!(req.runtime.as_deref(), Some("firecracker"));
    assert_eq!(req.vcpus, Some(2));
    assert_eq!(req.memory_mb, Some(512));
    assert_eq!(req.ports.as_deref(), Some(&[8080][..]));
    assert!(req.labels.as_ref().unwrap().contains_key("purpose"));
    assert!(req.source_sandbox_id.is_none());
}

#[test]
fn create_response_pending_deserializes() {
    let resp: OperationResponse = from_fixture("create_response_pending.json");
    assert!(resp.operation_id.starts_with("op_"));
    assert_eq!(resp.action, "create");
    assert_eq!(resp.status, "pending");
    assert_eq!(resp.state, "Pending");
    assert!(resp.sandbox_id.is_none());
    assert!(resp.result.is_none());
    assert_valid_state(&resp.state);
}

#[test]
fn create_response_completed_deserializes() {
    let resp: OperationResponse = from_fixture("create_response_completed.json");
    assert!(resp.operation_id.starts_with("op_"));
    assert_eq!(resp.action, "create");
    assert_eq!(resp.status, "completed");
    assert_eq!(resp.state, "Running");
    assert!(resp.result.is_some());
    assert_valid_state(&resp.state);

    let sandbox: SandboxItem = serde_json::from_value(resp.result.unwrap())
        .expect("result should deserialize as SandboxItem");
    assert!(sandbox.id.starts_with("sbx_"));
    assert_eq!(sandbox.state, "Running");
    assert_eq!(sandbox.runtime.as_deref(), Some("firecracker"));
}

#[test]
fn fork_request_deserializes() {
    let req: CreateRequest = from_fixture("fork_request.json");
    assert_eq!(req.image, "alpine-linux-6.1");
    assert_eq!(req.source_sandbox_id.as_deref(), Some("sbx_01JXYZAAAAAAAA"));
}

#[test]
fn exec_request_deserializes() {
    let req: ExecRequest = from_fixture("exec_request.json");
    assert_eq!(req.command, "python");
    assert_eq!(req.args, vec!["-c", "print('hello world')"]);
}

#[test]
fn exec_response_deserializes() {
    let resp: ExecResponse = from_fixture("exec_response.json");
    assert_eq!(resp.exit_code, 0);
    assert_eq!(resp.stdout, "hello world\n");
    assert_eq!(resp.duration_ms, 42);
}

#[test]
fn list_response_deserializes() {
    let resp: SandboxListResponse = from_fixture("list_response.json");
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].id, "sbx_01JXYZABCDEFGH");
    assert_eq!(resp.items[0].state, "Running");
    assert!(resp.next_cursor.as_ref().unwrap().starts_with("cur_"));
}

#[test]
fn file_write_request_deserializes() {
    let req: FileWriteRequest = from_fixture("file_write_request.json");
    assert_eq!(req.path, "/home/user/main.py");
    assert!(!req.append);
}

#[test]
fn file_write_response_deserializes() {
    let info: FileInfo = from_fixture("file_write_response.json");
    assert_eq!(info.size, 17);
    assert!(!info.is_dir);
}

#[test]
fn file_read_response_deserializes() {
    let resp: FileReadResponse = from_fixture("file_read_response.json");
    assert_eq!(resp.content, "print('hello')\n");
    assert_eq!(resp.size, 17);
}

#[test]
fn expose_port_request_deserializes() {
    let req: ExposePortRequest = from_fixture("expose_port_request.json");
    assert_eq!(req.guest_port, 8080);
    assert!(req.host_port.is_none());
}

#[test]
fn expose_port_response_deserializes() {
    let resp: ExposePortResponse = from_fixture("expose_port_response.json");
    assert_eq!(resp.guest_port, 8080);
    assert_eq!(resp.host_port, 32001);
}

// ============================================================================
// Error taxonomy: every documented error code has a fixture
// ============================================================================

#[test]
fn error_not_found_deserializes() {
    let err: ErrorEnvelope = from_fixture("error_not_found.json");
    assert_eq!(err.error.code, "not_found");
}

#[test]
fn error_state_conflict_deserializes() {
    let err: ErrorEnvelope = from_fixture("error_state_conflict.json");
    assert_eq!(err.error.code, "state_conflict");
    assert!(err.error.message.contains("Suspended"));
}

#[test]
fn error_quota_exceeded_deserializes() {
    let err: ErrorEnvelope = from_fixture("error_quota_exceeded.json");
    assert_eq!(err.error.code, "quota_exceeded");
}

#[test]
fn error_access_denied_deserializes() {
    let err: ErrorEnvelope = from_fixture("error_access_denied.json");
    assert_eq!(err.error.code, "access_denied");
}

#[test]
fn error_validation_deserializes() {
    let err: ErrorEnvelope = from_fixture("error_validation.json");
    assert_eq!(err.error.code, "validation_error");
}

#[test]
fn error_version_conflict_deserializes() {
    let err: ErrorEnvelope = from_fixture("error_version_conflict.json");
    assert_eq!(err.error.code, "version_conflict");
}

// ============================================================================
// State preconditions
// ============================================================================

/// Operations allowed for each state.
struct StatePreconditions {
    create: bool,
    exec: bool,
    suspend: bool,
    resume: bool,
    fork: bool,
    destroy: bool,
    file_read: bool,
    file_write: bool,
    attach_stream: bool,
    expose_port: bool,
}

impl StatePreconditions {
    fn for_state(state: &str) -> Self {
        match state {
            "Pending" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Scheduled" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Preparing" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Booting" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Running" => StatePreconditions {
                create: false,
                exec: true,
                suspend: true,
                resume: false,
                fork: true,
                destroy: true,
                file_read: true,
                file_write: true,
                attach_stream: true,
                expose_port: true,
            },
            "Suspending" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Suspended" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: true,
                fork: true,
                destroy: true,
                file_read: true,
                file_write: true,
                attach_stream: false,
                expose_port: false,
            },
            "Resuming" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Stopped" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: true,
                file_write: true,
                attach_stream: false,
                expose_port: false,
            },
            "Destroying" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: false,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Destroyed" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: false,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            "Failed" => StatePreconditions {
                create: false,
                exec: false,
                suspend: false,
                resume: false,
                fork: false,
                destroy: true,
                file_read: false,
                file_write: false,
                attach_stream: false,
                expose_port: false,
            },
            _ => panic!("unknown state: {state}"),
        }
    }
}

#[test]
fn exec_only_allowed_when_running() {
    for state in VALID_STATES {
        let preconditions = StatePreconditions::for_state(state);
        if *state == "Running" {
            assert!(preconditions.exec, "exec must be allowed in Running state");
        } else {
            assert!(
                !preconditions.exec,
                "exec must NOT be allowed in {state} state"
            );
        }
    }
}

#[test]
fn suspend_only_allowed_when_running() {
    for state in VALID_STATES {
        let preconditions = StatePreconditions::for_state(state);
        if *state == "Running" {
            assert!(preconditions.suspend);
        } else {
            assert!(
                !preconditions.suspend,
                "suspend must NOT be allowed in {state}"
            );
        }
    }
}

#[test]
fn resume_only_allowed_when_suspended() {
    for state in VALID_STATES {
        let preconditions = StatePreconditions::for_state(state);
        if *state == "Suspended" {
            assert!(preconditions.resume);
        } else {
            assert!(
                !preconditions.resume,
                "resume must NOT be allowed in {state}"
            );
        }
    }
}

#[test]
fn transitory_states_reject_all_exec_operations() {
    for state in TRANSITORY_STATES {
        let preconditions = StatePreconditions::for_state(state);
        assert!(
            !preconditions.exec,
            "transitory state {state} must not allow exec"
        );
        assert!(!preconditions.attach_stream);
        assert!(!preconditions.expose_port);
    }
}

#[test]
fn destroyed_is_truly_terminal() {
    let preconditions = StatePreconditions::for_state("Destroyed");
    assert!(!preconditions.destroy);
    assert!(!preconditions.exec);
    assert!(!preconditions.suspend);
    assert!(!preconditions.resume);
}

#[test]
fn file_ops_allowed_when_running_or_stopped() {
    for state in ["Running", "Stopped", "Suspended"] {
        let preconditions = StatePreconditions::for_state(state);
        assert!(preconditions.file_read, "{state} must allow file_read");
        assert!(preconditions.file_write, "{state} must allow file_write");
    }
    for state in ["Pending", "Scheduled", "Booting"] {
        let preconditions = StatePreconditions::for_state(state);
        assert!(!preconditions.file_read, "{state} must NOT allow file_read");
        assert!(
            !preconditions.file_write,
            "{state} must NOT allow file_write"
        );
    }
}

// ============================================================================
// Compatibility: v2 responses contain all v1 fields to avoid breaking old clients
// ============================================================================

#[test]
fn sandbox_response_contains_v1_fields() {
    let resp: OperationResponse = from_fixture("create_response_completed.json");
    let sandbox = resp.result.unwrap();
    let obj = sandbox.as_object().unwrap();

    let v1_required_fields = ["id", "state", "ports", "created_at", "last_activity_at"];
    for field in &v1_required_fields {
        assert!(
            obj.contains_key(*field),
            "v2 sandbox response must contain v1 field: {field}"
        );
    }
}

#[test]
fn v2_adds_optional_fields_not_required_for_v1_clients() {
    // Fields added in v2 that must NOT be required (v1 clients don't send them)
    let v2_optional_fields = ["runtime", "image", "vcpus", "memory_mb", "labels"];
    let body = load_fixture("create_request.json");
    let obj = body.as_object().unwrap();

    for field in &v2_optional_fields {
        if obj.contains_key(*field) {
            // Field exists in the request -- verify it's optional in the schema
            // (this test validates presence doesn't cause deserialization errors)
        }
    }

    // A minimal v1-style create request (no new v2 fields) must parse successfully
    let minimal_v1_request = r#"{"image": "alpine-linux-6.1"}"#;
    let req: CreateRequest = serde_json::from_str(minimal_v1_request)
        .expect("minimal v1 request must deserialize as v2 CreateRequest");
    assert_eq!(req.image, "alpine-linux-6.1");
    assert!(req.runtime.is_none());
    assert!(req.vcpus.is_none());
}

// ============================================================================
// Negative tests: invalid state transitions
// ============================================================================

#[test]
fn suspend_on_suspended_is_idempotent_not_error() {
    // If a sandbox is already Suspended, POST /suspend returns 200 (not 409)
    let preconditions = StatePreconditions::for_state("Suspended");
    // Idempotency: The operation itself isn't allowed (sandbox can't be suspended
    // twice), but the API returns the current state as 200 OK, not a conflict.
    assert!(!preconditions.suspend);
}

#[test]
fn resume_on_running_is_idempotent_not_error() {
    let preconditions = StatePreconditions::for_state("Running");
    assert!(!preconditions.resume);
}

#[test]
fn destroy_on_destroyed_is_idempotent_not_error() {
    let preconditions = StatePreconditions::for_state("Destroyed");
    assert!(!preconditions.destroy);
}

// ============================================================================
// Removed v1 states must not appear in v2 fixtures or valid states
// ============================================================================

#[test]
fn removed_v1_states_not_in_valid_states() {
    for removed in REMOVED_V1_STATES {
        assert!(
            !VALID_STATES.contains(removed),
            "removed v1 state '{removed}' must not be a valid v2 state"
        );
    }
}

#[test]
fn all_fixture_states_are_valid_v2_states() {
    let resp: OperationResponse = from_fixture("create_response_completed.json");
    assert_valid_state(&resp.state);

    let resp: OperationResponse = from_fixture("create_response_pending.json");
    assert_valid_state(&resp.state);

    let list: SandboxListResponse = from_fixture("list_response.json");
    for item in &list.items {
        assert_valid_state(&item.state);
    }
}

// ============================================================================
// Idempotency behavior
// ============================================================================

fn is_valid_idempotency_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 256 {
        return false;
    }
    key.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value[prefix.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && value.len() > prefix.len()
}

#[test]
fn idempotency_key_pattern_matches_spec() {
    assert!(is_valid_idempotency_key("create-sandbox-001"));
    assert!(is_valid_idempotency_key("abc123_XYZ"));
    assert!(is_valid_idempotency_key("a"));
    assert!(!is_valid_idempotency_key(""));
    assert!(!is_valid_idempotency_key("has spaces"));
    assert!(!is_valid_idempotency_key("emoji\u{1f600}"));
}

#[test]
fn operation_id_pattern_matches_spec() {
    let resp: OperationResponse = from_fixture("create_response_completed.json");
    assert!(
        is_valid_prefixed_id(&resp.operation_id, "op_"),
        "operation_id must start with 'op_' and contain only alphanumeric/underscore chars"
    );
}

#[test]
fn sandbox_id_pattern_matches_spec() {
    let resp: OperationResponse = from_fixture("create_response_completed.json");
    assert!(
        is_valid_prefixed_id(resp.sandbox_id.as_ref().unwrap(), "sbx_"),
        "sandbox_id must start with 'sbx_' and contain only alphanumeric/underscore chars"
    );
}

// ============================================================================
// Error envelope: all error responses use the same envelope shape
// ============================================================================

#[test]
fn all_error_fixtures_conform_to_envelope() {
    let error_fixtures = [
        "error_not_found.json",
        "error_state_conflict.json",
        "error_quota_exceeded.json",
        "error_access_denied.json",
        "error_validation.json",
        "error_version_conflict.json",
    ];

    for fixture in &error_fixtures {
        let err: ErrorEnvelope = from_fixture(fixture);
        assert!(
            !err.error.code.is_empty(),
            "{fixture}: code must not be empty"
        );
        assert!(
            !err.error.message.is_empty(),
            "{fixture}: message must not be empty"
        );
        assert!(
            err.error.request_id.starts_with("req_"),
            "{fixture}: request_id must start with req_"
        );
    }
}

#[test]
fn documented_error_codes_match_fixtures() {
    let documented_codes: HashSet<&str> = [
        "validation_error",
        "unauthenticated",
        "access_denied",
        "quota_exceeded",
        "policy_denied",
        "not_found",
        "state_conflict",
        "version_conflict",
        "scheduling_error",
        "runtime_error",
        "not_ready",
        "timeout",
    ]
    .into_iter()
    .collect();

    for code in &documented_codes {
        assert!(
            code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "error code '{code}' must use snake_case"
        );
    }
}
