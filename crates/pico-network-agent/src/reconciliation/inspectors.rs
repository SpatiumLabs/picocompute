//! Inspector traits for cross-crate resource enumeration.
//!
//! These traits let the host-agent wire its DNS proxy and port-forward
//! manager into the network reconciliation pass without creating a
//! circular dependency. When an inspector is not provided, its resource
//! class is silently skipped.

use std::collections::BTreeSet;

/// Inspects the DNS proxy's per-sandbox registrations and cache.
///
/// Implemented by the DNS proxy server in `pico-network-agent::dns`.
pub trait DnsInspector: Send + Sync {
    /// Returns the set of sandbox IDs currently registered with the DNS proxy.
    fn registered_sandbox_ids(&self) -> BTreeSet<String>;

    /// Returns the number of cached DNS entries for a specific sandbox.
    fn sandbox_cache_entry_count(&self, sandbox_id: &str) -> usize;

    /// Returns the total number of sandboxes with DNS cache entries.
    fn total_cache_sandbox_count(&self) -> usize;
}

/// Inspects the port-forward manager's per-sandbox endpoints and leases.
///
/// Implemented by `PortForwardManager` in `pico-host-agent`.
pub trait PortForwardInspector: Send + Sync {
    /// Returns the set of sandbox IDs with active port-forwarding endpoints.
    fn registered_sandbox_ids(&self) -> BTreeSet<String>;
}

/// A no-op DNS inspector for when DNS reconciliation is not wired in.
#[derive(Clone)]
pub struct NoopDnsInspector;

impl DnsInspector for NoopDnsInspector {
    fn registered_sandbox_ids(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn sandbox_cache_entry_count(&self, _sandbox_id: &str) -> usize {
        0
    }

    fn total_cache_sandbox_count(&self) -> usize {
        0
    }
}

/// A no-op port-forward inspector for when port-forward reconciliation is not wired in.
#[derive(Clone)]
pub struct NoopPortForwardInspector;

impl PortForwardInspector for NoopPortForwardInspector {
    fn registered_sandbox_ids(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }
}

// ── Command runner seam ─────────────────────────────────────────────────

/// Output from a CLI command for reconciliation.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit status (0 = success).
    pub exit_code: i32,
}

/// Runs external CLI commands for enumeration and cleanup.
///
/// This seam lets integration tests inject canned command outputs
/// without requiring `ip`, `nft`, and `tc` binaries on the test host.
pub trait CommandRunner: Send + Sync {
    /// Run a command and return its output.
    fn run(
        &self,
        program: &str,
        args: &[&str],
    ) -> impl std::future::Future<Output = std::io::Result<CommandOutput>> + Send;
}

/// Real command runner that shells out via `tokio::process::Command`.
#[derive(Clone)]
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    async fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
        use tokio::process::Command;
        let output = Command::new(program)
            .args(args)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .await?;
        Ok(CommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

/// Fake command runner for tests — returns canned outputs keyed by program.
#[derive(Clone)]
pub struct FakeCommandRunner {
    outputs: hashbrown::HashMap<String, CommandOutput>,
}

impl FakeCommandRunner {
    /// Create a fake runner with pre-configured outputs.
    #[must_use]
    pub fn new() -> Self {
        Self {
            outputs: hashbrown::HashMap::new(),
        }
    }

    /// Register a canned output for a given program.
    pub fn insert(&mut self, program: &str, output: CommandOutput) {
        self.outputs.insert(program.to_string(), output);
    }

    /// Register canned stdout text for a program (empty stderr, exit 0).
    pub fn insert_stdout(&mut self, program: &str, stdout: &str) {
        self.insert(
            program,
            CommandOutput {
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            },
        );
    }
}

impl Default for FakeCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for FakeCommandRunner {
    async fn run(&self, program: &str, _args: &[&str]) -> std::io::Result<CommandOutput> {
        self.outputs.get(program).cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no canned output for {program}"),
            )
        })
    }
}
