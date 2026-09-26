use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pc", about = "CLI for PicoCompute sandbox platform")]
pub(crate) struct Args {
    #[arg(long, global = true, help = "API base URL [env: PICO_API_URL]")]
    pub api_url: Option<String>,

    #[arg(long, global = true, help = "API token [env: PICO_API_TOKEN]")]
    pub token: Option<String>,

    #[arg(short, long, global = true, action = clap::ArgAction::Count, help = "Increase verbosity (-v, -vv, -vvv)")]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Create a new sandbox
    Create(CreateArgs),
    /// List sandboxes
    List(ListArgs),
    /// Get sandbox details
    Get(GetArgs),
    /// Force-destroy a sandbox and release its host resources
    Destroy(DestroyArgs),
    /// Stop a running sandbox without purging its host-side record
    Stop(LifecycleArgs),
    /// Purge the remaining state of a stopped sandbox
    Purge(LifecycleArgs),
    /// Suspend a running sandbox
    Suspend(LifecycleArgs),
    /// Resume a suspended sandbox
    Resume(LifecycleArgs),
    /// Bump the idle timeout so the sandbox is not reaped
    Keepalive(LifecycleArgs),
    /// Execute a command inside a sandbox
    Exec(ExecArgs),
    /// Show SSH connection info for a sandbox (no tunnel)
    SshInfo(GetArgs),
    /// SSH into a sandbox via WebSocket tunnel
    Ssh(SshArgs),
    /// Read and write sandbox workspace files
    Files(FilesArgs),
    /// Start, inspect, and cancel background tasks
    Tasks(TasksArgs),
    /// Manage controlled port-forward endpoints
    Ports(PortsArgs),
    /// Issue signed access leases for data-plane actions
    Lease(LeaseArgs),
    /// Build reproducible rootfs images
    Image(ImageArgs),
    /// Quarantine and fenced cleanup operator checks (no undrain, no force GC, no ledger writes)
    Operator(OperatorArgs),
}

#[derive(clap::Args)]
pub(crate) struct CreateArgs {
    #[arg(long, help = "Sandbox ID (auto-generated if omitted)")]
    pub id: Option<String>,

    #[arg(
        long,
        help = "Comma-separated ports to expose (e.g. 3000,8080)",
        value_delimiter = ','
    )]
    pub ports: Option<Vec<u16>>,

    #[arg(long, help = "Runtime backend (firecracker, qemu, remote-firecracker)")]
    pub runtime: Option<String>,

    #[arg(long, help = "Memory in MB")]
    pub memory_mb: Option<u64>,

    #[arg(long, help = "Number of vCPUs")]
    pub vcpus: Option<u32>,

    #[arg(long, help = "SSH public key content")]
    pub ssh_key: Option<String>,

    #[arg(long, default_value = "ed25519", help = "SSH key type (ed25519, rsa)")]
    pub ssh_key_type: String,

    #[arg(long, help = "Idle timeout in seconds")]
    pub idle_timeout_secs: Option<u64>,

    #[arg(long, help = "Environment variable (KEY=VALUE, repeatable)")]
    pub env: Vec<String>,

    #[arg(long, help = "Guest image ID")]
    pub image_id: Option<String>,

    #[arg(long, help = "Guest image digest")]
    pub image_digest: Option<String>,
}

#[derive(clap::Args)]
pub(crate) struct ListArgs {
    #[arg(long, default_value = "50", help = "Max results (1-250)")]
    pub limit: usize,

    #[arg(long, help = "Pagination cursor from a previous list call")]
    pub cursor: Option<String>,
}

#[derive(clap::Args)]
pub(crate) struct DestroyArgs {
    pub id: String,
}

#[derive(clap::Args)]
pub(crate) struct LifecycleArgs {
    pub id: String,
}

#[derive(clap::Args)]
pub(crate) struct ExecArgs {
    pub id: String,

    #[arg(help = "Command to run inside the sandbox")]
    pub command: String,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Arguments to the command"
    )]
    pub args: Vec<String>,

    #[arg(long, help = "Environment override (KEY=VALUE, repeatable)")]
    pub env: Vec<String>,

    #[arg(long, help = "Working directory inside the sandbox")]
    pub working_dir: Option<String>,

    #[arg(long, help = "Execution deadline in seconds")]
    pub timeout_secs: Option<u64>,
}

#[derive(clap::Args)]
pub(crate) struct FilesArgs {
    #[command(subcommand)]
    pub command: FilesCommands,
}

#[derive(Subcommand)]
pub(crate) enum FilesCommands {
    /// Read a file from the sandbox workspace
    Read {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(long, help = "Path inside the sandbox workspace")]
        path: String,
    },
    /// Write a file into the sandbox workspace
    Write {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(long, help = "Destination path inside the sandbox workspace")]
        path: String,
        #[arg(long, conflicts_with = "file", help = "Inline file content")]
        content: Option<String>,
        #[arg(long, help = "Read content from a local file")]
        file: Option<camino::Utf8PathBuf>,
        #[arg(long, help = "Append instead of overwriting")]
        append: bool,
    },
    /// List files under a directory in the sandbox workspace
    List {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(long, help = "Directory inside the sandbox workspace")]
        dir: String,
        #[arg(long, help = "List directories recursively")]
        recursive: bool,
        #[arg(long, default_value = "50", help = "Max results (1-250)")]
        limit: usize,
        #[arg(long, help = "Pagination cursor from a previous list call")]
        cursor: Option<String>,
    },
}

#[derive(clap::Args)]
pub(crate) struct TasksArgs {
    #[command(subcommand)]
    pub command: TasksCommands,
}

#[derive(Subcommand)]
pub(crate) enum TasksCommands {
    /// Start a background task in the sandbox
    Start {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(long, help = "Task prompt")]
        prompt: String,
        #[arg(long, help = "Agent handling the task")]
        agent: String,
        #[arg(long, help = "Model for the task")]
        model: Option<String>,
        #[arg(long, help = "Task timeout in seconds")]
        timeout_secs: Option<u64>,
    },
    /// Show the current state of a task
    Get {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(help = "Task ID")]
        task_id: String,
    },
    /// Cancel a running task
    Cancel {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(help = "Task ID")]
        task_id: String,
    },
    /// Stream task events over SSE until the task completes
    Events {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(help = "Task ID")]
        task_id: String,
    },
}

#[derive(clap::Args)]
pub(crate) struct PortsArgs {
    #[command(subcommand)]
    pub command: PortsCommands,
}

#[derive(Subcommand)]
pub(crate) enum PortsCommands {
    /// Expose a sandbox guest port through a platform-managed endpoint
    Expose {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(long, help = "Tenant ID owning the endpoint")]
        tenant_id: String,
        #[arg(long, help = "Access lease ID authorizing the exposure")]
        lease_id: String,
        #[arg(long, help = "Guest-side port to expose")]
        guest_port: u16,
        #[arg(long, help = "Requested host-side port (auto-assigned if omitted)")]
        host_port: Option<u16>,
        #[arg(long, help = "Bind host-side listener to loopback only")]
        localhost_only: bool,
        #[arg(long, help = "Maximum concurrent connections")]
        max_connections: Option<usize>,
        #[arg(long, help = "Signed access-lease blob")]
        lease: Option<String>,
    },
    /// List the currently exposed port endpoints of a sandbox
    List {
        #[arg(help = "Sandbox ID")]
        id: String,
    },
    /// Revoke a previously exposed port endpoint
    Revoke {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(help = "Port endpoint ID")]
        endpoint_id: String,
    },
}

#[derive(clap::Args)]
pub(crate) struct LeaseArgs {
    #[command(subcommand)]
    pub command: LeaseCommands,
}

#[derive(Subcommand)]
pub(crate) enum LeaseCommands {
    /// Issue a signed access lease for a sandbox action
    Issue {
        #[arg(help = "Sandbox ID")]
        id: String,
        #[arg(
            long,
            help = "Lease action (exec, file_transfer, port_forward, egress_exception, snapshot_operation, admin_override, credential_access)"
        )]
        action: String,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Allowed ports for port_forward leases"
        )]
        ports: Vec<u16>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Allowed paths for file_transfer leases"
        )]
        paths: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Allowed CIDRs for egress_exception leases"
        )]
        egress_cidrs: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Allowed types for credential_access leases"
        )]
        credential_types: Vec<String>,
    },
}

#[derive(clap::Args)]
pub(crate) struct GetArgs {
    pub id: String,
}

#[derive(clap::Args)]
pub(crate) struct SshArgs {
    pub id: String,
}

#[derive(clap::Args)]
pub(crate) struct ImageArgs {
    #[command(subcommand)]
    pub command: ImageCommands,
}

#[derive(Subcommand)]
pub(crate) enum ImageCommands {
    /// Build a rootfs image from a definition file
    Build {
        #[arg(short = 'c', long, value_name = "FILE")]
        config: camino::Utf8PathBuf,

        #[arg(short = 'l', long, value_name = "FILE")]
        lock_file: Option<camino::Utf8PathBuf>,

        #[arg(long, value_name = "FILE")]
        guest_agent: Option<camino::Utf8PathBuf>,

        #[arg(short = 'o', long, value_name = "DIR", default_value = "output")]
        output_dir: camino::Utf8PathBuf,

        #[arg(
            short = 'w',
            long,
            value_name = "DIR",
            default_value = "/var/tmp/pico-build"
        )]
        work_dir: camino::Utf8PathBuf,

        #[arg(long)]
        locked: bool,
    },
    /// Generate a lock file from an image definition
    Lock {
        #[arg(short = 'c', long, value_name = "FILE")]
        config: camino::Utf8PathBuf,

        #[arg(short = 'o', long, value_name = "FILE")]
        output: camino::Utf8PathBuf,
    },
}

#[derive(clap::Args)]
pub(crate) struct OperatorArgs {
    #[command(subcommand)]
    pub command: OperatorCommands,
}

#[derive(Subcommand)]
pub(crate) enum OperatorCommands {
    /// Validate ticket plus owner for quarantine acknowledge (offline, no mutation)
    QuarantineAck {
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        condition: String,
        #[arg(long)]
        owner: String,
    },
    /// Validate ticket plus cleared condition for quarantine resolve (offline, no mutation)
    QuarantineResolve {
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        condition: String,
        #[arg(long)]
        condition_cleared: bool,
    },
    /// Validate ticket plus fencing tokens for fenced cleanup (offline, no deletion)
    FencedCleanup {
        #[arg(long)]
        ticket: String,
        #[arg(long, value_delimiter = ',', required = true)]
        fencing_token: Vec<String>,
    },
    /// Validate ticket plus read-only ledger query (offline, no writes)
    LedgerInspect {
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        query: String,
        #[arg(long)]
        sandbox_id: Option<String>,
    },
    /// Post drain to the existing host-agent RPC with ticket evidence
    Drain {
        #[arg(long)]
        host_url: String,
        #[arg(
            long,
            help = "Host-agent bearer token (prefer PICO_HOST_TOKEN env so the secret stays out of shell history)"
        )]
        host_token: Option<String>,
        #[arg(long)]
        ticket: String,
    },
    /// Read host health for drain status (public endpoint)
    DrainStatus {
        #[arg(long)]
        host_url: String,
    },
    /// Validate re-admit gates (no undrain helper exists by design)
    ReadmitCheck {
        #[arg(long)]
        quarantine_gauge_zero: bool,
        #[arg(long)]
        capacity_age_secs: u64,
        #[arg(
            long,
            help = "Observed host health: ready, degraded, draining, or unsafe (required)"
        )]
        health: String,
        #[arg(long)]
        reconciliation_clean: bool,
        #[arg(long)]
        watch_clean: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(argv)
    }

    #[test]
    fn parses_lifecycle_singletons() {
        for (cmd, id) in [
            ("destroy", "sbx_1"),
            ("stop", "sbx_1"),
            ("purge", "sbx_1"),
            ("suspend", "sbx_1"),
            ("resume", "sbx_1"),
            ("keepalive", "sbx_1"),
            ("ssh-info", "sbx_1"),
        ] {
            let args = parse(&["pc", cmd, id]).expect(cmd);
            match (cmd, args.command) {
                ("destroy", Commands::Destroy(a)) => assert_eq!(a.id, id),
                ("stop", Commands::Stop(a)) => assert_eq!(a.id, id),
                ("purge", Commands::Purge(a)) => assert_eq!(a.id, id),
                ("suspend", Commands::Suspend(a)) => assert_eq!(a.id, id),
                ("resume", Commands::Resume(a)) => assert_eq!(a.id, id),
                ("keepalive", Commands::Keepalive(a)) => assert_eq!(a.id, id),
                ("ssh-info", Commands::SshInfo(a)) => assert_eq!(a.id, id),
                _ => panic!("wrong variant for {cmd}"),
            }
        }
    }

    #[test]
    fn parses_exec_with_trailing_args() {
        let args =
            parse(&["pc", "exec", "sbx_1", "echo", "hello", "--", "-n"]).expect("exec parses");
        match args.command {
            Commands::Exec(ea) => {
                assert_eq!(ea.id, "sbx_1");
                assert_eq!(ea.command, "echo");
                assert!(ea.args.contains(&"hello".to_string()));
            }
            _ => panic!("expected exec"),
        }
    }

    #[test]
    fn parses_exec_options() {
        let args = parse(&[
            "pc",
            "exec",
            "sbx_1",
            "--working-dir",
            "/tmp",
            "--timeout-secs",
            "30",
            "--env",
            "FOO=bar",
            "echo",
        ])
        .expect("exec options parse");
        match args.command {
            Commands::Exec(ea) => {
                assert_eq!(ea.working_dir.as_deref(), Some("/tmp"));
                assert_eq!(ea.timeout_secs, Some(30));
                assert_eq!(ea.env, vec!["FOO=bar".to_string()]);
            }
            _ => panic!("expected exec"),
        }
    }

    #[test]
    fn parses_files_groups() {
        let args = parse(&["pc", "files", "read", "sbx_1", "--path", "a.txt"]).expect("read");
        assert!(matches!(
            args.command,
            Commands::Files(FilesArgs {
                command: FilesCommands::Read { .. },
            })
        ));

        let args = parse(&[
            "pc",
            "files",
            "write",
            "sbx_1",
            "--path",
            "a.txt",
            "--content",
            "hi",
        ])
        .expect("write");
        assert!(matches!(
            args.command,
            Commands::Files(FilesArgs {
                command: FilesCommands::Write { .. },
            })
        ));

        let args = parse(&["pc", "files", "list", "sbx_1", "--dir", "/"]).expect("list");
        assert!(matches!(
            args.command,
            Commands::Files(FilesArgs {
                command: FilesCommands::List { .. },
            })
        ));
    }

    #[test]
    fn files_write_rejects_both_content_and_file() {
        assert!(
            parse(&[
                "pc",
                "files",
                "write",
                "sbx_1",
                "--path",
                "a.txt",
                "--content",
                "hi",
                "--file",
                "local.txt",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_tasks_groups() {
        let args = parse(&[
            "pc", "tasks", "start", "sbx_1", "--prompt", "do work", "--agent", "echo",
        ])
        .expect("start");
        assert!(matches!(
            args.command,
            Commands::Tasks(TasksArgs {
                command: TasksCommands::Start { .. },
            })
        ));

        for sub in ["get", "cancel", "events"] {
            let args = parse(&["pc", "tasks", sub, "sbx_1", "task_1"]).expect(sub);
            assert!(matches!(args.command, Commands::Tasks(_)), "{sub} parses");
        }
    }

    #[test]
    fn parses_ports_groups() {
        let args = parse(&[
            "pc",
            "ports",
            "expose",
            "sbx_1",
            "--tenant-id",
            "tnt_1",
            "--lease-id",
            "lse_1",
            "--guest-port",
            "8080",
        ])
        .expect("expose");
        assert!(matches!(
            args.command,
            Commands::Ports(PortsArgs {
                command: PortsCommands::Expose { .. },
            })
        ));

        let args = parse(&["pc", "ports", "list", "sbx_1"]).expect("ports list");
        assert!(matches!(
            args.command,
            Commands::Ports(PortsArgs {
                command: PortsCommands::List { .. },
            })
        ));

        let args = parse(&["pc", "ports", "revoke", "sbx_1", "epf_1"]).expect("revoke");
        assert!(matches!(
            args.command,
            Commands::Ports(PortsArgs {
                command: PortsCommands::Revoke { .. },
            })
        ));
    }

    #[test]
    fn parses_lease_issue() {
        let args =
            parse(&["pc", "lease", "issue", "sbx_1", "--action", "exec"]).expect("lease issue");
        assert!(matches!(
            args.command,
            Commands::Lease(LeaseArgs {
                command: LeaseCommands::Issue { .. },
            })
        ));
    }

    #[test]
    fn parses_create_new_fields_and_list_cursor() {
        let args = parse(&[
            "pc",
            "create",
            "--env",
            "FOO=bar",
            "--image-id",
            "img_1",
            "--image-digest",
            "sha256:abc",
        ])
        .expect("create");
        match args.command {
            Commands::Create(ca) => {
                assert_eq!(ca.env, vec!["FOO=bar".to_string()]);
                assert_eq!(ca.image_id.as_deref(), Some("img_1"));
                assert_eq!(ca.image_digest.as_deref(), Some("sha256:abc"));
            }
            _ => panic!("expected create"),
        }

        let args =
            parse(&["pc", "list", "--limit", "10", "--cursor", "cur_1"]).expect("list with cursor");
        match args.command {
            Commands::List(la) => {
                assert_eq!(la.limit, 10);
                assert_eq!(la.cursor.as_deref(), Some("cur_1"));
            }
            _ => panic!("expected list"),
        }
    }
}
