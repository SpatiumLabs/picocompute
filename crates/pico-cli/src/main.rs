mod cli;
mod client;
mod config;
mod operator;
mod ssh;

use clap::Parser;
use cli::{
    Args, Commands, FilesCommands, ImageCommands, LeaseCommands, OperatorCommands, PortsCommands,
    TasksCommands,
};
use client::ApiClient;
use config::Config;
use hashbrown::HashMap;
use pico_core::{LeaseAction, LeaseScope, RuntimeType, SandboxSpec};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let log_filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let telemetry_config = pico_telemetry::TelemetryConfig {
        settings: &pico_telemetry::TelemetrySettings {
            log: pico_telemetry::LogSettings {
                format: pico_telemetry::LogFormat::Pretty,
                filter: log_filter.to_string(),
                ..Default::default()
            },
            metrics: pico_telemetry::MetricsSettings {
                service_name: "pico-cli".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };

    let _driver = pico_telemetry::init(telemetry_config).expect("failed to initialize telemetry");

    let mut config = Config::from_env();
    config.apply_overrides(args.api_url, args.token);
    if let Err(msg) = config.validate() {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let client = ApiClient::new(config.api_url, config.token);

    let result = match args.command {
        Commands::Image(ia) => match ia.command {
            ImageCommands::Build {
                config,
                lock_file,
                guest_agent,
                output_dir,
                work_dir,
                locked,
            } => {
                let builder = pico_image::RootfsBuilder {
                    definition_path: config,
                    lock_path: lock_file,
                    work_dir,
                    output_dir,
                    guest_agent_path: guest_agent,
                    locked,
                    signing_key_path: None,
                    signer_identity: None,
                };

                builder
                    .build()
                    .map(|output| {
                        println!("rootfs: {} ({})", output.rootfs.path, output.rootfs.digest);
                        println!("manifest: {}", output.manifest_path);
                    })
                    .map_err(|e| e.to_string())
            }

            ImageCommands::Lock { config, output } => {
                pico_image::definition::ImageDefinition::load(&config)
                    .and_then(|definition| pico_image::resolve::create_lock(&definition, &output))
                    .map(|lock| {
                        println!("lock: {} ({})", output, lock.metadata.version);
                    })
                    .map_err(|e| e.to_string())
            }
        },
        Commands::Create(ca) => match parse_env_vars(&ca.env) {
            Err(msg) => Err(msg),
            Ok(env) => {
                let spec = SandboxSpec {
                    id: ca.id,
                    ports: ca.ports,
                    runtime: ca.runtime.as_deref().map(parse_runtime),
                    memory_mb: ca.memory_mb,
                    vcpus: ca.vcpus,
                    idle_timeout_secs: ca.idle_timeout_secs,
                    ssh_public_key: ca.ssh_key,
                    ssh_key_type: Some(ca.ssh_key_type),
                    env,
                    image_id: ca.image_id,
                    image_digest: ca.image_digest,
                    credential_request: None,
                    service_class: None,
                };
                client
                    .create_sandbox(&spec)
                    .await
                    .and_then(|info| print_json(&info))
            }
        },
        Commands::List(la) => client
            .list_sandboxes(la.limit, la.cursor.as_deref())
            .await
            .and_then(|page| print_json(&page)),
        Commands::Get(ga) => client
            .get_sandbox(&ga.id)
            .await
            .and_then(|info| print_json(&info)),
        Commands::Destroy(da) => client.destroy_sandbox(&da.id).await.map(|()| {
            println!("destroyed {}", da.id);
        }),
        Commands::Stop(sa) => client.stop_sandbox(&sa.id).await.map(|()| {
            println!("stopped {}", sa.id);
        }),
        Commands::Purge(pa) => client.purge_sandbox(&pa.id).await.map(|()| {
            println!("purged {}", pa.id);
        }),
        Commands::Suspend(sa) => client.suspend_sandbox(&sa.id).await.map(|()| {
            println!("suspend requested {}", sa.id);
        }),
        Commands::Resume(ra) => client.resume_sandbox(&ra.id).await.map(|()| {
            println!("resume requested {}", ra.id);
        }),
        Commands::Keepalive(ka) => client.keepalive_sandbox(&ka.id).await.map(|()| {
            println!("keepalive sent {}", ka.id);
        }),
        Commands::Exec(ea) => match parse_env_vars(&ea.env) {
            Err(msg) => Err(msg),
            Ok(env) => {
                let req = pico_core::ExecRequest {
                    command: ea.command,
                    args: ea.args,
                    env,
                    working_dir: ea.working_dir,
                    timeout_secs: ea.timeout_secs,
                };
                client
                    .exec_sandbox(&ea.id, &req)
                    .await
                    .and_then(|resp| print_json(&resp))
            }
        },
        Commands::SshInfo(sa) => client
            .ssh_info(&sa.id)
            .await
            .and_then(|info| print_json(&info)),
        Commands::Ssh(sa) => ssh::ssh_into_sandbox(&client, &sa.id).await,
        Commands::Files(fa) => match fa.command {
            FilesCommands::Read { id, path } => client
                .file_read(&id, &path)
                .await
                .and_then(|resp| print_json(&resp)),
            FilesCommands::Write {
                id,
                path,
                content,
                file,
                append,
            } => match resolve_file_content(content, file) {
                Err(msg) => Err(msg),
                Ok(text) => {
                    let req = pico_core::FileWriteRequest {
                        path,
                        content: text,
                        append,
                    };
                    client
                        .file_write(&id, &req)
                        .await
                        .and_then(|info| print_json(&info))
                }
            },
            FilesCommands::List {
                id,
                dir,
                recursive,
                limit,
                cursor,
            } => client
                .file_list(&id, &dir, recursive, limit, cursor.as_deref())
                .await
                .and_then(|page| print_json(&page)),
        },
        Commands::Tasks(ta) => match ta.command {
            TasksCommands::Start {
                id,
                prompt,
                agent,
                model,
                timeout_secs,
            } => {
                let req = pico_core::TaskRequest {
                    prompt,
                    agent,
                    model,
                    timeout_secs,
                };
                client
                    .task_start(&id, &req)
                    .await
                    .and_then(|info| print_json(&info))
            }
            TasksCommands::Get { id, task_id } => client
                .task_get(&id, &task_id)
                .await
                .and_then(|info| print_json(&info)),
            TasksCommands::Cancel { id, task_id } => {
                client.task_cancel(&id, &task_id).await.map(|()| {
                    println!("cancelled {task_id} in {id}");
                })
            }
            TasksCommands::Events { id, task_id } => client.stream_task_events(&id, &task_id).await,
        },
        Commands::Ports(pa) => match pa.command {
            PortsCommands::Expose {
                id,
                tenant_id,
                lease_id,
                guest_port,
                host_port,
                localhost_only,
                max_connections,
                lease,
            } => match parse_port_ids(&tenant_id, &lease_id) {
                Err(msg) => Err(msg),
                Ok((tenant, lease_id)) => {
                    let req = pico_core::PortForwardRequest {
                        tenant_id: tenant,
                        lease_id,
                        guest_port,
                        requested_host_port: host_port,
                        localhost_only,
                        max_connections,
                        lease,
                    };
                    client
                        .expose_port(&id, &req)
                        .await
                        .and_then(|resp| print_json(&resp))
                }
            },
            PortsCommands::List { id } => client
                .list_ports(&id)
                .await
                .and_then(|endpoints| print_json(&endpoints)),
            PortsCommands::Revoke { id, endpoint_id } => client
                .revoke_port(&id, &endpoint_id)
                .await
                .and_then(|resp| print_json(&resp)),
        },
        Commands::Lease(la) => match la.command {
            LeaseCommands::Issue {
                id,
                action,
                ports,
                paths,
                egress_cidrs,
                credential_types,
            } => match LeaseAction::from_name(&action) {
                None => Err(format!("unknown lease action: {action}")),
                Some(parsed) => {
                    let scope = LeaseScope {
                        ports,
                        paths,
                        egress_cidrs,
                        credential_types,
                    };
                    client
                        .issue_lease(&id, parsed, scope)
                        .await
                        .and_then(|lease| print_json(&lease))
                }
            },
        },
        Commands::Operator(oa) => match oa.command {
            OperatorCommands::QuarantineAck {
                ticket,
                host,
                condition,
                owner,
            } => operator::run_quarantine_ack(&ticket, &host, &condition, &owner)
                .map(|out| println!("{out}")),
            OperatorCommands::QuarantineResolve {
                ticket,
                host,
                condition,
                condition_cleared,
            } => operator::run_quarantine_resolve(&ticket, &host, &condition, condition_cleared)
                .map(|out| println!("{out}")),
            OperatorCommands::FencedCleanup {
                ticket,
                fencing_token,
            } => operator::run_fenced_cleanup(&ticket, &fencing_token).map(|out| println!("{out}")),
            OperatorCommands::LedgerInspect {
                ticket,
                query,
                sandbox_id,
            } => operator::run_ledger_inspect(&ticket, &query, sandbox_id.as_deref())
                .map(|out| println!("{out}")),
            OperatorCommands::Drain {
                host_url,
                host_token,
                ticket,
            } => {
                let env_token = std::env::var(operator::HOST_TOKEN_ENV).unwrap_or_default();
                let env_opt = if env_token.trim().is_empty() {
                    None
                } else {
                    Some(env_token.as_str())
                };
                match operator::resolve_host_token(host_token.as_deref(), env_opt) {
                    Err(msg) => Err(msg),
                    Ok(token) => operator::run_drain(&host_url, &token, &ticket)
                        .await
                        .map(|out| println!("{out}")),
                }
            }
            OperatorCommands::DrainStatus { host_url } => operator::run_drain_status(&host_url)
                .await
                .map(|out| println!("{out}")),
            OperatorCommands::ReadmitCheck {
                quarantine_gauge_zero,
                capacity_age_secs,
                health,
                reconciliation_clean,
                watch_clean,
            } => operator::run_readmit_check(
                quarantine_gauge_zero,
                capacity_age_secs,
                &health,
                reconciliation_clean,
                watch_clean,
            )
            .map(|out| println!("{out}")),
        },
    };

    if let Err(msg) = result {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }
}

fn parse_runtime(name: &str) -> RuntimeType {
    match name.to_lowercase().as_str() {
        "firecracker" => RuntimeType::Firecracker,
        "qemu" => RuntimeType::Qemu,
        "remote-firecracker" => RuntimeType::RemoteFirecracker,
        other => {
            eprintln!("warning: unknown runtime '{other}', defaulting to firecracker");
            RuntimeType::Firecracker
        }
    }
}

fn parse_env_vars(vars: &[String]) -> Result<Option<HashMap<String, String>>, String> {
    if vars.is_empty() {
        return Ok(None);
    }
    let mut env = HashMap::default();
    for raw in vars {
        let (key, value) = raw
            .split_once('=')
            .ok_or_else(|| format!("invalid env {raw:?}: expected KEY=VALUE"))?;
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Err(format!("invalid env {raw:?}: key is empty"));
        }
        env.insert(trimmed.to_string(), value.to_string());
    }
    Ok(Some(env))
}

/// Maximum byte length of a PicoCompute identifier backed by a 128-byte inline string.
const MAX_ID_LEN: usize = 128;

fn parse_port_ids(
    tenant_id: &str,
    lease_id: &str,
) -> Result<(pico_core::TenantId, pico_core::LeaseId), String> {
    let tenant = tenant_id.trim();
    if tenant.is_empty() {
        return Err("tenant id is required".to_string());
    }
    if tenant.len() > MAX_ID_LEN {
        return Err(format!(
            "tenant id exceeds {MAX_ID_LEN}-byte limit (got {} bytes)",
            tenant.len()
        ));
    }
    let lease = lease_id.trim();
    if lease.is_empty() {
        return Err("lease id is required".to_string());
    }
    if lease.len() > MAX_ID_LEN {
        return Err(format!(
            "lease id exceeds {MAX_ID_LEN}-byte limit (got {} bytes)",
            lease.len()
        ));
    }
    Ok((
        pico_core::TenantId::from_string(tenant),
        pico_core::LeaseId::from_string(lease),
    ))
}

fn print_json(value: &impl serde::Serialize) -> Result<(), String> {
    serde_json::to_string_pretty(value)
        .map_err(|e| format!("failed to render response: {e}"))
        .map(|text| println!("{text}"))
}

fn resolve_file_content(
    content: Option<String>,
    file: Option<camino::Utf8PathBuf>,
) -> Result<String, String> {
    match (content, file) {
        (Some(text), None) => Ok(text),
        (None, Some(path)) => {
            std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path))
        }
        (None, None) => Err("--content or --file is required".to_string()),
        (Some(_), Some(_)) => Err("use only one of --content or --file".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_runtime_known_names() {
        assert_eq!(parse_runtime("firecracker"), RuntimeType::Firecracker);
        assert_eq!(parse_runtime("qemu"), RuntimeType::Qemu);
        assert_eq!(
            parse_runtime("remote-firecracker"),
            RuntimeType::RemoteFirecracker
        );
    }

    #[test]
    fn parse_runtime_case_insensitive() {
        assert_eq!(parse_runtime("QEMU"), RuntimeType::Qemu);
        assert_eq!(parse_runtime("Firecracker"), RuntimeType::Firecracker);
    }

    #[test]
    fn parse_runtime_unknown_defaults_to_firecracker() {
        assert_eq!(parse_runtime("docker"), RuntimeType::Firecracker);
    }

    #[test]
    fn parse_env_vars_empty_is_none() {
        assert_eq!(parse_env_vars(&[]).unwrap(), None);
    }

    #[test]
    fn parse_env_vars_splits_key_value() {
        let vars = vec!["FOO=bar".to_string(), "EMPTY=".to_string()];
        let env = parse_env_vars(&vars).unwrap().unwrap();
        assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(env.get("EMPTY").map(String::as_str), Some(""));
    }

    #[test]
    fn parse_env_vars_rejects_missing_equals() {
        assert!(parse_env_vars(&["NOEQUALS".to_string()]).is_err());
        assert!(parse_env_vars(&["=value".to_string()]).is_err());
    }

    #[test]
    fn parse_env_vars_trims_keys() {
        let env = parse_env_vars(&[" FOO=bar".to_string()]).unwrap().unwrap();
        assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
        assert!(!env.contains_key(" FOO"));
    }

    #[test]
    fn parse_env_vars_keeps_value_spacing() {
        let env = parse_env_vars(&["FOO= bar ".to_string()]).unwrap().unwrap();
        assert_eq!(env.get("FOO").map(String::as_str), Some(" bar "));
    }

    #[test]
    fn parse_port_ids_accepts_valid_ids() {
        let (tenant, lease) = parse_port_ids("tnt_1", "lse_1").unwrap();
        assert_eq!(tenant.as_str(), "tnt_1");
        assert_eq!(lease.as_str(), "lse_1");
    }

    #[test]
    fn parse_port_ids_rejects_empty() {
        assert!(parse_port_ids("", "lse_1").is_err());
        assert!(parse_port_ids("tnt_1", "  ").is_err());
    }

    #[test]
    fn parse_port_ids_rejects_overlong_ids() {
        let long = "x".repeat(129);
        assert!(parse_port_ids(&long, "lse_1").is_err());
        assert!(parse_port_ids("tnt_1", &long).is_err());
        let max = "x".repeat(128);
        assert!(parse_port_ids(&max, &max).is_ok());
    }

    #[test]
    fn print_json_renders_value() {
        assert!(print_json(&serde_json::json!({"ok": true})).is_ok());
    }

    #[test]
    fn resolve_file_content_prefers_inline() {
        assert_eq!(
            resolve_file_content(Some("hi".to_string()), None).unwrap(),
            "hi"
        );
    }

    #[test]
    fn resolve_file_content_requires_one_source() {
        assert!(resolve_file_content(None, None).is_err());
        assert!(
            resolve_file_content(Some("a".to_string()), Some(camino::Utf8PathBuf::from("b")),)
                .is_err()
        );
    }

    #[test]
    fn spec_from_create_args_keeps_new_fields() {
        let env = parse_env_vars(&["FOO=bar".to_string()]).unwrap();
        let spec = SandboxSpec {
            id: Some("sbx_1".to_string()),
            ports: None,
            runtime: Some(RuntimeType::Qemu),
            memory_mb: None,
            vcpus: None,
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            env,
            image_id: Some("img_1".to_string()),
            image_digest: Some("sha256:abc".to_string()),
            credential_request: None,
            service_class: None,
        };
        assert_eq!(spec.image_id.as_deref(), Some("img_1"));
        assert!(spec.env.unwrap().contains_key("FOO"));
    }
}
