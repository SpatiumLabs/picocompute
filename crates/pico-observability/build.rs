use std::env;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        generate_stub_bpf_elf();
    }

    #[cfg(target_os = "linux")]
    {
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let ebpf_crate = manifest_dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("pico-observability-ebpf");

        if !ebpf_crate.join("Cargo.toml").exists() {
            eprintln!(
                "eBPF crate not found at {}, using stub",
                ebpf_crate.display()
            );
            generate_stub_bpf_elf();
            return;
        }

        let arch_feature = match target_arch.as_str() {
            "x86_64" | "x86" => "arch-x86_64",
            "aarch64" | "arm" => "arch-aarch64",
            other => {
                eprintln!(
                    "unsupported target architecture '{}' for eBPF probes, using stub",
                    other
                );
                generate_stub_bpf_elf();
                return;
            }
        };

        let status = Command::new("cargo")
            .args([
                "build",
                "--manifest-path",
                ebpf_crate.join("Cargo.toml").to_str().unwrap(),
                "--release",
                "--target",
                "bpfel-unknown-none",
                "-Z",
                "build-std=core",
                "--features",
                arch_feature,
            ])
            .status();

        match status {
            Ok(s) if s.success() => {
                let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
                let bpf_elf = ebpf_crate
                    .join("target")
                    .join("bpfel-unknown-none")
                    .join("release")
                    .join("pico-observability-ebpf");

                let dest = out_dir.join("pico_observability.bpf.o");
                if bpf_elf.exists() {
                    std::fs::copy(&bpf_elf, &dest).ok();
                    println!(
                        "cargo:rerun-if-changed={}",
                        ebpf_crate.join("src").display()
                    );
                } else {
                    eprintln!("eBPF ELF not found after build, using stub");
                    generate_stub_bpf_elf();
                }
            }
            _ => {
                eprintln!("eBPF crate build failed, using stub");
                generate_stub_bpf_elf();
            }
        }
    }
}

fn generate_stub_bpf_elf() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("pico_observability.bpf.o");
    let _ = std::fs::write(&dest, []);
}
