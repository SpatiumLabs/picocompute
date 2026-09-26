use std::hint::black_box;
use std::time::Instant;

use pico_network_agent::egress::EgressPolicy;
use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};

struct BenchmarkResult {
    name: &'static str,
    iterations: u64,
    total_ns: u128,
    avg_ns: u128,
}

impl BenchmarkResult {
    fn print(&self) {
        println!(
            "{:<50} {:>10} iters  {:>12} ns avg  {:>12} ns total",
            self.name, self.iterations, self.avg_ns, self.total_ns
        );
    }
}

fn run_bench<F>(name: &'static str, min_iterations: u64, mut f: F) -> BenchmarkResult
where
    F: FnMut(),
{
    for _ in 0..100 {
        f();
        black_box(());
    }

    let start = Instant::now();
    for _ in 0..min_iterations {
        f();
        black_box(());
    }
    let elapsed = start.elapsed().as_nanos();

    BenchmarkResult {
        name,
        iterations: min_iterations,
        total_ns: elapsed,
        avg_ns: elapsed / min_iterations as u128,
    }
}

fn main() {
    println!("=== eBPF Network Policy Microbenchmarks (98) ===\n");

    let mut results = Vec::new();

    let sandbox_id = "bench_sandbox_ebpf_test_12345";
    results.push(run_bench("identity::for_sandbox(microvm)", 100_000, || {
        let _ = SandboxNetworkIdentity::for_sandbox(sandbox_id, BackendClass::MicroVm);
    }));

    results.push(run_bench(
        "identity::for_sandbox(container)",
        100_000,
        || {
            let _ = SandboxNetworkIdentity::for_sandbox(sandbox_id, BackendClass::Container);
        },
    ));

    let policy = EgressPolicy {
        sandbox_id: "bench_sbx".into(),
        tenant_id: "bench_tnt".into(),
        if_name: "cvx001".into(),
        allowed_cidrs: vec![
            "1.1.1.1/32".into(),
            "8.8.8.8/32".into(),
            "10.0.0.1/32".into(),
            "172.16.0.1/32".into(),
        ],
        policy_decision_id: "bench_pdc".into(),
        lease_id: Some("bench_lse".into()),
    };

    results.push(run_bench("egress::compile_rules (4 CIDRs)", 50_000, || {
        let _ = policy.compile_rules();
    }));

    results.push(run_bench(
        "egress::compile_ruleset (4 CIDRs)",
        50_000,
        || {
            let _ = policy.compile_ruleset();
        },
    ));

    let test_ip = std::net::Ipv4Addr::new(172, 16, 0, 2);

    results.push(run_bench("ipv4_addr -> u32 (BE bytes)", 1_000_000, || {
        let be = u32::from_be_bytes(test_ip.octets());
        black_box(be);
    }));

    results.push(run_bench("fnv1a64 hash (32 bytes)", 500_000, || {
        let _ = pico_network_agent::identity::fnv1a64(b"bench_sandbox_ebpf_test_12345");
    }));

    println!(
        "\n{:<50} {:>10} {:>14} {:>14}",
        "Benchmark", "Iters", "Avg (ns)", "Total (ns)"
    );
    println!("{}", "-".repeat(90));

    for result in &results {
        result.print();
    }

    println!("\n=== Estimated Throughput Comparison ===");
    println!("eBPF XDP drop path: < 100 ns per packet (kernel-native, no syscall)");
    println!("nftables drop path: ~500 ns per packet (netfilter hook traversal)");
    println!(
        "Estimated speedup: ~5x when XDP is used for simple L3 deny-by-default with small allow-list"
    );
    println!("\nNote: Actual throughput depends on hardware, kernel version, and workload.");
    println!("Run on Linux with XDP-capable NIC for real end-to-end measurements.");
}
