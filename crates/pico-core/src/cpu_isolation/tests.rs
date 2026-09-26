use super::*;

// --- CpuSet tests ---

#[test]
fn cpu_set_new_sorts_and_deduplicates() {
    let set = CpuSet::new([3u32, 1, 3, 2]).unwrap();
    assert_eq!(set.as_slice(), &[1, 2, 3]);
}

#[test]
fn cpu_set_empty_returns_none() {
    assert!(CpuSet::new(Vec::<u32>::new()).is_none());
}

#[test]
fn cpu_set_overlap_detection() {
    let a = CpuSet::new([0u32, 1, 2]).unwrap();
    let b = CpuSet::new([2u32, 3, 4]).unwrap();
    let c = CpuSet::new([5u32, 6]).unwrap();
    assert!(a.overlaps(&b));
    assert!(!a.overlaps(&c));
}

#[test]
fn cpu_set_intersection() {
    let a = CpuSet::new([0u32, 1, 2, 3]).unwrap();
    let b = CpuSet::new([2u32, 3, 4, 5]).unwrap();
    assert_eq!(a.intersection(&b), vec![2, 3]);
}

#[test]
fn cpu_set_display() {
    let set = CpuSet::new([0u32, 1, 3]).unwrap();
    assert_eq!(set.to_string(), "0,1,3");
}

#[test]
fn cpu_set_hex_mask() {
    let set = CpuSet::new([0u32, 1, 3]).unwrap();
    let mask = set.to_hex_mask();
    // CPU 0,1,3 -> bitmask 0b1011 = 0x0b
    assert!(mask.contains("0b"));
}

#[test]
fn cpu_set_union() {
    let a = CpuSet::new([0u32, 1]).unwrap();
    let b = CpuSet::new([1u32, 2]).unwrap();
    let u = a.union(&b);
    assert_eq!(u.as_slice(), &[0, 1, 2]);
}

// --- CpuTopology tests ---

#[test]
fn flat_fallback_creates_one_core_per_cpu() {
    let topo = CpuTopology::flat_fallback();
    assert!(topo.total_logical_cpus > 0);
    assert_eq!(topo.physical_cores.len(), topo.total_logical_cpus);
    for core in &topo.physical_cores {
        assert_eq!(core.siblings.len(), 1);
    }
}

#[test]
fn smt_sibling_map_is_complete() {
    let topo = CpuTopology::flat_fallback();
    let map = topo.smt_sibling_map();
    assert_eq!(map.len(), topo.total_logical_cpus);
}

#[test]
fn validate_smt_exclusion_detects_sharing() {
    let topo = CpuTopology {
        total_logical_cpus: 4,
        physical_cores: vec![
            PhysicalCore {
                core_id: 0,
                siblings: vec![0, 2],
            },
            PhysicalCore {
                core_id: 1,
                siblings: vec![1, 3],
            },
        ],
    };

    let a = CpuSet::new([0u32]).unwrap();
    let b = CpuSet::new([2u32]).unwrap(); // sibling of 0
    let c = CpuSet::new([1u32]).unwrap();

    let violations = topo.validate_smt_exclusion(&[&a, &b]);
    assert_eq!(violations.len(), 1);

    let violations = topo.validate_smt_exclusion(&[&a, &c]);
    assert_eq!(violations.len(), 0);
}

// --- CpuAllocator tests ---

#[test]
fn allocator_no_pinning_returns_all_cpus() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::None);
    let set = allocator.allocate("sbx_a", "tnt_1", None, 1).unwrap();
    assert_eq!(set.len(), allocator.topology().total_logical_cpus);
}

#[test]
fn allocator_detects_overlap_with_different_tenant() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);
    let set_a = CpuSet::new([0u32]).unwrap();
    allocator
        .allocate("sbx_a", "tnt_1", Some(&set_a), 1)
        .unwrap();

    let set_b = CpuSet::new([0u32]).unwrap();
    let err = allocator
        .allocate("sbx_b", "tnt_2", Some(&set_b), 1)
        .unwrap_err();
    assert!(matches!(err, CpuAllocationError::Overlap { .. }));
}

#[test]
fn allocator_allows_same_tenant_overlap() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);
    let set_a = CpuSet::new([0u32]).unwrap();
    allocator
        .allocate("sbx_a", "tnt_1", Some(&set_a), 1)
        .unwrap();
    allocator
        .allocate("sbx_b", "tnt_1", Some(&set_a), 1)
        .unwrap();
    // Same tenant, overlap is allowed
}

#[test]
fn allocator_detects_smt_exclusion_violation() {
    let topo = CpuTopology {
        total_logical_cpus: 4,
        physical_cores: vec![
            PhysicalCore {
                core_id: 0,
                siblings: vec![0, 2],
            },
            PhysicalCore {
                core_id: 1,
                siblings: vec![1, 3],
            },
        ],
    };
    let mut allocator = CpuAllocator::new(
        topo.clone(),
        CpuIsolationPolicy::DedicatedCoresWithSmtExclusion,
    );
    let set_a = CpuSet::new([0u32]).unwrap();
    allocator
        .allocate("sbx_a", "tnt_1", Some(&set_a), 1)
        .unwrap();

    let set_b = CpuSet::new([2u32]).unwrap(); // SMT sibling of 0
    let err = allocator
        .allocate("sbx_b", "tnt_2", Some(&set_b), 1)
        .unwrap_err();
    assert!(matches!(
        err,
        CpuAllocationError::SmtExclusionViolation { .. }
    ));
}

#[test]
fn allocator_release_frees_cpus() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);
    let set_a = CpuSet::new([0u32]).unwrap();
    allocator
        .allocate("sbx_a", "tnt_1", Some(&set_a), 1)
        .unwrap();
    allocator.release("sbx_a");

    let set_b = CpuSet::new([0u32]).unwrap();
    // After release, CPU 0 should be free again
    assert!(
        allocator
            .allocate("sbx_b", "tnt_2", Some(&set_b), 1)
            .is_ok()
    );
}

#[test]
fn allocator_restore_blocks_reallocating_restored_cpus() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);
    let set_a = CpuSet::new([0u32]).unwrap();
    allocator.restore("sbx_a", "tnt_1", set_a.clone()).unwrap();

    assert_eq!(allocator.get("sbx_a"), Some(&set_a));
    let set_b = CpuSet::new([0u32]).unwrap();
    let err = allocator
        .allocate("sbx_b", "tnt_2", Some(&set_b), 1)
        .unwrap_err();
    assert!(matches!(err, CpuAllocationError::Overlap { .. }));
}

#[test]
fn allocator_restore_allows_same_tenant_sharing() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);
    let set_a = CpuSet::new([0u32]).unwrap();
    allocator.restore("sbx_a", "tnt_1", set_a.clone()).unwrap();

    let set_b = CpuSet::new([0u32]).unwrap();
    assert!(
        allocator
            .allocate("sbx_b", "tnt_1", Some(&set_b), 1)
            .is_ok()
    );
}

#[test]
fn allocator_restore_rejects_out_of_range_cpu_set() {
    let topo = CpuTopology::flat_fallback();
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);
    let set_a = CpuSet::new([u32::MAX]).unwrap();
    let err = allocator
        .restore("sbx_a", "tnt_1", set_a.clone())
        .unwrap_err();
    assert!(matches!(err, CpuAllocationError::InvalidCpuIndices { .. }));
    assert_eq!(allocator.get("sbx_a"), None);
}

#[test]
fn validate_cross_tenant_smt_detects_violation() {
    let topo = CpuTopology {
        total_logical_cpus: 4,
        physical_cores: vec![
            PhysicalCore {
                core_id: 0,
                siblings: vec![0, 2],
            },
            PhysicalCore {
                core_id: 1,
                siblings: vec![1, 3],
            },
        ],
    };
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCoresWithSmtExclusion);

    // Allocate CPU 0 to tenant 1
    allocator
        .allocate("sbx_a", "tnt_1", Some(&CpuSet::new([0u32]).unwrap()), 1)
        .unwrap();

    // Attempt to allocate CPU 2 (SMT sibling of 0) to tenant 2 - should be rejected
    let err = allocator
        .allocate("sbx_b", "tnt_2", Some(&CpuSet::new([2u32]).unwrap()), 1)
        .unwrap_err();
    assert!(matches!(
        err,
        CpuAllocationError::SmtExclusionViolation { .. }
    ));

    // Valid: allocate CPU 1 (non-overlapping, non-sibling) to tenant 2
    allocator
        .allocate("sbx_b", "tnt_2", Some(&CpuSet::new([1u32]).unwrap()), 1)
        .unwrap();

    let violations = allocator.validate_cross_tenant_smt();
    assert_eq!(violations.len(), 0);
}

#[test]
fn allocate_rejects_out_of_range_cpu_indices() {
    let topo = CpuTopology {
        total_logical_cpus: 2,
        physical_cores: vec![
            PhysicalCore {
                core_id: 0,
                siblings: vec![0],
            },
            PhysicalCore {
                core_id: 1,
                siblings: vec![1],
            },
        ],
    };
    let mut allocator = CpuAllocator::new(topo, CpuIsolationPolicy::DedicatedCores);

    let bad_set = CpuSet::new([0u32, 5]).unwrap();
    let err = allocator
        .allocate("sbx_a", "tnt_1", Some(&bad_set), 1)
        .unwrap_err();
    assert!(matches!(err, CpuAllocationError::InvalidCpuIndices { .. }));
}

#[test]
fn cpu_set_validate_topology_rejects_out_of_range() {
    let topo = CpuTopology {
        total_logical_cpus: 4,
        physical_cores: vec![],
    };
    let set = CpuSet::new([0u32, 3, 5]).unwrap();
    assert_eq!(set.validate_against_topology(&topo), Err(vec![5]));
}

// --- parse_cpu_list tests ---

#[test]
fn parse_range() {
    assert_eq!(parse_cpu_list("0-3"), vec![0, 1, 2, 3]);
}

#[test]
fn parse_mixed() {
    assert_eq!(parse_cpu_list("0,2-4,7"), vec![0, 2, 3, 4, 7]);
}

#[test]
fn parse_empty() {
    assert!(parse_cpu_list("").is_empty());
}

#[test]
fn parse_single() {
    assert_eq!(parse_cpu_list("5"), vec![5]);
}

// --- CpuIsolationPolicy tests ---

#[test]
fn policy_requires_pinning() {
    assert!(!CpuIsolationPolicy::None.requires_pinning());
    assert!(CpuIsolationPolicy::DedicatedCores.requires_pinning());
    assert!(CpuIsolationPolicy::DedicatedCoresWithSmtExclusion.requires_pinning());
}

#[test]
fn policy_requires_smt_exclusion() {
    assert!(!CpuIsolationPolicy::None.requires_smt_exclusion());
    assert!(!CpuIsolationPolicy::DedicatedCores.requires_smt_exclusion());
    assert!(CpuIsolationPolicy::DedicatedCoresWithSmtExclusion.requires_smt_exclusion());
}
