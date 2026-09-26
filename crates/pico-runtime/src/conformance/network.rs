use std::time::Instant;

use pico_core::{BackendCapability, PortExposure, RuntimeBackend};

use super::{ConformanceCheck, ConformanceReport};

pub(super) fn test_network_behavior(backend: &dyn RuntimeBackend, report: &mut ConformanceReport) {
    let t0 = Instant::now();
    let ssh_exposure = backend.port_exposure(22);
    match ssh_exposure {
        PortExposure::HostProxy | PortExposure::BackendManaged | PortExposure::Unsupported => {
            report.add_check(ConformanceCheck::pass(
                "network/port-exposure-valid-variant",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let metadata = backend.metadata();
    let has_managed = metadata
        .capabilities
        .contains(BackendCapability::BackendManagedPortForwarding);

    if has_managed {
        let t0 = Instant::now();
        let exposures: Vec<_> = [22u16, 80, 443, 8080]
            .iter()
            .map(|p| backend.port_exposure(*p))
            .collect();
        let has_managed_port = exposures.contains(&PortExposure::BackendManaged);
        if has_managed_port {
            report.add_check(ConformanceCheck::pass(
                "network/managed-port-exists",
                t0.elapsed().as_millis() as u64,
            ));
        } else {
            report.add_check(ConformanceCheck::fail(
                "network/managed-port-exists",
                "BackendManagedPortForwarding declared but no port returns BackendManaged",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }
}
