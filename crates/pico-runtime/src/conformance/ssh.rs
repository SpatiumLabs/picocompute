use std::time::Instant;

use pico_core::RuntimeBackend;

use super::{ConformanceCheck, ConformanceReport};

pub(super) fn test_ssh_metadata(backend: &dyn RuntimeBackend, report: &mut ConformanceReport) {
    let t0 = Instant::now();
    let username = backend.ssh_username();
    if !username.is_empty() {
        report.add_check(ConformanceCheck::pass(
            "ssh/username-non-empty",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::fail(
            "ssh/username-non-empty",
            "SSH username is empty",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let home_dir = backend.ssh_home_dir();
    if !home_dir.is_empty() {
        report.add_check(ConformanceCheck::pass(
            "ssh/home-dir-non-empty",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::fail(
            "ssh/home-dir-non-empty",
            "SSH home directory is empty",
            t0.elapsed().as_millis() as u64,
        ));
    }
}
