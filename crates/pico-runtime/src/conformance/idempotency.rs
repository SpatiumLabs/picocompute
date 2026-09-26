use std::time::Instant;

use pico_core::RuntimeBackend;

use super::{ConformanceCheck, ConformanceReport};

pub(super) async fn test_destroy_idempotency(
    backend: &dyn RuntimeBackend,
    report: &mut ConformanceReport,
) {
    let t0 = Instant::now();
    let first = backend.destroy().await;
    let t_first = t0.elapsed().as_millis() as u64;

    let t0 = Instant::now();
    let second = backend.destroy().await;
    let t_second = t0.elapsed().as_millis() as u64;

    match (&first, &second) {
        (Ok(_), Ok(_)) => {
            report.add_check(ConformanceCheck::pass(
                "idempotency/destroy-twice-ok",
                t_first.max(t_second),
            ));
        }
        (Ok(_), Err(e)) => {
            report.add_check(ConformanceCheck::fail(
                "idempotency/destroy-twice-ok",
                format!("second destroy failed (first succeeded): {e}"),
                t_first.max(t_second),
            ));
        }
        (Err(e), Ok(_)) => {
            report.add_check(ConformanceCheck::fail(
                "idempotency/destroy-twice-ok",
                format!("first destroy failed, second succeeded (inconsistent): {e}"),
                t_first.max(t_second),
            ));
        }
        (Err(e1), Err(e2)) => {
            report.add_check(ConformanceCheck::fail(
                "idempotency/destroy-twice-ok",
                format!("both destroys failed: first={e1}, second={e2}"),
                t_first.max(t_second),
            ));
        }
    }
}

pub(super) async fn test_cleanup_idempotency(
    backend: &dyn RuntimeBackend,
    report: &mut ConformanceReport,
) {
    let t0 = Instant::now();
    let first = backend.cleanup().await;
    let t_first = t0.elapsed().as_millis() as u64;

    let t0 = Instant::now();
    let second = backend.cleanup().await;
    let t_second = t0.elapsed().as_millis() as u64;

    match (&first, &second) {
        (Ok(_), Ok(_)) => {
            report.add_check(ConformanceCheck::pass(
                "idempotency/cleanup-twice-ok",
                t_first.max(t_second),
            ));
        }
        (Ok(_), Err(e)) => {
            report.add_check(ConformanceCheck::fail(
                "idempotency/cleanup-twice-ok",
                format!("second cleanup failed (first succeeded): {e}"),
                t_first.max(t_second),
            ));
        }
        (Err(e), Ok(_)) => {
            report.add_check(ConformanceCheck::fail(
                "idempotency/cleanup-twice-ok",
                format!("first cleanup failed, second succeeded (inconsistent): {e}"),
                t_first.max(t_second),
            ));
        }
        (Err(e1), Err(e2)) => {
            report.add_check(ConformanceCheck::fail(
                "idempotency/cleanup-twice-ok",
                format!("both cleanups failed: first={e1}, second={e2}"),
                t_first.max(t_second),
            ));
        }
    }
}
