#!/usr/bin/env python3
"""Simulate burn-rate alert thresholds against sample SLI traffic.

This is the offline test for docs/observability/slo-error-budget-policy.md.
It does not query Prometheus. It checks:

- budget remaining math
- fast (14.4x on 1h and 5m) and slow (6x on 6h and 30m) alert predicates
- recording-rule and alert names exist in o11y/rules/pico-recording-rules.yaml
"""

from __future__ import annotations

import sys
from pathlib import Path

FAST_BURN = 14.4
SLOW_BURN = 6.0
WINDOW_DAYS = 30

TARGETS = {
    "create": 0.995,
    "boot": 0.995,
    "exec": 0.999,
    "destroy": 0.999,
    "suspend": 0.995,
    "resume": 0.995,
    "fork": 0.995,
    "restore": 0.995,
    "audit": 0.9999,
}

REQUIRED_RECORDS = (
    "pico:slo:availability_target",
    "pico:slo:bad:rate5m",
    "pico:slo:valid:rate5m",
    "pico:slo:error_ratio:5m",
    "pico:slo:error_ratio:30m",
    "pico:slo:error_ratio:1h",
    "pico:slo:error_ratio:6h",
    "pico:slo:error_ratio:30d",
    "pico:slo:burn:5m",
    "pico:slo:burn:30m",
    "pico:slo:burn:1h",
    "pico:slo:burn:6h",
    "pico:slo:budget_remaining",
)

REQUIRED_ALERTS = (
    "PicoComputeSloBurnFast",
    "PicoComputeSloBurnSlow",
    "PicoComputeSloBudgetExhausted",
    "PicoComputeSloTelemetryStale",
)


def error_ratio(bad: float, valid: float) -> float:
    if valid <= 0:
        raise ValueError("valid events must be positive")
    return bad / valid


def burn(ratio: float, target: float) -> float:
    budget = 1.0 - target
    if budget <= 0:
        raise ValueError("target must be < 1")
    return ratio / budget


def budget_remaining(ratio: float, target: float) -> float:
    return max(0.0, 1.0 - ratio / (1.0 - target))


def fast_fires(burn_1h: float, burn_5m: float, valid_rate_5m: float) -> bool:
    return burn_1h > FAST_BURN and burn_5m > FAST_BURN and valid_rate_5m > 0.01


def slow_fires(burn_6h: float, burn_30m: float, valid_rate_30m: float) -> bool:
    return burn_6h > SLOW_BURN and burn_30m > SLOW_BURN and valid_rate_30m > 0.003


def check_rules(rules_path: Path) -> None:
    text = rules_path.read_text()
    missing = [name for name in REQUIRED_RECORDS if f"record: {name}" not in text]
    missing += [name for name in REQUIRED_ALERTS if f"alert: {name}" not in text]
    if "outcome=\"error\"" in text:
        missing.append("stale outcome=error SLI selector")
    if missing:
        raise AssertionError(f"recording rules missing {missing}")


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    check_rules(repo / "o11y/rules/pico-recording-rules.yaml")

    target = TARGETS["create"]
    # 99.5% SLO, 0.5% budget: 7.2% errors is 14.4x burn.
    ratio_fast = 0.072
    assert abs(burn(ratio_fast, target) - FAST_BURN) < 1e-9
    assert abs(budget_remaining(0.005, target) - 0.0) < 1e-9
    assert abs(budget_remaining(0.0, target) - 1.0) < 1e-9
    assert abs(budget_remaining(0.0025, target) - 0.5) < 1e-9

    assert fast_fires(14.5, 14.5, 0.02)
    assert not fast_fires(14.5, 14.5, 0.001)
    assert not fast_fires(14.5, 1.0, 0.02)
    assert slow_fires(6.1, 6.1, 0.01)
    assert not slow_fires(6.1, 5.0, 0.01)

    # Quiet region: 1 bad / 2 valid looks like 50% errors but must not page.
    quiet_ratio = error_ratio(1, 2)
    quiet_burn = burn(quiet_ratio, target)
    assert quiet_burn > FAST_BURN
    assert not fast_fires(quiet_burn, quiet_burn, 2 / 300)

    # 99.9% exec: 1.44% errors is 14.4x.
    exec_fast_ratio = FAST_BURN * (1.0 - TARGETS["exec"])
    assert abs(exec_fast_ratio - 0.0144) < 1e-9

    hours_to_exhaust = WINDOW_DAYS * 24 / FAST_BURN
    assert abs(hours_to_exhaust - 50) < 0.1

    print("ok: burn-rate math and recording-rule names")
    return 0


if __name__ == "__main__":
    sys.exit(main())
