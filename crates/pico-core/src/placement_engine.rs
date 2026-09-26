//! Generic placement engine for filter-score-select scheduling.
//!
//! Extracts the shared algorithm used by both [`RegionalScheduler`] and
//! [`CellScheduler`]: filter candidates through hard constraints, score
//! survivors across weighted dimensions, and select the best candidate
//! with deterministic tie-breaking.
//!
//! ## Single-evaluation contract
//!
//! Constraint logic lives in one `filter` closure per scheduler
//! ([`ConstraintResult`]). Scoring lives in one `score` closure that returns
//! the full breakdown; [`place_with_breakdown`] sorts by the breakdown total
//! and returns the breakdowns directly so callers never re-score to rebuild
//! observability payloads. Headroom for backpressure derives from the stored
//! breakdown (`Fn(&C, &B) -> f64`), not from re-reading candidate capacity;
//! callers that already folded headroom into the breakdown ignore the
//! candidate argument. Legacy [`place`] delegates to [`place_with_breakdown`]
//! so sort and backpressure logic live once.

use std::fmt;

/// Result of a hard-constraint check.
#[derive(Debug, Clone)]
pub enum ConstraintResult {
    /// Candidate passes all hard constraints.
    Pass,
    /// Candidate fails with a human-readable reason.
    Fail(String),
}

/// A scored candidate with its total score.
#[derive(Debug, Clone)]
pub struct ScoredCandidate<'a, C> {
    /// The candidate that was scored.
    pub candidate: &'a C,
    /// Total weighted score.
    pub total_score: f64,
}

/// A scored candidate that retains its full breakdown.
///
/// Returned by [`place_with_breakdown`] so callers compute each candidate's
/// score once and reuse the breakdown for selection, observability, and
/// backpressure without a second scoring pass.
#[derive(Debug, Clone)]
pub struct ScoredWithBreakdown<'a, C, B> {
    /// The candidate that was scored.
    pub candidate: &'a C,
    /// Full scoring breakdown (observability payload).
    pub breakdown: B,
    /// Total weighted score extracted from `breakdown`.
    pub total_score: f64,
}

/// Backpressure signal computed from placement results.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlacementBackpressure {
    /// Fraction of candidates that passed hard constraints (0.0 to 1.0).
    pub admission_rate: f64,
    /// Average headroom score across surviving candidates.
    pub avg_headroom: f64,
    /// Whether the scheduler recommends throttling new requests.
    pub should_throttle: bool,
    /// Total candidates evaluated.
    pub total_candidates: usize,
    /// Candidates that passed hard constraints.
    pub eligible_candidates: usize,
}

impl PlacementBackpressure {
    /// Threshold below which the scheduler recommends throttling.
    pub const THROTTLE_THRESHOLD: f64 = 0.15;

    /// Threshold below which headroom triggers throttle.
    pub const HEADROOM_THRESHOLD: f64 = 0.10;
}

/// Outcome of a placement decision.
#[derive(Debug, Clone)]
pub struct PlacementOutcome<'a, C> {
    /// The selected candidate (if any).
    pub selected: Option<&'a C>,
    /// All scored candidates, sorted by score descending then ID ascending.
    pub scored: Vec<ScoredCandidate<'a, C>>,
    /// Candidates that failed hard constraints, with reasons.
    pub rejections: Vec<(&'a C, String)>,
    /// Backpressure signal.
    pub backpressure: PlacementBackpressure,
}

/// Outcome of [`place_with_breakdown`] carrying full breakdowns.
///
/// `scored` is sorted by total descending then ID ascending and already
/// contains the observability breakdowns, so callers must not re-invoke the
/// scoring closure to rebuild them.
#[derive(Debug, Clone)]
pub struct PlacementOutcomeWithBreakdown<'a, C, B> {
    /// The selected candidate (if any).
    pub selected: Option<&'a C>,
    /// All scored candidates with breakdowns, sorted deterministically.
    pub scored: Vec<ScoredWithBreakdown<'a, C, B>>,
    /// Candidates that failed hard constraints, with reasons.
    pub rejections: Vec<(&'a C, String)>,
    /// Backpressure signal.
    pub backpressure: PlacementBackpressure,
}

/// Execute the filter-score-select placement algorithm.
///
/// # Arguments
///
/// * `candidates` - Slice of candidates to evaluate
/// * `filter` - Hard constraint checker; returns `ConstraintResult::Pass` or `Fail(reason)`
/// * `score` - Scoring function; returns total score for a candidate
/// * `headroom` - Extracts headroom score (0.0-1.0) from a scored candidate for backpressure
/// * `id` - Extracts a string ID for deterministic tie-breaking
///
/// # Returns
///
/// A `PlacementOutcome` containing the selected candidate, all scores,
/// rejections, and backpressure signal.
pub fn place<'a, C, F, S, H, I>(
    candidates: &'a [C],
    filter: F,
    score: S,
    headroom: H,
    id: I,
) -> PlacementOutcome<'a, C>
where
    F: Fn(&C) -> ConstraintResult,
    S: Fn(&C) -> f64,
    H: Fn(&C, f64) -> f64,
    I: Fn(&C) -> &str,
{
    // Delegate so sort and backpressure logic live once in
    // `place_with_breakdown`; the trivial f64 breakdown carries the total.
    let outcome = place_with_breakdown(
        candidates,
        filter,
        |c| score(c),
        |c, total| headroom(c, *total),
        id,
        |total| *total,
    );
    PlacementOutcome {
        selected: outcome.selected,
        scored: outcome
            .scored
            .into_iter()
            .map(|s| ScoredCandidate {
                candidate: s.candidate,
                total_score: s.total_score,
            })
            .collect(),
        rejections: outcome.rejections,
        backpressure: outcome.backpressure,
    }
}

/// Execute filter-score-select in a single scoring pass.
///
/// Unlike [`place`], the `score` closure returns the full breakdown `B`.
/// The engine extracts the total via `total`, sorts deterministically, derives
/// backpressure headroom from the stored breakdown via `headroom`, and returns
/// the breakdowns so callers never score twice (once for ranking, once for
/// observability).
///
/// `filter` is the single constraint evaluation point: schedulers must route
/// all hard-constraint checks through it so a constraint fix lands once.
/// `classify` helpers must derive typed errors from the returned `rejections`,
/// not by re-evaluating candidate fields. `headroom` receives the candidate
/// for legacy callers; single-pass schedulers derive headroom from the stored
/// breakdown and ignore the candidate argument.
pub fn place_with_breakdown<'a, C, B, F, S, H, I, T>(
    candidates: &'a [C],
    filter: F,
    score: S,
    headroom: H,
    id: I,
    total: T,
) -> PlacementOutcomeWithBreakdown<'a, C, B>
where
    F: Fn(&C) -> ConstraintResult,
    S: Fn(&C) -> B,
    H: Fn(&C, &B) -> f64,
    I: Fn(&C) -> &str,
    T: Fn(&B) -> f64,
{
    let total_candidates = candidates.len();

    let mut passed: Vec<&C> = Vec::new();
    let mut rejections: Vec<(&C, String)> = Vec::new();

    for candidate in candidates {
        match filter(candidate) {
            ConstraintResult::Pass => passed.push(candidate),
            ConstraintResult::Fail(reason) => rejections.push((candidate, reason)),
        }
    }

    let eligible_candidates = passed.len();

    let mut scored: Vec<ScoredWithBreakdown<'a, C, B>> = passed
        .iter()
        .map(|c| {
            let breakdown = score(*c);
            let total_score = total(&breakdown);
            ScoredWithBreakdown {
                candidate: *c,
                breakdown,
                total_score,
            }
        })
        .collect();

    scored.sort_by(|a, b| {
        b.total_score
            .partial_cmp(&a.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| id(a.candidate).cmp(id(b.candidate)))
    });

    let selected = scored.first().map(|s| s.candidate);

    let admission_rate = if total_candidates > 0 {
        eligible_candidates as f64 / total_candidates as f64
    } else {
        0.0
    };

    let avg_headroom = if scored.is_empty() {
        0.0
    } else {
        let sum: f64 = scored
            .iter()
            .map(|s| headroom(s.candidate, &s.breakdown))
            .sum();
        sum / scored.len() as f64
    };

    let should_throttle = admission_rate < PlacementBackpressure::THROTTLE_THRESHOLD
        || avg_headroom < PlacementBackpressure::HEADROOM_THRESHOLD;

    PlacementOutcomeWithBreakdown {
        selected,
        scored,
        rejections,
        backpressure: PlacementBackpressure {
            admission_rate,
            avg_headroom,
            should_throttle,
            total_candidates,
            eligible_candidates,
        },
    }
}

/// Categorize a rejection reason into a standard category.
///
/// Used by both schedulers to aggregate rejection counts for observability.
pub fn categorize_rejection(reason: &str) -> &'static str {
    const CATEGORIES: &[(&str, &str)] = &[
        ("unavailable", "unavailable"),
        ("draining", "draining"),
        ("disabled", "disabled_for_placement"),
        ("capacity", "insufficient_capacity"),
        ("runtime", "unsupported_runtime"),
        ("pressure", "pressure_saturated"),
    ];
    CATEGORIES
        .iter()
        .find(|(keyword, _)| reason.contains(keyword))
        .map(|(_, category)| *category)
        .unwrap_or("other")
}

/// Aggregate rejection reasons into counts by category.
pub fn aggregate_rejections(rejections: &[(&impl fmt::Debug, String)]) -> Vec<(String, usize)> {
    let mut counts: hashbrown::HashMap<String, usize> = hashbrown::HashMap::new();
    for (_, reason) in rejections {
        let category = categorize_rejection(reason);
        *counts.entry(category.to_string()).or_insert(0) += 1;
    }
    counts.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct TestCandidate {
        id: String,
        capacity: u32,
        healthy: bool,
    }

    fn make_candidates() -> Vec<TestCandidate> {
        vec![
            TestCandidate {
                id: "c1".into(),
                capacity: 100,
                healthy: true,
            },
            TestCandidate {
                id: "c2".into(),
                capacity: 50,
                healthy: true,
            },
            TestCandidate {
                id: "c3".into(),
                capacity: 200,
                healthy: false,
            },
        ]
    }

    #[test]
    fn place_filters_unhealthy_candidates() {
        let candidates = make_candidates();
        let outcome = place(
            &candidates,
            |c| {
                if c.healthy {
                    ConstraintResult::Pass
                } else {
                    ConstraintResult::Fail("unhealthy".into())
                }
            },
            |c| c.capacity as f64,
            |_, score| score / 200.0,
            |c| &c.id,
        );

        assert_eq!(outcome.rejections.len(), 1);
        assert_eq!(outcome.scored.len(), 2);
        assert_eq!(outcome.selected.unwrap().id, "c1");
    }

    #[test]
    fn place_breaks_ties_by_id() {
        let candidates = vec![
            TestCandidate {
                id: "b".into(),
                capacity: 100,
                healthy: true,
            },
            TestCandidate {
                id: "a".into(),
                capacity: 100,
                healthy: true,
            },
        ];
        let outcome = place(
            &candidates,
            |_| ConstraintResult::Pass,
            |_| 50.0,
            |_, _| 0.5,
            |c| &c.id,
        );

        assert_eq!(outcome.selected.unwrap().id, "a");
    }

    #[test]
    fn place_returns_none_when_all_filtered() {
        let candidates = make_candidates();
        let outcome = place(
            &candidates,
            |_| ConstraintResult::Fail("all fail".into()),
            |_| 0.0,
            |_, _| 0.0,
            |c| &c.id,
        );

        assert!(outcome.selected.is_none());
        assert_eq!(outcome.rejections.len(), 3);
    }

    #[test]
    fn place_returns_none_for_empty_candidates() {
        let candidates: Vec<TestCandidate> = vec![];
        let outcome = place(
            &candidates,
            |_| ConstraintResult::Pass,
            |_| 0.0,
            |_, _| 0.0,
            |c| &c.id,
        );

        assert!(outcome.selected.is_none());
        assert!(outcome.backpressure.should_throttle);
    }

    #[test]
    fn backpressure_signals_throttle_when_few_eligible() {
        let mut candidates: Vec<TestCandidate> = (0..10)
            .map(|i| TestCandidate {
                id: format!("c{i}"),
                capacity: 100,
                healthy: i == 0,
            })
            .collect();
        candidates[0].healthy = true;

        let outcome = place(
            &candidates,
            |c| {
                if c.healthy {
                    ConstraintResult::Pass
                } else {
                    ConstraintResult::Fail("unhealthy".into())
                }
            },
            |_| 50.0,
            |_, _| 0.5,
            |c| &c.id,
        );

        assert!(outcome.backpressure.should_throttle);
        assert_eq!(outcome.backpressure.eligible_candidates, 1);
    }

    #[test]
    fn categorize_rejection_matches_keywords() {
        assert_eq!(categorize_rejection("host is unavailable"), "unavailable");
        assert_eq!(categorize_rejection("host is draining"), "draining");
        assert_eq!(
            categorize_rejection("insufficient capacity"),
            "insufficient_capacity"
        );
        assert_eq!(
            categorize_rejection("unsupported runtime"),
            "unsupported_runtime"
        );
        assert_eq!(
            categorize_rejection("pressure saturated"),
            "pressure_saturated"
        );
        assert_eq!(categorize_rejection("something else"), "other");
    }

    #[test]
    fn place_with_breakdown_scores_once_per_survivor() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct Breakdown {
            total: f64,
            headroom: f64,
        }

        let candidates = make_candidates();
        let filter_calls = AtomicUsize::new(0);
        let score_calls = AtomicUsize::new(0);

        let outcome = place_with_breakdown(
            &candidates,
            |c| {
                filter_calls.fetch_add(1, Ordering::SeqCst);
                if c.healthy {
                    ConstraintResult::Pass
                } else {
                    ConstraintResult::Fail("unhealthy".into())
                }
            },
            |c| {
                score_calls.fetch_add(1, Ordering::SeqCst);
                Breakdown {
                    total: c.capacity as f64,
                    headroom: c.capacity as f64 / 200.0,
                }
            },
            |_, b| b.headroom,
            |c| &c.id,
            |b| b.total,
        );

        // One filter per candidate, one score per survivor (2 healthy).
        assert_eq!(filter_calls.load(Ordering::SeqCst), 3);
        assert_eq!(score_calls.load(Ordering::SeqCst), 2);
        assert_eq!(outcome.scored.len(), 2);
        assert_eq!(outcome.selected.unwrap().id, "c1");
        // Breakdowns travel with the outcome; no rebuild needed.
        assert_eq!(outcome.scored[0].breakdown.total, 100.0);
    }
}
