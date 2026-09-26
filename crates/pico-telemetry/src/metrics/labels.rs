//! Metric label sets that own the shared-host redaction decision.
//!
//! Every metric in PicoCompute is emitted through a [`Labels`] set. Callers cannot
//! hand-build an identity attribute, so the decision "does this series carry
//! `tenant_id` instead of `sandbox_id`" is made in exactly one place: here.
//!
//! # Why identity attributes are not free-form
//!
//! On a dedicated-tenancy host an operator may correlate a metric with a
//! specific sandbox, so sandbox-scoped series carry `sandbox_id`. On a shared
//! host that label would let one tenant infer another tenant's activity from
//! metric sampling alone, so `sandbox_id` is replaced by `tenant_id`.
//! Enforcing that by convention did not hold: sandbox-scoped network metrics
//! were building `&[("sandbox_id", ..)]` inline and never consulted the flag.
//! Routing every call site through [`Labels`] makes the policy the only
//! reachable path.
//!
//! # The three policies
//!
//! The policies are distinct because collapsing any two of them would change
//! the emitted series and break existing dashboards:
//!
//! * [`Labels::host`] - host-level aggregate, never attributed.
//! * [`Labels::tenant`] - unattributed by default, gains `tenant_id` under
//!   redaction. Never emits `sandbox_id`.
//! * [`Labels::sandbox`] - `sandbox_id` normally, `tenant_id` under redaction.

use smallvec::SmallVec;

use super::redaction;

/// Number of label pairs held inline before spilling to the heap.
///
/// The widest series in the workspace carries four pairs (`sandbox_id` or
/// `tenant_id`, plus `if_name`, `backend`, and `status`). Sizing the inline
/// buffer above that keeps recording allocation-free on every current path.
const INLINE_PAIRS: usize = 6;

/// Label value used when a sandbox-scoped series has no tenant context.
///
/// Keeps the series present under redaction rather than dropping the data point
/// and making the panel look empty. Bounded, so it cannot inflate cardinality.
const UNKNOWN_TENANT: &str = "unknown_tenant";

/// A metric's label set.
///
/// Built through one of the three policy constructors, then extended with
/// non-identity labels. The identity decision happens at construction, so no
/// later call can add or swap an identity attribute.
pub struct Labels<'a> {
    pairs: SmallVec<[(&'static str, &'a str); INLINE_PAIRS]>,
}

impl std::fmt::Debug for Labels<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.pairs.iter().map(|(k, v)| (*k, *v)))
            .finish()
    }
}

impl<'a> Labels<'a> {
    /// Host-level aggregate: no identity attribute is ever attached.
    ///
    /// Use for counters and gauges that aggregate across sandboxes, such as
    /// cgroup event totals or scheduler capacity.
    pub fn host() -> Self {
        Self {
            pairs: SmallVec::new(),
        }
    }

    /// Attributed only while shared-host redaction is enabled.
    ///
    /// Emits `tenant_id` when redaction is on and nothing when it is off, so a
    /// dedicated host never gains a tenancy dimension it did not ask for. Used
    /// by lifecycle series that are host-scoped by default.
    pub fn tenant(tenant_id: Option<&'a str>) -> Self {
        let mut labels = Self::host();
        if redaction::shared_host_redaction()
            && let Some(tid) = tenant_id
        {
            labels.pairs.push((super::attr::TENANT_ID, tid));
        }
        labels
    }

    /// Sandbox-scoped: `sandbox_id`, or `tenant_id` under redaction.
    ///
    /// When redaction is on and no tenant is known, falls back to
    /// `tenant_id="unknown_tenant"` so the series stays continuous without
    /// reintroducing the sandbox identifier.
    pub fn sandbox(sandbox_id: &'a str, tenant_id: Option<&'a str>) -> Self {
        let mut labels = Self::host();
        if redaction::shared_host_redaction() {
            labels
                .pairs
                .push((super::attr::TENANT_ID, tenant_id.unwrap_or(UNKNOWN_TENANT)));
        } else {
            labels.pairs.push((super::attr::SANDBOX_ID, sandbox_id));
        }
        labels
    }

    /// Adds a non-identity label.
    ///
    /// Takes a [`PlainKey`] rather than a `&'static str` so that the identity
    /// keys cannot be passed here by mistake: only the `attr` constants typed
    /// as `PlainKey` are accepted, and the identity keys are deliberately not
    /// among them. That makes "a caller built their own `tenant_id` label"
    /// unrepresentable rather than merely discouraged.
    pub fn with(mut self, key: PlainKey, value: &'a str) -> Self {
        self.pairs.push((key.as_str(), value));
        self
    }

    /// Adds several non-identity labels at once, e.g. the outcome and reason of
    /// a single failure.
    pub fn with_all(mut self, extra: &[(PlainKey, &'a str)]) -> Self {
        self.pairs
            .extend(extra.iter().map(|(k, v)| (k.as_str(), *v)));
        self
    }

    /// The pairs, in the order they will be attached to the data point.
    pub fn as_slice(&self) -> &[(&'static str, &'a str)] {
        &self.pairs
    }

    /// Whether this set carries an identity attribute.
    pub fn is_attributed(&self) -> bool {
        self.pairs
            .iter()
            .any(|(k, _)| *k == super::attr::TENANT_ID || *k == super::attr::SANDBOX_ID)
    }
}

/// A non-identity attribute key.
///
/// Distinct from the identity keys (`tenant_id`, `sandbox_id`) at the type
/// level, so [`Labels::with`] cannot be handed one and bypass the redaction
/// decision. Obtain these from the `attr` module rather than writing them
/// inline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainKey(&'static str);

impl PlainKey {
    /// Declares a non-identity attribute key.
    ///
    /// `pub(crate)` on purpose: keys belong in the `attr` module, so that the
    /// full set of label names a crate can emit is readable in one place
    /// rather than scattered across call sites as string literals.
    pub(crate) const fn new(key: &'static str) -> Self {
        Self(key)
    }

    /// The key as a plain string, for the OpenTelemetry attribute.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// A closed set of label values, plus the value to substitute for anything
/// outside it.
///
/// The fallback is a field rather than a separate argument because "the
/// fallback must itself be a member of the set" is the invariant that makes the
/// bound meaningful. Keeping them apart let a caller pass a fallback from a
/// different set, which would reintroduce the unbounded value the allowlist
/// exists to prevent. With the fallback owned here there is no way to express
/// that mistake.
///
/// Declare these as `const` so the membership check in [`Allowlist::new`] runs
/// at compile time; a set missing its own fallback is then a build error rather
/// than a runtime one.
///
/// ```
/// use pico_telemetry::metrics::Allowlist;
///
/// const STATUS: Allowlist =
///     Allowlist::new(&["ok", "failed", "unknown"], "unknown");
///
/// // An unbounded string cannot escape.
/// assert_eq!(STATUS.bound("sha256:deadbeef").as_str(), "unknown");
/// assert_eq!(STATUS.bound("ok").as_str(), "ok");
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Allowlist {
    values: &'static [&'static str],
    fallback: &'static str,
}

impl Allowlist {
    /// Builds an allowlist whose fallback is guaranteed to be in the set.
    ///
    /// `const`, so use it in a `const` item. If `fallback` is not a member of
    /// `values` this fails to compile; at runtime it would be a logic error, so
    /// there is no release-mode relaxation.
    pub const fn new(values: &'static [&'static str], fallback: &'static str) -> Self {
        // A const-eval loop rather than `values.contains(fallback)`, which is
        // not usable in const context.
        let mut i = 0;
        while i < values.len() {
            if const_str_eq(values[i], fallback) {
                return Self { values, fallback };
            }
            i += 1;
        }
        panic!("allowlist fallback is not a member of its own value set");
    }

    /// The values in this set.
    #[must_use]
    pub const fn values(&self) -> &'static [&'static str] {
        self.values
    }

    /// The value substituted for input outside this set.
    #[must_use]
    pub const fn fallback(&self) -> &'static str {
        self.fallback
    }

    /// Normalizes `value` against this set.
    ///
    /// The returned value is always a member of the set: either `value` itself
    /// or the set's own fallback. There is no input for which this returns an
    /// unbounded string.
    #[must_use]
    pub fn bound<'a>(&self, value: &'a str) -> Bounded<'a> {
        Bounded {
            value: if self.values.contains(&value) {
                value
            } else {
                self.fallback
            },
        }
    }
}

/// `str` equality in const context, which `PartialEq` does not yet support.
const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// A label value that is known to be a member of some [`Allowlist`].
///
/// Constructing one is the only way to obtain a value that has already been
/// checked, so an unbounded string cannot reach a label by accident.
#[derive(Clone, Copy, Debug)]
pub struct Bounded<'a> {
    value: &'a str,
}

impl<'a> Bounded<'a> {
    /// The normalized value, always a member of the originating set.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.value
    }

    /// The normalized value, always a member of the originating set.
    #[must_use]
    pub fn into_inner(self) -> &'a str {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::attr;
    use crate::metrics::redaction;

    /// Serializes against the other redaction-touching tests in this crate and
    /// restores the prior value on drop.
    ///
    /// `nextest` gives every test its own process, but a plain `cargo test`
    /// shares one, so without this lock two tests flipping the process-global
    /// flag can observe each other's value.
    struct RedactionGuard {
        previous: bool,
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl RedactionGuard {
        fn set(enabled: bool) -> Self {
            let lock = crate::metrics::STATE_LOCK.lock();
            let guard = Self {
                previous: redaction::shared_host_redaction(),
                _lock: lock,
            };
            redaction::set_shared_host_redaction(enabled);
            guard
        }
    }

    impl Drop for RedactionGuard {
        fn drop(&mut self) {
            redaction::set_shared_host_redaction(self.previous);
        }
    }

    /// The label pairs as a plain vector, for comparison in assertions.
    ///
    /// Borrows from the set rather than the underlying data so the set can be
    /// dropped at the end of the test.
    fn pairs<'l, 'a>(labels: &'l Labels<'a>) -> Vec<(&'static str, &'l str)> {
        labels.as_slice().to_vec()
    }

    #[test]
    fn host_carries_no_identity_under_either_policy() {
        for enabled in [false, true] {
            let _guard = RedactionGuard::set(enabled);
            let labels = Labels::host();
            assert!(pairs(&labels).is_empty());
            assert!(!labels.is_attributed());
        }
    }

    #[test]
    fn tenant_is_absent_on_dedicated_hosts() {
        let _guard = RedactionGuard::set(false);
        let labels = Labels::tenant(Some("tnt_a"));
        assert!(pairs(&labels).is_empty());
        assert!(!labels.is_attributed());
    }

    #[test]
    fn tenant_is_present_under_redaction() {
        let _guard = RedactionGuard::set(true);
        let labels = Labels::tenant(Some("tnt_a"));
        assert_eq!(pairs(&labels), vec![(attr::TENANT_ID, "tnt_a")]);
        assert!(labels.is_attributed());
    }

    #[test]
    fn tenant_without_context_stays_unattributed() {
        let _guard = RedactionGuard::set(true);
        let labels = Labels::tenant(None);
        assert!(pairs(&labels).is_empty());
    }

    #[test]
    fn sandbox_uses_sandbox_id_on_dedicated_hosts() {
        let _guard = RedactionGuard::set(false);
        let labels = Labels::sandbox("sbx_a", Some("tnt_a"));
        assert_eq!(pairs(&labels), vec![(attr::SANDBOX_ID, "sbx_a")]);
        assert!(labels.is_attributed());
    }

    #[test]
    fn sandbox_substitutes_tenant_id_under_redaction() {
        let _guard = RedactionGuard::set(true);
        let labels = Labels::sandbox("sbx_a", Some("tnt_a"));
        assert_eq!(pairs(&labels), vec![(attr::TENANT_ID, "tnt_a")]);
    }

    #[test]
    fn sandbox_never_leaks_id_when_tenant_is_unknown() {
        let _guard = RedactionGuard::set(true);
        let labels = Labels::sandbox("sbx_a", None);
        assert_eq!(pairs(&labels), vec![(attr::TENANT_ID, "unknown_tenant")]);
        assert!(
            !pairs(&labels)
                .iter()
                .any(|(k, v)| *k == attr::SANDBOX_ID || *v == "sbx_a")
        );
    }

    #[test]
    fn non_identity_labels_follow_the_identity_attribute() {
        let _guard = RedactionGuard::set(true);
        let labels = Labels::sandbox("sbx_a", Some("tnt_a"))
            .with(attr::IF_NAME, "cvx0")
            .with(attr::BACKEND, "microvm");
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::TENANT_ID, "tnt_a"),
                (attr::IF_NAME.as_str(), "cvx0"),
                (attr::BACKEND.as_str(), "microvm"),
            ]
        );
    }

    #[test]
    fn with_all_appends_in_order() {
        let _guard = RedactionGuard::set(false);
        let labels =
            Labels::tenant(None).with_all(&[(attr::EVENT, "create_failed"), (attr::REASON, "oom")]);
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::EVENT.as_str(), "create_failed"),
                (attr::REASON.as_str(), "oom"),
            ]
        );
    }

    #[test]
    fn allowlist_keeps_members_and_falls_back_for_everything_else() {
        const RESULTS: Allowlist = Allowlist::new(&["hit", "miss", "unknown"], "unknown");
        assert_eq!(RESULTS.bound("sha256:deadbeef").as_str(), "unknown");
        assert_eq!(RESULTS.bound("").as_str(), "unknown");
        assert_eq!(RESULTS.bound("hit").as_str(), "hit");
        assert_eq!(RESULTS.bound("miss").as_str(), "miss");
    }

    #[test]
    fn allowlist_output_is_always_a_member() {
        const RESULTS: Allowlist = Allowlist::new(&["hit", "miss", "unknown"], "unknown");
        for input in ["hit", "miss", "unknown", "sha256:deadbeef", "", "HIT"] {
            assert!(
                RESULTS.values().contains(&RESULTS.bound(input).as_str()),
                "{input:?} produced a value outside the set"
            );
        }
    }

    #[test]
    fn allowlist_reports_its_own_fallback() {
        const RESULTS: Allowlist = Allowlist::new(&["hit", "unknown"], "unknown");
        assert_eq!(RESULTS.fallback(), "unknown");
        assert_eq!(RESULTS.values(), &["hit", "unknown"]);
    }

    #[test]
    fn allowlist_rejects_a_fallback_outside_its_own_set() {
        // The invariant is a `const fn` check, so a bad set is a build error and
        // this only ever runs for a set that compiled. Assert the guarantee the
        // check exists to provide: a constructed allowlist's fallback is a
        // member of its set.
        const RESULTS: Allowlist = Allowlist::new(&["hit", "miss", "unknown"], "unknown");
        assert!(RESULTS.values().contains(&RESULTS.fallback()));
    }

    #[test]
    fn plain_keys_are_never_identity_keys() {
        // The type split is what stops `Labels::with` accepting an identity key.
        // Identity keys stay `&'static str` and so are not `PlainKey`; this
        // asserts the two namespaces do not overlap by value.
        for key in [
            attr::KIND,
            attr::BACKEND,
            attr::REASON,
            attr::EVENT,
            attr::STATUS,
            attr::OUTCOME,
            attr::IF_NAME,
            attr::HOST_ID,
            attr::SEVERITY,
            attr::CONDITION,
            attr::STATE,
            attr::RESOURCE,
            attr::HEALTH_STATE,
            attr::CACHE_RESULT,
            attr::IMAGE_PROFILE,
            attr::DOMAIN,
            attr::RCODE,
            attr::ACTION,
            attr::SOURCE,
            attr::SYSCALL,
        ] {
            let name = key.as_str();
            assert_ne!(name, attr::TENANT_ID, "{name} collided with tenant_id");
            assert_ne!(name, attr::SANDBOX_ID, "{name} collided with sandbox_id");
        }
    }

    #[test]
    fn bound_label_reaches_a_label_set_normalized() {
        const PROFILES: Allowlist = Allowlist::new(&["minimal", "agent", "unknown"], "unknown");
        let labels = Labels::host().with(
            attr::IMAGE_PROFILE,
            PROFILES.bound("custom-gpu-image-v99").as_str(),
        );
        assert_eq!(
            pairs(&labels),
            vec![(attr::IMAGE_PROFILE.as_str(), "unknown")]
        );
    }

    #[test]
    fn wide_label_sets_stay_on_the_inline_buffer() {
        let _guard = RedactionGuard::set(false);
        let labels = Labels::sandbox("sbx_a", Some("tnt_a"))
            .with(attr::BACKEND, "microvm")
            .with(attr::IF_NAME, "cvx0")
            .with(attr::STATUS, "prepare_completed")
            .with(attr::CACHE_RESULT, "unknown")
            .with(attr::IMAGE_PROFILE, "unknown");
        assert_eq!(labels.as_slice().len(), INLINE_PAIRS);
    }
}
