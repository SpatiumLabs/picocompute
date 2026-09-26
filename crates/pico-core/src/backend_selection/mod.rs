//! Deterministic backend selection policy.
//!
//! Implements the selection rules from ADR-0004: ordered candidate evaluation
//! against hard selection gates with typed rejection reasons and explicit
//! fallback behavior. Backend choice is a control-plane policy decision
//! separated from scheduler scoring and adapter preference.

use hashbrown::HashMap;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, VariantNames};

use crate::cpu_isolation::CpuIsolationPolicy;
use crate::runtime::{BackendCapabilities, BackendHealth, RuntimeType};
use crate::tenant::Tenant;

/// Workload classification that determines the backend selection order.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    Display,
    EnumString,
    VariantNames,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum WorkloadClass {
    /// Internet-facing or cross-tenant code requiring hardware isolation.
    PublicUntrusted,
    /// Tenant-authorized lower-isolation workloads for gVisor compatibility.
    TrustedFastPath,
    /// Workloads requiring a broader VM device model or guest kernel behavior.
    CompatibilityVm,
    /// Deployment environment uses Kubernetes. This never lowers the
    /// isolation floor: selection uses the public-untrusted order and floor.
    /// Trusted tenants that want gVisor on a Kubernetes cell request
    /// `TrustedFastPath` explicitly.
    KubernetesIntegrated,
}

/// Required isolation boundary strength.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationFloor {
    /// Userspace application kernel with syscall mediation.
    Container = 1,
    /// KVM microVM with minimized device model.
    MicroVm = 2,
    /// KVM VM with a broad machine and device model.
    Vm = 3,
}

impl From<WorkloadClass> for IsolationFloor {
    fn from(class: WorkloadClass) -> Self {
        match class {
            WorkloadClass::PublicUntrusted | WorkloadClass::CompatibilityVm => {
                IsolationFloor::MicroVm
            }
            WorkloadClass::TrustedFastPath => IsolationFloor::Container,
            // Kubernetes is a deployment environment, not an isolation class:
            // it never lowers the floor. Trusted tenants that want gVisor on
            // a Kubernetes cell request `TrustedFastPath` explicitly.
            WorkloadClass::KubernetesIntegrated => IsolationFloor::MicroVm,
        }
    }
}

impl RuntimeType {
    /// Returns the isolation floor provided by this backend.
    #[must_use]
    pub fn isolation_floor(&self) -> IsolationFloor {
        match self {
            Self::Firecracker | Self::RemoteFirecracker => IsolationFloor::MicroVm,
            Self::Qemu => IsolationFloor::Vm,
            Self::GVisor => IsolationFloor::Container,
        }
    }
}

/// Hard selection gate from ADR-0004.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum BackendSelectionGate {
    /// The tenant is not allowed to use the backend or workload class.
    TenantPolicy,
    /// The backend does not meet or exceed the class's required isolation floor.
    IsolationFloor,
    /// The backend does not declare at least one required capability.
    Capabilities,
    /// Image metadata does not identify compatible artifacts for this backend.
    ImageCompatibility,
    /// Snapshot restore metadata does not match the backend family or version.
    SnapshotCompatibility,
    /// The backend does not provide an approved local transport.
    ProtocolCompatibility,
    /// The backend or its helpers are unhealthy or the host lacks capacity.
    HealthCapacity,
    /// The backend lacks a passing conformance result for the selected profile.
    ConformanceStatus,
    /// The host or cell does not support required CPU isolation (pinning or SMT exclusion).
    CpuIsolation,
    /// The target host or cell does not expose this backend.
    HostSupport,
}

/// Stable machine-readable reason code for a selection outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum SelectionReasonCode {
    /// The preferred backend passed every gate.
    PreferredBackendPassed,
    /// The preferred backend failed; a fallback passed every gate.
    FallbackBackendSelected,
    /// No backend passed the required gates.
    NoBackendAvailable,
}

/// Evidence describing a rejected backend candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedCandidate {
    /// The backend that was rejected.
    pub runtime: RuntimeType,
    /// Which gate it failed.
    pub gate: BackendSelectionGate,
    /// Human-readable rejection detail.
    pub reason: String,
}

/// The result of a backend selection decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendSelection {
    /// Workload class used for the decision.
    pub workload_class: WorkloadClass,
    /// Required isolation floor.
    pub isolation_floor: IsolationFloor,
    /// The selected backend, if one passed all gates.
    pub selected: Option<RuntimeType>,
    /// Zero-based fallback rank (0 = preferred).
    pub fallback_rank: u32,
    /// Stable reason code.
    pub reason_code: SelectionReasonCode,
    /// Required capability set at decision time.
    pub required_capabilities: BackendCapabilities,
    /// Candidates that were evaluated and rejected, ordered by preference.
    pub rejected_candidates: Vec<RejectedCandidate>,
    /// Tenant identifier used for the policy check.
    pub tenant_id: Option<String>,
    /// Policy epoch at decision time (from tenant config).
    pub policy_epoch: Option<u64>,
    /// When the decision was made (ISO 8601).
    pub decided_at: String,
}

/// Backend conformance status input to selection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConformanceStatus {
    /// True when the backend has a passing, non-expired conformance result.
    pub passing: bool,
    /// The specific workload profile that was tested.
    pub profile: Option<WorkloadClass>,
}

/// Image compatibility evidence for a backend.
///
/// ADR-0004 gate 4: signed image metadata identifies compatible kernel,
/// rootfs, firmware, architecture, and backend artifacts.
///
/// `compatible` is an attestation by the caller that owns the image evidence:
/// set it only after verifying the signed metadata against the backend.
/// The selection gate enforces presence of the attestation (fail closed on
/// omitted or negative evidence); it does not re-verify digests itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageCompatibility {
    /// True when the image is compatible with the backend.
    pub compatible: bool,
}

/// Snapshot compatibility evidence for a backend.
///
/// ADR-0004 gate 5: restore metadata matches the backend family, runtime
/// version policy, CPU template, device model, image digest, and guest
/// protocol requirements.
///
/// `compatible` is an attestation by the caller that owns the restore
/// evidence: set it only after verifying the snapshot lineage against the
/// backend. The selection gate enforces presence of the attestation; it
/// does not re-verify lineage itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotCompatibility {
    /// True when restore is compatible with the backend.
    pub compatible: bool,
}

/// Protocol compatibility evidence for a backend.
///
/// ADR-0004 gate 6: the backend provides an approved local transport
/// (vsock or Unix) and the image can negotiate all required
/// ADR-0003 capabilities.
///
/// `compatible` is an attestation by the caller that owns the transport
/// evidence: set it only for vsock or Unix transports. The selection gate
/// enforces presence of the attestation; it does not inspect the transport
/// itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolCompatibility {
    /// True when the backend transport and protocol are approved.
    pub compatible: bool,
}

/// Inputs consumed by the backend selection policy.
#[derive(Debug, Clone)]
pub struct SelectionInputs<'a> {
    /// Workload classification.
    pub workload_class: WorkloadClass,
    /// Tenant configuration including allowed runtimes and workload classes.
    pub tenant: &'a Tenant,
    /// Required capabilities for the requested sandbox.
    pub required_capabilities: &'a BackendCapabilities,
    /// Backends available on the target cell or host.
    pub available_backends: &'a [RuntimeType],
    /// Capability declarations per backend (from adapter registry or host inventory).
    pub backend_capabilities: &'a HashMap<RuntimeType, BackendCapabilities>,
    /// Optional conformance status per backend.
    pub conformance: Option<&'a HashMap<RuntimeType, ConformanceStatus>>,
    /// Optional health observations per backend on the target host.
    pub host_health: Option<&'a HashMap<RuntimeType, BackendHealth>>,
    /// Image compatibility per backend. `None` fails closed.
    pub image_compatibility: Option<&'a HashMap<RuntimeType, ImageCompatibility>>,
    /// Snapshot compatibility per backend. `None` fails closed.
    pub snapshot_compatibility: Option<&'a HashMap<RuntimeType, SnapshotCompatibility>>,
    /// Protocol compatibility per backend. `None` fails closed.
    pub protocol_compatibility: Option<&'a HashMap<RuntimeType, ProtocolCompatibility>>,
    /// CPU isolation policy configured on the target host or cell.
    /// When None, CPU isolation is not required (dedicated tenancy assumed).
    pub cpu_isolation_policy: Option<CpuIsolationPolicy>,
    /// Whether the placement targets a host with cross-tenant sandboxes.
    /// When true, CPU isolation is required for gVisor and recommended for microVMs.
    pub cross_tenant_host: bool,
}

/// Errors returned when backend selection cannot proceed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BackendSelectionError {
    /// No backend satisfied the required gates.
    #[error(
        "no backend satisfies requirements for class {class}: {rejected_count} candidates rejected"
    )]
    NoBackendAvailable {
        class: WorkloadClass,
        rejected_count: usize,
        rejected: Vec<RejectedCandidate>,
    },
    /// Tenant is not authorized for the requested workload class.
    #[error("tenant {tenant} is not authorized for workload class {class}")]
    UnauthorizedClass {
        tenant: String,
        class: WorkloadClass,
    },
}

impl From<BackendSelectionError> for crate::SandboxError {
    fn from(err: BackendSelectionError) -> Self {
        match err {
            BackendSelectionError::NoBackendAvailable {
                ref class,
                rejected_count,
                ref rejected,
            } => {
                let reasons: Vec<String> = rejected
                    .iter()
                    .map(|r| format!("{}: {}", r.gate, r.reason))
                    .collect();
                crate::SandboxError::BackendSelectionRejected {
                    class: class.to_string(),
                    rejected_count,
                    reasons,
                }
            }
            BackendSelectionError::UnauthorizedClass {
                ref tenant,
                ref class,
            } => crate::SandboxError::PolicyDenied {
                reason: format!("tenant {tenant} is not authorized for workload class {class}"),
            },
        }
    }
}

/// Deterministic backend selection policy from ADR-0004.
///
/// Evaluates ordered candidates against hard selection gates. Returns a
/// `BackendSelection` with the chosen backend or typed rejection evidence.
#[derive(Debug, Default, Clone)]
pub struct BackendSelectionPolicy;

impl BackendSelectionPolicy {
    /// Creates a new policy instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Evaluates backend candidates against all selection gates.
    ///
    /// Returns `BackendSelection` on success, or `BackendSelectionError` when
    /// no backend passes or the tenant is unauthorized for the workload class.
    pub fn evaluate(
        &self,
        inputs: &SelectionInputs<'_>,
    ) -> Result<BackendSelection, BackendSelectionError> {
        let isolation_floor = IsolationFloor::from(inputs.workload_class);

        if !inputs.tenant.is_authorized_for_class(inputs.workload_class) {
            return Err(BackendSelectionError::UnauthorizedClass {
                tenant: inputs.tenant.id.to_string(),
                class: inputs.workload_class,
            });
        }

        let candidates = self.ordered_candidates(inputs);
        let mut rejected = Vec::new();

        for (rank, candidate) in candidates.iter().enumerate() {
            if let Some(rejection) = self.check_tenant_policy(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_isolation_floor(candidate, isolation_floor) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_capabilities(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_image_compatibility(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_snapshot_compatibility(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_protocol_compatibility(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_host_support(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_health_capacity(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_cpu_isolation(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }
            if let Some(rejection) = self.check_conformance_status(candidate, inputs) {
                rejected.push(rejection);
                continue;
            }

            // All gates passed for this candidate.
            let reason_code = if rank == 0 {
                SelectionReasonCode::PreferredBackendPassed
            } else {
                SelectionReasonCode::FallbackBackendSelected
            };

            return Ok(BackendSelection {
                workload_class: inputs.workload_class,
                isolation_floor,
                selected: Some(*candidate),
                fallback_rank: rank as u32,
                reason_code,
                required_capabilities: inputs.required_capabilities.clone(),
                rejected_candidates: rejected,
                tenant_id: Some(inputs.tenant.id.to_string()),
                policy_epoch: inputs.tenant.policy_epoch,
                decided_at: crate::types::now_iso(),
            });
        }

        Err(BackendSelectionError::NoBackendAvailable {
            class: inputs.workload_class,
            rejected_count: rejected.len(),
            rejected,
        })
    }

    /// Gate: Backend must be present on the target host or cell.
    fn check_host_support(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        if inputs.available_backends.contains(candidate) {
            None
        } else {
            Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::HostSupport,
                reason: format!("backend {candidate} is not available on the target host"),
            })
        }
    }

    /// Gate 1: Backend must be in tenant's allowed runtimes.
    fn check_tenant_policy(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        if !inputs.tenant.allowed_runtimes.contains(candidate) {
            Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::TenantPolicy,
                reason: format!("backend {candidate} is not in tenant allowed_runtimes"),
            })
        } else {
            None
        }
    }

    /// Gate 2: Backend isolation floor must meet or exceed the required boundary.
    fn check_isolation_floor(
        &self,
        candidate: &RuntimeType,
        required: IsolationFloor,
    ) -> Option<RejectedCandidate> {
        let floor = candidate.isolation_floor();
        if floor < required {
            Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::IsolationFloor,
                reason: format!(
                    "backend {candidate} isolation floor {floor:?} is below required {required:?}"
                ),
            })
        } else {
            None
        }
    }

    /// Gate 3: Backend must declare every required capability.
    fn check_capabilities(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        match inputs.backend_capabilities.get(candidate) {
            Some(caps) if caps.supports_all(inputs.required_capabilities) => None,
            Some(caps) => {
                let missing = caps.missing(inputs.required_capabilities);
                Some(RejectedCandidate {
                    runtime: *candidate,
                    gate: BackendSelectionGate::Capabilities,
                    reason: format!(
                        "backend {candidate} is missing required capabilities: {missing:?}"
                    ),
                })
            }
            None => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::Capabilities,
                reason: format!("backend {candidate} has no capability metadata registered"),
            }),
        }
    }

    /// Gate 4: Image metadata must identify compatible artifacts.
    ///
    /// Omitting `image_compatibility` fails closed. A missing entry or
    /// `compatible=false` for a candidate is also a rejection.
    fn check_image_compatibility(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        let Some(map) = inputs.image_compatibility else {
            return Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ImageCompatibility,
                reason: format!(
                    "backend {candidate} has no image compatibility evidence; image gate is mandatory"
                ),
            });
        };
        match map.get(candidate) {
            Some(status) if status.compatible => None,
            Some(_) => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ImageCompatibility,
                reason: format!("backend {candidate} image is not compatible"),
            }),
            None => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ImageCompatibility,
                reason: format!("backend {candidate} has no image compatibility evidence"),
            }),
        }
    }

    /// Gate 5: Snapshot restore metadata must match the backend.
    ///
    /// Omitting `snapshot_compatibility` fails closed.
    fn check_snapshot_compatibility(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        let Some(map) = inputs.snapshot_compatibility else {
            return Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::SnapshotCompatibility,
                reason: format!(
                    "backend {candidate} has no snapshot compatibility evidence; snapshot gate is mandatory"
                ),
            });
        };
        match map.get(candidate) {
            Some(status) if status.compatible => None,
            Some(_) => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::SnapshotCompatibility,
                reason: format!("backend {candidate} snapshot is not compatible"),
            }),
            None => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::SnapshotCompatibility,
                reason: format!("backend {candidate} has no snapshot compatibility evidence"),
            }),
        }
    }

    /// Gate 6: Backend must provide an approved local transport.
    ///
    /// Omitting `protocol_compatibility` fails closed. Approved transports
    /// are vsock and Unix; TCP is never approved for production.
    fn check_protocol_compatibility(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        let Some(map) = inputs.protocol_compatibility else {
            return Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ProtocolCompatibility,
                reason: format!(
                    "backend {candidate} has no protocol compatibility evidence; protocol gate is mandatory"
                ),
            });
        };
        match map.get(candidate) {
            Some(status) if status.compatible => None,
            Some(_) => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ProtocolCompatibility,
                reason: format!("backend {candidate} protocol transport is not approved"),
            }),
            None => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ProtocolCompatibility,
                reason: format!("backend {candidate} has no protocol compatibility evidence"),
            }),
        }
    }

    /// Backend must be healthy and host must have capacity.
    ///
    /// Omitting `host_health` fails closed. A missing observation for a
    /// candidate is also a rejection; health is never advisory.
    fn check_health_capacity(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        let Some(health_map) = inputs.host_health else {
            return Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::HealthCapacity,
                reason: format!(
                    "backend {candidate} has no host health observation; health gate is mandatory"
                ),
            });
        };
        use crate::runtime::BackendHealthStatus;
        match health_map.get(candidate) {
            Some(health) if matches!(health.status, BackendHealthStatus::Unavailable) => {
                Some(RejectedCandidate {
                    runtime: *candidate,
                    gate: BackendSelectionGate::HealthCapacity,
                    reason: format!("backend {candidate} is unhealthy: {:?}", health.message),
                })
            }
            Some(_) => None,
            None => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::HealthCapacity,
                reason: format!("backend {candidate} has no host health observation"),
            }),
        }
    }

    /// Gate: CPU isolation must be satisfied for cross-tenant placement.
    ///
    /// - gVisor must never be used for cross-tenant placement without CPU pinning
    ///   and SMT sibling exclusion (per RR-06c accepted-risk register).
    /// - MicroVM backends (Firecracker, QEMU) require at least dedicated-core
    ///   pinning on cross-tenant hosts (per RR-06a).
    /// - On non-cross-tenant hosts, this gate always passes.
    fn check_cpu_isolation(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        if !inputs.cross_tenant_host {
            return None;
        }

        let Some(policy) = inputs.cpu_isolation_policy else {
            return Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::CpuIsolation,
                reason: format!(
                    "backend {candidate} cannot be placed on a cross-tenant host without a CPU isolation policy"
                ),
            });
        };

        // gVisor: must have CPU pinning and SMT exclusion on cross-tenant hosts
        if *candidate == RuntimeType::GVisor {
            if !policy.requires_smt_exclusion() {
                return Some(RejectedCandidate {
                    runtime: *candidate,
                    gate: BackendSelectionGate::CpuIsolation,
                    reason: format!(
                        "gVisor cross-tenant placement requires CPU pinning with SMT sibling exclusion (policy is {policy:?})"
                    ),
                });
            }
            return None;
        }

        // MicroVM backends: require at least dedicated-core pinning on cross-tenant hosts
        if candidate.is_vm_boundary() {
            if !policy.requires_pinning() {
                return Some(RejectedCandidate {
                    runtime: *candidate,
                    gate: BackendSelectionGate::CpuIsolation,
                    reason: format!(
                        "MicroVM backend {candidate} requires CPU pinning on cross-tenant hosts (policy is {policy:?})"
                    ),
                });
            }
            return None;
        }

        None
    }

    /// Backend must have a passing conformance result.
    ///
    /// Omitting `conformance` fails closed. A missing record for a candidate
    /// is also a rejection; conformance is never advisory.
    fn check_conformance_status(
        &self,
        candidate: &RuntimeType,
        inputs: &SelectionInputs<'_>,
    ) -> Option<RejectedCandidate> {
        let Some(conf_map) = inputs.conformance else {
            return Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ConformanceStatus,
                reason: format!(
                    "backend {candidate} has no conformance record; conformance gate is mandatory"
                ),
            });
        };
        match conf_map.get(candidate) {
            Some(conf) if conf.passing => None,
            Some(_) => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ConformanceStatus,
                reason: format!("backend {candidate} does not have a passing conformance result"),
            }),
            None => Some(RejectedCandidate {
                runtime: *candidate,
                gate: BackendSelectionGate::ConformanceStatus,
                reason: format!("backend {candidate} has no conformance record"),
            }),
        }
    }

    /// Returns the ordered candidate list for a workload class.
    ///
    /// Order follows ADR-0004 §Workload Classes and Backend Order:
    /// - PublicUntrusted: Firecracker, QEMU (never gVisor)
    /// - TrustedFastPath: gVisor, Firecracker, QEMU
    /// - CompatibilityVm: QEMU only
    /// - KubernetesIntegrated: Firecracker, QEMU (never gVisor; the class
    ///   never lowers the floor, so a held trusted grant must not admit a
    ///   Container backend here. Trusted tenants that want gVisor on a
    ///   Kubernetes cell request `TrustedFastPath` explicitly.)
    fn ordered_candidates(&self, inputs: &SelectionInputs<'_>) -> Vec<RuntimeType> {
        match inputs.workload_class {
            WorkloadClass::PublicUntrusted | WorkloadClass::KubernetesIntegrated => {
                vec![RuntimeType::Firecracker, RuntimeType::Qemu]
            }
            WorkloadClass::TrustedFastPath => {
                vec![
                    RuntimeType::GVisor,
                    RuntimeType::Firecracker,
                    RuntimeType::Qemu,
                ]
            }
            WorkloadClass::CompatibilityVm => {
                vec![RuntimeType::Qemu]
            }
        }
    }
}

#[cfg(test)]
mod tests;
