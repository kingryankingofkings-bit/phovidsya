#![no_std]

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResourceClass {
    QuarantineMemory = 0,
    Storage = 1,
    DmaDevice = 2,
    Network = 3,
    Secret = 4,
    Recovery = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorPolicy {
    pub schema_major: u16,
    pub monitor_generation: u64,
    pub policy_epoch: u64,
    pub main_kernel_digest: Digest,
    pub direct_device_passthrough_denied: bool,
    pub iommu_owned_by_monitor: bool,
    pub quarantine_region_isolated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainKernelRequest {
    pub request_id: u128,
    pub kernel_digest: Digest,
    pub subject_id: u128,
    pub resource: ResourceClass,
    pub capability_id: u128,
    pub input_digest: Digest,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub deadline_monotonic_ns: u64,
    pub requests_direct_hardware: bool,
    pub input_was_quarantined: bool,
    pub validator_receipt_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorContext {
    pub now_monotonic_ns: u64,
    pub last_sequence: u64,
    pub capability_bound_to_subject: bool,
    pub device_owned_by_monitor: bool,
    pub sanitized_view_immutable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorError {
    UnsupportedSchema,
    MissingIdentity,
    ZeroDigest,
    UnrecognizedKernel,
    StalePolicy,
    Replay,
    Expired,
    SubjectCapabilityMismatch,
    DirectHardwareDenied,
    MonitorDoesNotOwnDevice,
    IommuNotOwned,
    QuarantineBypass,
    MutableSanitizedView,
}

pub fn admit(
    policy: &MonitorPolicy,
    request: &MainKernelRequest,
    context: &MonitorContext,
) -> Result<(), MonitorError> {
    if policy.schema_major != 1 { return Err(MonitorError::UnsupportedSchema); }
    if request.request_id == 0 || request.subject_id == 0 || request.capability_id == 0 {
        return Err(MonitorError::MissingIdentity);
    }
    for digest in [request.kernel_digest, request.input_digest, request.validator_receipt_digest] {
        if digest.iter().all(|byte| *byte == 0) { return Err(MonitorError::ZeroDigest); }
    }
    if request.kernel_digest != policy.main_kernel_digest { return Err(MonitorError::UnrecognizedKernel); }
    if request.policy_epoch != policy.policy_epoch { return Err(MonitorError::StalePolicy); }
    if request.sequence == 0 || request.sequence <= context.last_sequence { return Err(MonitorError::Replay); }
    if request.deadline_monotonic_ns < context.now_monotonic_ns { return Err(MonitorError::Expired); }
    if !context.capability_bound_to_subject { return Err(MonitorError::SubjectCapabilityMismatch); }
    if request.requests_direct_hardware || !policy.direct_device_passthrough_denied {
        return Err(MonitorError::DirectHardwareDenied);
    }
    if matches!(request.resource, ResourceClass::Storage | ResourceClass::DmaDevice) {
        if !context.device_owned_by_monitor { return Err(MonitorError::MonitorDoesNotOwnDevice); }
        if !policy.iommu_owned_by_monitor { return Err(MonitorError::IommuNotOwned); }
    }
    if !request.input_was_quarantined || !policy.quarantine_region_isolated {
        return Err(MonitorError::QuarantineBypass);
    }
    if !context.sanitized_view_immutable { return Err(MonitorError::MutableSanitizedView); }
    Ok(())
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> MonitorPolicy {
        MonitorPolicy { schema_major: 1, monitor_generation: 2, policy_epoch: 3,
            main_kernel_digest: [1; 32], direct_device_passthrough_denied: true,
            iommu_owned_by_monitor: true, quarantine_region_isolated: true }
    }
    fn request() -> MainKernelRequest {
        MainKernelRequest { request_id: 1, kernel_digest: [1; 32], subject_id: 2,
            resource: ResourceClass::Storage, capability_id: 3, input_digest: [2; 32],
            policy_epoch: 3, sequence: 5, deadline_monotonic_ns: 20,
            requests_direct_hardware: false, input_was_quarantined: true,
            validator_receipt_digest: [3; 32] }
    }
    fn context() -> MonitorContext {
        MonitorContext { now_monotonic_ns: 10, last_sequence: 4,
            capability_bound_to_subject: true, device_owned_by_monitor: true,
            sanitized_view_immutable: true }
    }
    #[test]
    fn mediated_request_passes() { assert_eq!(admit(&policy(), &request(), &context()), Ok(())); }
    #[test]
    fn direct_hardware_denied() {
        let mut r = request(); r.requests_direct_hardware = true;
        assert_eq!(admit(&policy(), &r, &context()), Err(MonitorError::DirectHardwareDenied));
    }
    #[test]
    fn monitor_must_own_device() {
        let mut c = context(); c.device_owned_by_monitor = false;
        assert_eq!(admit(&policy(), &request(), &c), Err(MonitorError::MonitorDoesNotOwnDevice));
    }
    #[test]
    fn quarantine_cannot_be_bypassed() {
        let mut r = request(); r.input_was_quarantined = false;
        assert_eq!(admit(&policy(), &r, &context()), Err(MonitorError::QuarantineBypass));
    }
    #[test]
    fn replay_rejects() {
        let mut r = request(); r.sequence = 4;
        assert_eq!(admit(&policy(), &r, &context()), Err(MonitorError::Replay));
    }
}
