#![no_std]

//! Allocation-free authority admission contract.
//!
//! Authentication is deliberately supplied by a trusted supervisor through
//! [`BindingVerifier`]. The verifier receives a canonical preimage containing
//! every security-relevant claim; a request-side boolean can never stand in
//! for a capability grant or an approval receipt.
//!
//! The mutable context serializes and consumes sequences in one supervisor
//! instance. Crash/reboot replay resistance additionally requires that the
//! supervisor restore and checkpoint this sequence from its durable ledger.

pub type Digest = [u8; 32];

pub const SCHEMA_MAJOR: u16 = 2;
pub const SCHEMA_MINOR: u16 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DataTrust {
    TrustedSystem = 0,
    UserSupplied = 1,
    RemoteUntrusted = 2,
    ModelGenerated = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorityClass {
    ReadData = 0,
    WriteData = 1,
    Network = 2,
    Secret = 3,
    Device = 4,
    Execute = 5,
    Authorize = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeClass {
    Monotonic,
    WallUntrusted,
    UpdateTrusted { uncertainty_ns: u64 },
    TokenExpiryTrusted { uncertainty_ns: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembraneRequest {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub request_id: u128,
    pub request_sequence: u64,
    pub subject_id: u128,
    pub resource_id: u128,
    pub input_digest: Digest,
    pub source: DataTrust,
    pub requested: AuthorityClass,
    pub capability_id: u128,
    pub policy_generation: u64,
    pub deadline_monotonic_ns: u64,
    /// Untrusted annotation retained for telemetry only. It is never consulted
    /// by admission and is intentionally absent from signed authority claims.
    pub server_claims_safe: bool,
}

/// Exact request-scoped claims authenticated by the capability issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub issuer_id: u128,
    pub capability_id: u128,
    pub request_id: u128,
    pub request_sequence: u64,
    pub subject_id: u128,
    pub resource_id: u128,
    pub source: DataTrust,
    pub requested: AuthorityClass,
    pub input_digest: Digest,
    pub policy_generation: u64,
    pub issued_at_monotonic_ns: u64,
    pub not_before_monotonic_ns: u64,
    pub expires_at_monotonic_ns: u64,
    pub request_deadline_monotonic_ns: u64,
    /// Digest or MAC handle for detached authentication evidence. A nonzero
    /// value is not sufficient: [`BindingVerifier`] must authenticate it.
    pub authentication_evidence_digest: Digest,
}

/// Exact request-and-capability-scoped approval issued by a supervisor that is
/// independent of the requesting subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorApprovalReceipt {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub approval_id: u128,
    pub supervisor_id: u128,
    pub request_id: u128,
    pub request_sequence: u64,
    pub subject_id: u128,
    pub resource_id: u128,
    pub source: DataTrust,
    pub requested: AuthorityClass,
    pub capability_id: u128,
    pub capability_issuer_id: u128,
    pub capability_authentication_evidence_digest: Digest,
    pub input_digest: Digest,
    pub policy_generation: u64,
    pub approved_at_monotonic_ns: u64,
    pub expires_at_monotonic_ns: u64,
    pub request_deadline_monotonic_ns: u64,
    /// Digest or MAC handle for detached authentication evidence. A nonzero
    /// value is not sufficient: [`BindingVerifier`] must authenticate it.
    pub authentication_evidence_digest: Digest,
}

#[derive(Debug, Eq, PartialEq)]
pub struct MembraneContext {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub now_monotonic_ns: u64,
    pub current_policy_generation: u64,
    /// Issuers selected by trusted policy, never copied from the request.
    pub trusted_capability_issuer_id: u128,
    pub trusted_supervisor_id: u128,
    /// Highest sequence restored from, or pending checkpoint to, the trusted
    /// replay ledger for this subject and policy stream.
    pub last_accepted_request_sequence: u64,
    pub direct_privileged_path_absent: bool,
    pub credentials_shared_with_server: bool,
}

/// Downstream consumers receive this exact validated authority, not the raw
/// request, grant, or approval.
#[must_use = "validated authority must be consumed by the privileged operation"]
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedAdmission {
    request_id: u128,
    request_sequence: u64,
    subject_id: u128,
    resource_id: u128,
    input_digest: Digest,
    source: DataTrust,
    requested: AuthorityClass,
    capability_id: u128,
    capability_issuer_id: u128,
    capability_authentication_evidence_digest: Digest,
    approval_id: u128,
    approval_authentication_evidence_digest: Digest,
    policy_generation: u64,
    admitted_at_monotonic_ns: u64,
    deadline_monotonic_ns: u64,
}

impl ValidatedAdmission {
    pub const fn request_id(&self) -> u128 {
        self.request_id
    }
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }
    pub const fn subject_id(&self) -> u128 {
        self.subject_id
    }
    pub const fn resource_id(&self) -> u128 {
        self.resource_id
    }
    pub const fn input_digest(&self) -> Digest {
        self.input_digest
    }
    pub const fn source(&self) -> DataTrust {
        self.source
    }
    pub const fn requested(&self) -> AuthorityClass {
        self.requested
    }
    pub const fn capability_id(&self) -> u128 {
        self.capability_id
    }
    pub const fn capability_issuer_id(&self) -> u128 {
        self.capability_issuer_id
    }
    pub const fn capability_authentication_evidence_digest(&self) -> Digest {
        self.capability_authentication_evidence_digest
    }
    pub const fn approval_id(&self) -> u128 {
        self.approval_id
    }
    pub const fn approval_authentication_evidence_digest(&self) -> Digest {
        self.approval_authentication_evidence_digest
    }
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    pub const fn admitted_at_monotonic_ns(&self) -> u64 {
        self.admitted_at_monotonic_ns
    }
    pub const fn deadline_monotonic_ns(&self) -> u64 {
        self.deadline_monotonic_ns
    }
}

/// Production implementations must verify detached signature/MAC evidence
/// under a trusted issuer key. The canonical preimages passed here contain all
/// fields that admission later compares.
pub trait BindingVerifier {
    fn verify_capability(
        &self,
        issuer_id: u128,
        canonical_preimage: &[u8],
        authentication_evidence_digest: &Digest,
    ) -> bool;

    fn verify_supervisor_approval(
        &self,
        supervisor_id: u128,
        canonical_preimage: &[u8],
        authentication_evidence_digest: &Digest,
    ) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembraneError {
    UnsupportedSchema,
    MissingIdentity,
    ZeroDigest,
    StalePolicy,
    RequestExpired,
    ReplayOrOutOfOrder,
    CapabilityMissing,
    CapabilityMismatch,
    CapabilityNotYetValid,
    CapabilityExpired,
    CapabilityAuthenticationFailed,
    AmbientBypass,
    CredentialExposure,
    SupervisorApprovalRequired,
    SupervisorApprovalMismatch,
    SupervisorApprovalFromFuture,
    SupervisorApprovalExpired,
    SupervisorApprovalAuthenticationFailed,
    IndependentSupervisorRequired,
}

const CAPABILITY_GRANT_DOMAIN: [u8; 16] = *b"OSAIR_CAP_GRANT\0";
const SUPERVISOR_APPROVAL_DOMAIN: [u8; 16] = *b"OSAIR_SUP_APPROV";
pub const CAPABILITY_GRANT_PREIMAGE_LEN: usize = 182;
pub const SUPERVISOR_APPROVAL_PREIMAGE_LEN: usize = 238;

pub fn admit<V: BindingVerifier>(
    request: &MembraneRequest,
    capability: Option<&CapabilityGrant>,
    approval: Option<&SupervisorApprovalReceipt>,
    context: &mut MembraneContext,
    verifier: &V,
) -> Result<ValidatedAdmission, MembraneError> {
    validate_request(request, context)?;

    if !context.direct_privileged_path_absent {
        return Err(MembraneError::AmbientBypass);
    }
    if context.credentials_shared_with_server {
        return Err(MembraneError::CredentialExposure);
    }
    if requires_supervisor_approval(request) && context.trusted_supervisor_id == 0 {
        return Err(MembraneError::IndependentSupervisorRequired);
    }

    let capability = capability.ok_or(MembraneError::CapabilityMissing)?;
    validate_capability(request, capability, context, verifier)?;

    let approval = if requires_supervisor_approval(request) {
        Some(approval.ok_or(MembraneError::SupervisorApprovalRequired)?)
    } else {
        approval
    };

    let (approval_id, approval_digest) = if let Some(receipt) = approval {
        validate_approval(request, capability, receipt, context, verifier)?;
        (receipt.approval_id, receipt.authentication_evidence_digest)
    } else {
        (0, [0_u8; 32])
    };

    let admission = ValidatedAdmission {
        request_id: request.request_id,
        request_sequence: request.request_sequence,
        subject_id: request.subject_id,
        resource_id: request.resource_id,
        input_digest: request.input_digest,
        source: request.source,
        requested: request.requested,
        capability_id: request.capability_id,
        capability_issuer_id: capability.issuer_id,
        capability_authentication_evidence_digest: capability.authentication_evidence_digest,
        approval_id,
        approval_authentication_evidence_digest: approval_digest,
        policy_generation: context.current_policy_generation,
        admitted_at_monotonic_ns: context.now_monotonic_ns,
        deadline_monotonic_ns: request.deadline_monotonic_ns,
    };
    // Successful admission is the commit point for this supervisor-owned
    // sequence stream. Every error path above leaves replay state unchanged.
    context.last_accepted_request_sequence = request.request_sequence;
    Ok(admission)
}

pub fn encode_capability_grant_preimage(
    grant: &CapabilityGrant,
) -> Result<[u8; CAPABILITY_GRANT_PREIMAGE_LEN], MembraneError> {
    validate_claim_schema(grant.schema_major, grant.schema_minor)?;
    if grant.issuer_id == 0 || grant.capability_id == 0 || grant.request_id == 0
        || grant.request_sequence == 0 || grant.subject_id == 0 || grant.resource_id == 0
        || grant.policy_generation == 0
    {
        return Err(MembraneError::MissingIdentity);
    }
    if is_zero(&grant.input_digest) {
        return Err(MembraneError::ZeroDigest);
    }

    let mut out = [0_u8; CAPABILITY_GRANT_PREIMAGE_LEN];
    let mut cursor = 0;
    put(&mut out, &mut cursor, &CAPABILITY_GRANT_DOMAIN);
    put(&mut out, &mut cursor, &grant.schema_major.to_be_bytes());
    put(&mut out, &mut cursor, &grant.schema_minor.to_be_bytes());
    put(&mut out, &mut cursor, &grant.issuer_id.to_be_bytes());
    put(&mut out, &mut cursor, &grant.capability_id.to_be_bytes());
    put(&mut out, &mut cursor, &grant.request_id.to_be_bytes());
    put(&mut out, &mut cursor, &grant.request_sequence.to_be_bytes());
    put(&mut out, &mut cursor, &grant.subject_id.to_be_bytes());
    put(&mut out, &mut cursor, &grant.resource_id.to_be_bytes());
    put(&mut out, &mut cursor, &[grant.source as u8]);
    put(&mut out, &mut cursor, &[grant.requested as u8]);
    put(&mut out, &mut cursor, &grant.input_digest);
    put(&mut out, &mut cursor, &grant.policy_generation.to_be_bytes());
    put(
        &mut out,
        &mut cursor,
        &grant.issued_at_monotonic_ns.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &grant.not_before_monotonic_ns.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &grant.expires_at_monotonic_ns.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &grant.request_deadline_monotonic_ns.to_be_bytes(),
    );
    debug_assert_eq!(cursor, CAPABILITY_GRANT_PREIMAGE_LEN);
    Ok(out)
}

pub fn encode_supervisor_approval_preimage(
    approval: &SupervisorApprovalReceipt,
) -> Result<[u8; SUPERVISOR_APPROVAL_PREIMAGE_LEN], MembraneError> {
    validate_claim_schema(approval.schema_major, approval.schema_minor)?;
    if approval.approval_id == 0 || approval.supervisor_id == 0 || approval.request_id == 0
        || approval.request_sequence == 0 || approval.subject_id == 0
        || approval.resource_id == 0
        || approval.capability_id == 0 || approval.capability_issuer_id == 0
        || approval.policy_generation == 0
    {
        return Err(MembraneError::MissingIdentity);
    }
    if is_zero(&approval.capability_authentication_evidence_digest)
        || is_zero(&approval.input_digest)
    {
        return Err(MembraneError::ZeroDigest);
    }

    let mut out = [0_u8; SUPERVISOR_APPROVAL_PREIMAGE_LEN];
    let mut cursor = 0;
    put(&mut out, &mut cursor, &SUPERVISOR_APPROVAL_DOMAIN);
    put(&mut out, &mut cursor, &approval.schema_major.to_be_bytes());
    put(&mut out, &mut cursor, &approval.schema_minor.to_be_bytes());
    put(&mut out, &mut cursor, &approval.approval_id.to_be_bytes());
    put(
        &mut out,
        &mut cursor,
        &approval.supervisor_id.to_be_bytes(),
    );
    put(&mut out, &mut cursor, &approval.request_id.to_be_bytes());
    put(
        &mut out,
        &mut cursor,
        &approval.request_sequence.to_be_bytes(),
    );
    put(&mut out, &mut cursor, &approval.subject_id.to_be_bytes());
    put(&mut out, &mut cursor, &approval.resource_id.to_be_bytes());
    put(&mut out, &mut cursor, &[approval.source as u8]);
    put(&mut out, &mut cursor, &[approval.requested as u8]);
    put(&mut out, &mut cursor, &approval.capability_id.to_be_bytes());
    put(
        &mut out,
        &mut cursor,
        &approval.capability_issuer_id.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &approval.capability_authentication_evidence_digest,
    );
    put(&mut out, &mut cursor, &approval.input_digest);
    put(
        &mut out,
        &mut cursor,
        &approval.policy_generation.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &approval.approved_at_monotonic_ns.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &approval.expires_at_monotonic_ns.to_be_bytes(),
    );
    put(
        &mut out,
        &mut cursor,
        &approval.request_deadline_monotonic_ns.to_be_bytes(),
    );
    debug_assert_eq!(cursor, SUPERVISOR_APPROVAL_PREIMAGE_LEN);
    Ok(out)
}

pub const fn trusted_for_expiry(time: TimeClass) -> bool {
    matches!(
        time,
        TimeClass::Monotonic | TimeClass::TokenExpiryTrusted { .. }
    )
}

fn validate_request(
    request: &MembraneRequest,
    context: &MembraneContext,
) -> Result<(), MembraneError> {
    validate_claim_schema(request.schema_major, request.schema_minor)?;
    validate_claim_schema(context.schema_major, context.schema_minor)?;
    if request.request_id == 0
        || request.request_sequence == 0
        || request.subject_id == 0
        || request.resource_id == 0
        || request.capability_id == 0
        || request.policy_generation == 0
        || context.current_policy_generation == 0
        || context.trusted_capability_issuer_id == 0
    {
        return Err(MembraneError::MissingIdentity);
    }
    if is_zero(&request.input_digest) {
        return Err(MembraneError::ZeroDigest);
    }
    if request.policy_generation != context.current_policy_generation {
        return Err(MembraneError::StalePolicy);
    }
    if request.deadline_monotonic_ns < context.now_monotonic_ns {
        return Err(MembraneError::RequestExpired);
    }
    if request.request_sequence <= context.last_accepted_request_sequence {
        return Err(MembraneError::ReplayOrOutOfOrder);
    }
    Ok(())
}

fn validate_capability<V: BindingVerifier>(
    request: &MembraneRequest,
    grant: &CapabilityGrant,
    context: &MembraneContext,
    verifier: &V,
) -> Result<(), MembraneError> {
    let preimage = encode_capability_grant_preimage(grant)?;
    if is_zero(&grant.authentication_evidence_digest) {
        return Err(MembraneError::CapabilityAuthenticationFailed);
    }
    if grant.schema_major != request.schema_major
        || grant.schema_minor != request.schema_minor
        || grant.capability_id != request.capability_id
        || grant.request_id != request.request_id
        || grant.request_sequence != request.request_sequence
        || grant.subject_id != request.subject_id
        || grant.resource_id != request.resource_id
        || grant.source != request.source
        || grant.requested != request.requested
        || grant.input_digest != request.input_digest
        || grant.policy_generation != request.policy_generation
        || grant.request_deadline_monotonic_ns != request.deadline_monotonic_ns
        || grant.issuer_id != context.trusted_capability_issuer_id
    {
        return Err(MembraneError::CapabilityMismatch);
    }
    if grant.policy_generation != context.current_policy_generation {
        return Err(MembraneError::StalePolicy);
    }
    if grant.issued_at_monotonic_ns > context.now_monotonic_ns
        || grant.not_before_monotonic_ns > context.now_monotonic_ns
        || grant.not_before_monotonic_ns < grant.issued_at_monotonic_ns
    {
        return Err(MembraneError::CapabilityNotYetValid);
    }
    if grant.expires_at_monotonic_ns < context.now_monotonic_ns
        || grant.expires_at_monotonic_ns < grant.not_before_monotonic_ns
        || grant.expires_at_monotonic_ns < request.deadline_monotonic_ns
    {
        return Err(MembraneError::CapabilityExpired);
    }
    if !verifier.verify_capability(
        grant.issuer_id,
        &preimage,
        &grant.authentication_evidence_digest,
    ) {
        return Err(MembraneError::CapabilityAuthenticationFailed);
    }
    Ok(())
}

fn validate_approval<V: BindingVerifier>(
    request: &MembraneRequest,
    capability: &CapabilityGrant,
    approval: &SupervisorApprovalReceipt,
    context: &MembraneContext,
    verifier: &V,
) -> Result<(), MembraneError> {
    let preimage = encode_supervisor_approval_preimage(approval)?;
    if approval.supervisor_id == request.subject_id
        || approval.supervisor_id == capability.issuer_id
    {
        return Err(MembraneError::IndependentSupervisorRequired);
    }
    if is_zero(&approval.authentication_evidence_digest) {
        return Err(MembraneError::SupervisorApprovalAuthenticationFailed);
    }
    if approval.schema_major != request.schema_major
        || approval.schema_minor != request.schema_minor
        || approval.request_id != request.request_id
        || approval.request_sequence != request.request_sequence
        || approval.subject_id != request.subject_id
        || approval.resource_id != request.resource_id
        || approval.source != request.source
        || approval.requested != request.requested
        || approval.capability_id != request.capability_id
        || approval.capability_issuer_id != capability.issuer_id
        || approval.capability_authentication_evidence_digest
            != capability.authentication_evidence_digest
        || approval.input_digest != request.input_digest
        || approval.policy_generation != request.policy_generation
        || approval.request_deadline_monotonic_ns != request.deadline_monotonic_ns
        || approval.approved_at_monotonic_ns < capability.issued_at_monotonic_ns
        || approval.supervisor_id != context.trusted_supervisor_id
    {
        return Err(MembraneError::SupervisorApprovalMismatch);
    }
    if approval.policy_generation != context.current_policy_generation {
        return Err(MembraneError::StalePolicy);
    }
    if approval.approved_at_monotonic_ns > context.now_monotonic_ns {
        return Err(MembraneError::SupervisorApprovalFromFuture);
    }
    if approval.expires_at_monotonic_ns < context.now_monotonic_ns
        || approval.expires_at_monotonic_ns < approval.approved_at_monotonic_ns
        || approval.expires_at_monotonic_ns < request.deadline_monotonic_ns
    {
        return Err(MembraneError::SupervisorApprovalExpired);
    }
    if !verifier.verify_supervisor_approval(
        approval.supervisor_id,
        &preimage,
        &approval.authentication_evidence_digest,
    ) {
        return Err(MembraneError::SupervisorApprovalAuthenticationFailed);
    }
    Ok(())
}

const fn requires_supervisor_approval(request: &MembraneRequest) -> bool {
    let elevated = !matches!(request.requested, AuthorityClass::ReadData);
    elevated && !matches!(request.source, DataTrust::TrustedSystem)
}

fn validate_claim_schema(
    schema_major: u16,
    schema_minor: u16,
) -> Result<(), MembraneError> {
    if schema_major != SCHEMA_MAJOR || schema_minor != SCHEMA_MINOR {
        return Err(MembraneError::UnsupportedSchema);
    }
    Ok(())
}

fn put(out: &mut [u8], cursor: &mut usize, bytes: &[u8]) {
    out[*cursor..*cursor + bytes.len()].copy_from_slice(bytes);
    *cursor += bytes.len();
}

fn is_zero(digest: &Digest) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerifier;

    impl BindingVerifier for TestVerifier {
        fn verify_capability(
            &self,
            issuer_id: u128,
            canonical_preimage: &[u8],
            authentication_evidence_digest: &Digest,
        ) -> bool {
            *authentication_evidence_digest
                == test_evidence(0x43, issuer_id, canonical_preimage)
        }
        fn verify_supervisor_approval(
            &self,
            supervisor_id: u128,
            canonical_preimage: &[u8],
            authentication_evidence_digest: &Digest,
        ) -> bool {
            *authentication_evidence_digest
                == test_evidence(0x41, supervisor_id, canonical_preimage)
        }
    }

    fn test_evidence(domain: u8, issuer: u128, bytes: &[u8]) -> Digest {
        let mut out = [domain; 32];
        for (index, byte) in issuer.to_be_bytes().iter().chain(bytes).enumerate() {
            let slot = index % out.len();
            out[slot] = out[slot]
                .rotate_left(((index + slot) % 7 + 1) as u32)
                .wrapping_add(*byte)
                ^ (index as u8).wrapping_mul(17);
        }
        out
    }

    fn request() -> MembraneRequest {
        MembraneRequest {
            schema_major: SCHEMA_MAJOR,
            schema_minor: SCHEMA_MINOR,
            request_id: 1,
            request_sequence: 11,
            subject_id: 2,
            resource_id: 9,
            input_digest: [1; 32],
            source: DataTrust::ModelGenerated,
            requested: AuthorityClass::Execute,
            capability_id: 3,
            policy_generation: 4,
            deadline_monotonic_ns: 20,
            server_claims_safe: true,
        }
    }

    fn context() -> MembraneContext {
        MembraneContext {
            schema_major: SCHEMA_MAJOR,
            schema_minor: SCHEMA_MINOR,
            now_monotonic_ns: 10,
            current_policy_generation: 4,
            trusted_capability_issuer_id: 100,
            trusted_supervisor_id: 300,
            last_accepted_request_sequence: 10,
            direct_privileged_path_absent: true,
            credentials_shared_with_server: false,
        }
    }

    fn unsigned_capability(request: &MembraneRequest) -> CapabilityGrant {
        CapabilityGrant {
            schema_major: request.schema_major,
            schema_minor: request.schema_minor,
            issuer_id: 100,
            capability_id: request.capability_id,
            request_id: request.request_id,
            request_sequence: request.request_sequence,
            subject_id: request.subject_id,
            resource_id: request.resource_id,
            source: request.source,
            requested: request.requested,
            input_digest: request.input_digest,
            policy_generation: request.policy_generation,
            issued_at_monotonic_ns: 5,
            not_before_monotonic_ns: 5,
            expires_at_monotonic_ns: request.deadline_monotonic_ns,
            request_deadline_monotonic_ns: request.deadline_monotonic_ns,
            authentication_evidence_digest: [0; 32],
        }
    }

    fn signed_capability(request: &MembraneRequest) -> CapabilityGrant {
        let mut grant = unsigned_capability(request);
        let preimage = encode_capability_grant_preimage(&grant).unwrap();
        grant.authentication_evidence_digest =
            test_evidence(0x43, grant.issuer_id, &preimage);
        grant
    }

    fn unsigned_approval(
        request: &MembraneRequest,
        capability: &CapabilityGrant,
    ) -> SupervisorApprovalReceipt {
        SupervisorApprovalReceipt {
            schema_major: request.schema_major,
            schema_minor: request.schema_minor,
            approval_id: 200,
            supervisor_id: 300,
            request_id: request.request_id,
            request_sequence: request.request_sequence,
            subject_id: request.subject_id,
            resource_id: request.resource_id,
            source: request.source,
            requested: request.requested,
            capability_id: request.capability_id,
            capability_issuer_id: capability.issuer_id,
            capability_authentication_evidence_digest: capability
                .authentication_evidence_digest,
            input_digest: request.input_digest,
            policy_generation: request.policy_generation,
            approved_at_monotonic_ns: 8,
            expires_at_monotonic_ns: request.deadline_monotonic_ns,
            request_deadline_monotonic_ns: request.deadline_monotonic_ns,
            authentication_evidence_digest: [0; 32],
        }
    }

    fn signed_approval(
        request: &MembraneRequest,
        capability: &CapabilityGrant,
    ) -> SupervisorApprovalReceipt {
        let mut approval = unsigned_approval(request, capability);
        let preimage = encode_supervisor_approval_preimage(&approval).unwrap();
        approval.authentication_evidence_digest =
            test_evidence(0x41, approval.supervisor_id, &preimage);
        approval
    }

    fn admitted() -> (
        MembraneRequest,
        CapabilityGrant,
        SupervisorApprovalReceipt,
        MembraneContext,
    ) {
        let request = request();
        let capability = signed_capability(&request);
        let approval = signed_approval(&request, &capability);
        (request, capability, approval, context())
    }

    #[test]
    fn exact_authenticated_bindings_pass_and_are_preserved() {
        let (request, capability, approval, mut context) = admitted();
        let validated = admit(
            &request,
            Some(&capability),
            Some(&approval),
            &mut context,
            &TestVerifier,
        )
        .unwrap();
        assert_eq!(validated.request_id(), request.request_id);
        assert_eq!(validated.resource_id(), request.resource_id);
        assert_eq!(validated.requested(), request.requested);
        assert_eq!(validated.capability_issuer_id(), capability.issuer_id);
        assert_eq!(validated.approval_id(), approval.approval_id);
    }

    #[test]
    fn successful_admission_consumes_the_request_sequence() {
        let (request, capability, approval, mut context) = admitted();
        assert!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            )
            .is_ok()
        );
        assert_eq!(
            context.last_accepted_request_sequence,
            request.request_sequence
        );
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::ReplayOrOutOfOrder)
        );
    }

    #[test]
    fn request_annotation_never_substitutes_for_capability_or_approval() {
        let request = request();
        let mut context = context();
        assert!(request.server_claims_safe);
        assert_eq!(
            admit(&request, None, None, &mut context, &TestVerifier),
            Err(MembraneError::CapabilityMissing)
        );
        let capability = signed_capability(&request);
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                None,
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::SupervisorApprovalRequired)
        );
    }

    #[test]
    fn old_schema_is_rejected_instead_of_insecurely_accepted() {
        let (mut request, capability, approval, mut context) = admitted();
        request.schema_major = 1;
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::UnsupportedSchema)
        );
    }

    #[test]
    fn stale_or_replayed_sequence_is_rejected() {
        let (mut request, _, _, mut context) = admitted();
        request.request_sequence = context.last_accepted_request_sequence;
        let capability = signed_capability(&request);
        let approval = signed_approval(&request, &capability);
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::ReplayOrOutOfOrder)
        );
    }

    #[test]
    fn capability_cannot_cross_subject_resource_authority_or_input() {
        let (request, capability, approval, mut context) = admitted();
        let mut changed = request;
        changed.resource_id += 1;
        assert_eq!(
            admit(
                &changed,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CapabilityMismatch)
        );
        changed = request;
        changed.subject_id += 1;
        assert_eq!(
            admit(
                &changed,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CapabilityMismatch)
        );
        changed = request;
        changed.requested = AuthorityClass::Device;
        assert_eq!(
            admit(
                &changed,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CapabilityMismatch)
        );
        changed = request;
        changed.input_digest = [0x77; 32];
        assert_eq!(
            admit(
                &changed,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CapabilityMismatch)
        );
    }

    #[test]
    fn altered_authenticated_capability_claims_fail_verification() {
        let (request, mut capability, approval, mut context) = admitted();
        capability.issued_at_monotonic_ns -= 1;
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CapabilityAuthenticationFailed)
        );
    }

    #[test]
    fn cryptographically_valid_grant_from_an_unselected_issuer_rejects() {
        let (request, mut capability, approval, mut context) = admitted();
        capability.issuer_id += 1;
        capability.authentication_evidence_digest = test_evidence(
            0x43,
            capability.issuer_id,
            &encode_capability_grant_preimage(&capability).unwrap(),
        );
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CapabilityMismatch)
        );
    }

    #[test]
    fn approval_cannot_be_replayed_across_request_or_target() {
        let (request, _, old_approval, mut context) = admitted();
        let mut changed = request;
        changed.request_id += 1;
        changed.request_sequence += 1;
        let capability = signed_capability(&changed);
        assert_eq!(
            admit(
                &changed,
                Some(&capability),
                Some(&old_approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::SupervisorApprovalMismatch)
        );
        changed = request;
        changed.resource_id += 1;
        let capability = signed_capability(&changed);
        assert_eq!(
            admit(
                &changed,
                Some(&capability),
                Some(&old_approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::SupervisorApprovalMismatch)
        );
    }

    #[test]
    fn self_future_expired_and_forged_approvals_reject() {
        let (request, capability, approval, mut context) = admitted();
        let mut self_approval = approval;
        self_approval.supervisor_id = request.subject_id;
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&self_approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::IndependentSupervisorRequired)
        );
        let mut future = unsigned_approval(&request, &capability);
        future.approved_at_monotonic_ns = context.now_monotonic_ns + 1;
        future.authentication_evidence_digest = test_evidence(
            0x41,
            future.supervisor_id,
            &encode_supervisor_approval_preimage(&future).unwrap(),
        );
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&future),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::SupervisorApprovalFromFuture)
        );
        let mut expired = unsigned_approval(&request, &capability);
        expired.expires_at_monotonic_ns = context.now_monotonic_ns - 1;
        expired.authentication_evidence_digest = test_evidence(
            0x41,
            expired.supervisor_id,
            &encode_supervisor_approval_preimage(&expired).unwrap(),
        );
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&expired),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::SupervisorApprovalExpired)
        );
        let mut forged = approval;
        forged.authentication_evidence_digest[0] ^= 1;
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&forged),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::SupervisorApprovalAuthenticationFailed)
        );
    }

    #[test]
    fn trusted_read_can_omit_separate_approval_but_not_capability() {
        let mut request = request();
        request.source = DataTrust::TrustedSystem;
        request.requested = AuthorityClass::ReadData;
        let capability = signed_capability(&request);
        assert!(
            admit(
                &request,
                Some(&capability),
                None,
                &mut context(),
                &TestVerifier
            )
            .is_ok()
        );
    }

    #[test]
    fn ambient_path_credentials_and_wall_time_are_never_trusted() {
        let (request, capability, approval, mut context) = admitted();
        context.direct_privileged_path_absent = false;
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::AmbientBypass)
        );
        context = self::context();
        context.credentials_shared_with_server = true;
        assert_eq!(
            admit(
                &request,
                Some(&capability),
                Some(&approval),
                &mut context,
                &TestVerifier
            ),
            Err(MembraneError::CredentialExposure)
        );
        assert!(!trusted_for_expiry(TimeClass::WallUntrusted));
        assert!(trusted_for_expiry(TimeClass::Monotonic));
    }
}
