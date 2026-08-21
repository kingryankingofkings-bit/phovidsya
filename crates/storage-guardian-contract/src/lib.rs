#![no_std]

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GuardState {
    BootSelfTest = 0,
    Normal = 1,
    Elevated = 2,
    Contained = 3,
    RecoveryReadOnly = 4,
    Maintenance = 5,
    Fault = 6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MutationKind {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    WriteZeroes = 4,
    Format = 5,
    Firmware = 6,
    Unknown = 7,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardPolicy {
    pub schema_major: u16,
    pub volume_id: u128,
    pub exposed_blocks: u64,
    pub block_size: u32,
    pub policy_epoch: u64,
    pub monitor_only: bool,
    pub require_journal_for_write: bool,
    pub deny_destructive_commands: bool,
    pub max_write_blocks: u32,
    pub emergency_reserve_bytes: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIntent {
    pub intent_id: u128,
    pub principal_id: u128,
    pub volume_id: u128,
    pub kind: MutationKind,
    pub start_block: u64,
    pub block_count: u32,
    pub volume_generation: u64,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub deadline_monotonic_ns: u64,
    pub payload_digest: Digest,
    pub authority_digest: Digest,
    pub recovery_point_digest: Digest,
    pub approval_digest: Digest,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardContext {
    pub now_monotonic_ns: u64,
    pub state: GuardState,
    pub volume_generation: u64,
    pub policy_epoch: u64,
    pub last_sequence: u64,
    pub journal_ready: bool,
    pub journal_free_bytes: u64,
    pub durable_commit_available: bool,
    pub authority_matches: bool,
    pub separate_approval_required: bool,
    pub approval_matches: bool,
    pub physical_presence: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardReceipt {
    pub intent_id: u128,
    pub volume_id: u128,
    pub volume_generation: u64,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub authorized_bytes: u64,
    pub journal_required: bool,
    pub state: GuardState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardError {
    UnsupportedSchema,
    MissingIdentity,
    ZeroDigest,
    VolumeMismatch,
    InvalidGeometry,
    OutOfBounds,
    WriteTooLarge,
    StaleGeneration,
    StalePolicy,
    Replay,
    Expired,
    StateDeniesMutation,
    DestructiveCommandDenied,
    JournalUnavailable,
    RecoveryReserveThreatened,
    DurabilityUnavailable,
    AuthorityMismatch,
    ApprovalRequired,
    ApprovalMismatch,
    PhysicalPresenceRequired,
}

pub fn authorize(
    policy: &GuardPolicy,
    intent: &StorageIntent,
    context: &GuardContext,
) -> Result<GuardReceipt, GuardError> {
    if policy.schema_major != 1 {
        return Err(GuardError::UnsupportedSchema);
    }
    if policy.volume_id == 0 || intent.intent_id == 0 || intent.principal_id == 0 {
        return Err(GuardError::MissingIdentity);
    }
    if intent.volume_id != policy.volume_id {
        return Err(GuardError::VolumeMismatch);
    }
    if policy.block_size == 0 || policy.exposed_blocks == 0 {
        return Err(GuardError::InvalidGeometry);
    }
    if intent.start_block > policy.exposed_blocks
        || u64::from(intent.block_count) > policy.exposed_blocks - intent.start_block
    {
        return Err(GuardError::OutOfBounds);
    }
    let mutating = !matches!(intent.kind, MutationKind::Read | MutationKind::Flush);
    let write_like = matches!(intent.kind, MutationKind::Write);
    if write_like && (intent.block_count == 0 || intent.block_count > policy.max_write_blocks) {
        return Err(GuardError::WriteTooLarge);
    }
    if intent.volume_generation != context.volume_generation {
        return Err(GuardError::StaleGeneration);
    }
    if intent.policy_epoch != policy.policy_epoch || intent.policy_epoch != context.policy_epoch {
        return Err(GuardError::StalePolicy);
    }
    if intent.sequence == 0 || intent.sequence <= context.last_sequence {
        return Err(GuardError::Replay);
    }
    if intent.deadline_monotonic_ns < context.now_monotonic_ns {
        return Err(GuardError::Expired);
    }
    if mutating && !matches!(context.state, GuardState::Normal | GuardState::Elevated) {
        return Err(GuardError::StateDeniesMutation);
    }
    if policy.deny_destructive_commands
        && matches!(
            intent.kind,
            MutationKind::Discard
                | MutationKind::WriteZeroes
                | MutationKind::Format
                | MutationKind::Firmware
                | MutationKind::Unknown
        )
    {
        return Err(GuardError::DestructiveCommandDenied);
    }
    if mutating
        && (intent.payload_digest.iter().all(|b| *b == 0)
            || intent.authority_digest.iter().all(|b| *b == 0))
    {
        return Err(GuardError::ZeroDigest);
    }
    if !context.authority_matches {
        return Err(GuardError::AuthorityMismatch);
    }
    if context.separate_approval_required {
        if intent.approval_digest.iter().all(|b| *b == 0) {
            return Err(GuardError::ApprovalRequired);
        }
        if !context.approval_matches {
            return Err(GuardError::ApprovalMismatch);
        }
    }
    let bytes = u64::from(intent.block_count)
        .checked_mul(u64::from(policy.block_size))
        .ok_or(GuardError::InvalidGeometry)?;
    if write_like && policy.require_journal_for_write {
        if !context.journal_ready {
            return Err(GuardError::JournalUnavailable);
        }
        if context.journal_free_bytes < bytes.saturating_add(policy.emergency_reserve_bytes) {
            return Err(GuardError::RecoveryReserveThreatened);
        }
        if !context.durable_commit_available {
            return Err(GuardError::DurabilityUnavailable);
        }
        if intent.recovery_point_digest.iter().all(|b| *b == 0) {
            return Err(GuardError::ZeroDigest);
        }
    }
    Ok(GuardReceipt {
        intent_id: intent.intent_id,
        volume_id: intent.volume_id,
        volume_generation: intent.volume_generation,
        policy_epoch: intent.policy_epoch,
        sequence: intent.sequence,
        authorized_bytes: bytes,
        journal_required: write_like && policy.require_journal_for_write,
        state: context.state,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAuthorization {
    pub device_id: u128,
    pub action_id: u128,
    pub state_version: u64,
    pub target_sequence: u64,
    pub nonce: Digest,
    pub challenge_digest: Digest,
    pub signature_digest: Digest,
    pub expires_at_monotonic_ns: u64,
}
pub fn authorize_recovery(
    auth: &RecoveryAuthorization,
    now: u64,
    current_state_version: u64,
    physical_presence: bool,
    signature_valid: bool,
) -> Result<(), GuardError> {
    if auth.device_id == 0 || auth.action_id == 0 || auth.target_sequence == 0 {
        return Err(GuardError::MissingIdentity);
    }
    if [auth.nonce, auth.challenge_digest, auth.signature_digest]
        .iter()
        .any(|d| d.iter().all(|b| *b == 0))
    {
        return Err(GuardError::ZeroDigest);
    }
    if auth.state_version != current_state_version {
        return Err(GuardError::StaleGeneration);
    }
    if auth.expires_at_monotonic_ns < now {
        return Err(GuardError::Expired);
    }
    if !signature_valid {
        return Err(GuardError::AuthorityMismatch);
    }
    if !physical_presence {
        return Err(GuardError::PhysicalPresenceRequired);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalClass {
    Idempotent,
    Compensatable,
    NonReplayable,
}
pub const fn safe_to_replay(class: JournalClass, commit_durable: bool) -> bool {
    commit_durable
        && matches!(
            class,
            JournalClass::Idempotent | JournalClass::Compensatable
        )
}
pub const fn transition_allowed(from: GuardState, to: GuardState) -> bool {
    matches!(
        (from, to),
        (GuardState::BootSelfTest, GuardState::Normal)
            | (GuardState::BootSelfTest, GuardState::Fault)
            | (GuardState::Normal, GuardState::Elevated)
            | (GuardState::Normal, GuardState::Contained)
            | (GuardState::Elevated, GuardState::Normal)
            | (GuardState::Elevated, GuardState::Contained)
            | (GuardState::Contained, GuardState::RecoveryReadOnly)
            | (GuardState::RecoveryReadOnly, GuardState::Maintenance)
            | (GuardState::Maintenance, GuardState::Normal)
            | (_, GuardState::Fault)
    )
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> GuardPolicy {
        GuardPolicy {
            schema_major: 1,
            volume_id: 7,
            exposed_blocks: 1000,
            block_size: 4096,
            policy_epoch: 9,
            monitor_only: true,
            require_journal_for_write: true,
            deny_destructive_commands: true,
            max_write_blocks: 32,
            emergency_reserve_bytes: 8192,
        }
    }
    fn i() -> StorageIntent {
        StorageIntent {
            intent_id: 1,
            principal_id: 2,
            volume_id: 7,
            kind: MutationKind::Write,
            start_block: 10,
            block_count: 2,
            volume_generation: 4,
            policy_epoch: 9,
            sequence: 5,
            deadline_monotonic_ns: 20,
            payload_digest: [1; 32],
            authority_digest: [2; 32],
            recovery_point_digest: [3; 32],
            approval_digest: [4; 32],
        }
    }
    fn c() -> GuardContext {
        GuardContext {
            now_monotonic_ns: 10,
            state: GuardState::Normal,
            volume_generation: 4,
            policy_epoch: 9,
            last_sequence: 4,
            journal_ready: true,
            journal_free_bytes: 32768,
            durable_commit_available: true,
            authority_matches: true,
            separate_approval_required: false,
            approval_matches: true,
            physical_presence: false,
        }
    }
    #[test]
    fn durable_write_authorized() {
        let r = authorize(&p(), &i(), &c()).unwrap();
        assert!(r.journal_required);
        assert_eq!(r.authorized_bytes, 8192)
    }
    #[test]
    fn overflow_safe_bounds() {
        let mut x = i();
        x.start_block = u64::MAX;
        x.block_count = 2;
        assert_eq!(authorize(&p(), &x, &c()), Err(GuardError::OutOfBounds));
    }
    #[test]
    fn stale_generation_denied() {
        let mut x = i();
        x.volume_generation = 3;
        assert_eq!(authorize(&p(), &x, &c()), Err(GuardError::StaleGeneration));
    }
    #[test]
    fn replay_denied() {
        let mut x = i();
        x.sequence = 4;
        assert_eq!(authorize(&p(), &x, &c()), Err(GuardError::Replay));
    }
    #[test]
    fn containment_denies_write() {
        let mut x = c();
        x.state = GuardState::Contained;
        assert_eq!(
            authorize(&p(), &i(), &x),
            Err(GuardError::StateDeniesMutation)
        );
    }
    #[test]
    fn destructive_command_denied() {
        let mut x = i();
        x.kind = MutationKind::Discard;
        assert_eq!(
            authorize(&p(), &x, &c()),
            Err(GuardError::DestructiveCommandDenied)
        );
    }
    #[test]
    fn journal_mandatory() {
        let mut x = c();
        x.journal_ready = false;
        assert_eq!(
            authorize(&p(), &i(), &x),
            Err(GuardError::JournalUnavailable)
        );
    }
    #[test]
    fn emergency_reserve_preserved() {
        let mut x = c();
        x.journal_free_bytes = 16000;
        assert_eq!(
            authorize(&p(), &i(), &x),
            Err(GuardError::RecoveryReserveThreatened)
        );
    }
    #[test]
    fn success_needs_durability() {
        let mut x = c();
        x.durable_commit_available = false;
        assert_eq!(
            authorize(&p(), &i(), &x),
            Err(GuardError::DurabilityUnavailable)
        );
    }
    #[test]
    fn separate_approval_bound() {
        let mut x = c();
        x.separate_approval_required = true;
        x.approval_matches = false;
        assert_eq!(authorize(&p(), &i(), &x), Err(GuardError::ApprovalMismatch));
    }
    #[test]
    fn recovery_needs_physical_presence() {
        let a = RecoveryAuthorization {
            device_id: 1,
            action_id: 2,
            state_version: 3,
            target_sequence: 4,
            nonce: [1; 32],
            challenge_digest: [2; 32],
            signature_digest: [3; 32],
            expires_at_monotonic_ns: 20,
        };
        assert_eq!(
            authorize_recovery(&a, 10, 3, false, true),
            Err(GuardError::PhysicalPresenceRequired)
        );
        assert_eq!(authorize_recovery(&a, 10, 3, true, true), Ok(()));
    }
    #[test]
    fn host_reset_cannot_clear_containment() {
        assert!(!transition_allowed(
            GuardState::Contained,
            GuardState::Normal
        ));
    }
    #[test]
    fn nonreplayable_journal_never_replays() {
        assert!(!safe_to_replay(JournalClass::NonReplayable, true));
    }
}
