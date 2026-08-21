#![no_std]

//! Allocation-free DMA command validation.
//!
//! A [`RegionCapability`] is scoped to one device, IOMMU security domain, and
//! queue. Compilation checks that binding against both the raw command and a
//! trusted dispatch context, then carries the complete target into
//! [`ValidatedCommand`] so a backend never has to recover authority from raw
//! input.

pub const SCHEMA_MAJOR: u16 = 2;
pub const SCHEMA_MINOR: u16 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ToDevice = 0,
    FromDevice = 1,
    Bidirectional = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionCapability {
    pub id: u128,
    pub device_id: u128,
    pub iommu_domain_id: u128,
    pub queue_id: u32,
    pub size_bytes: u64,
    pub generation: u64,
    pub allowed: Direction,
    pub mapped: bool,
    pub quarantined: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaCommand {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub command_id: u128,
    pub command_sequence: u64,
    pub device_id: u128,
    pub iommu_domain_id: u128,
    pub queue_id: u32,
    pub region_id: u128,
    pub offset: u64,
    pub length: u64,
    pub direction: Direction,
    pub generation: u64,
    pub deadline_monotonic_ns: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CompileContext {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub now_monotonic_ns: u64,
    pub last_accepted_command_sequence: u64,
    pub trusted_device_id: u128,
    pub trusted_iommu_domain_id: u128,
    pub trusted_queue_id: u32,
    pub authorized_region_id: u128,
    pub device_generation: u64,
    pub iommu_isolated: bool,
    pub bounce_pool_available: bool,
    pub allow_zero_length: bool,
}

#[must_use = "validated DMA authority must be consumed by the selected backend"]
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedCommand {
    command_id: u128,
    command_sequence: u64,
    device_id: u128,
    iommu_domain_id: u128,
    queue_id: u32,
    region_id: u128,
    offset: u64,
    length: u64,
    direction: Direction,
    generation: u64,
    deadline_monotonic_ns: u64,
    validated_at_monotonic_ns: u64,
    uses_bounce_buffer: bool,
}

impl ValidatedCommand {
    pub const fn command_id(&self) -> u128 {
        self.command_id
    }
    pub const fn command_sequence(&self) -> u64 {
        self.command_sequence
    }
    pub const fn device_id(&self) -> u128 {
        self.device_id
    }
    pub const fn iommu_domain_id(&self) -> u128 {
        self.iommu_domain_id
    }
    pub const fn queue_id(&self) -> u32 {
        self.queue_id
    }
    pub const fn region_id(&self) -> u128 {
        self.region_id
    }
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    pub const fn length(&self) -> u64 {
        self.length
    }
    pub const fn direction(&self) -> Direction {
        self.direction
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn deadline_monotonic_ns(&self) -> u64 {
        self.deadline_monotonic_ns
    }
    pub const fn validated_at_monotonic_ns(&self) -> u64 {
        self.validated_at_monotonic_ns
    }
    pub const fn uses_bounce_buffer(&self) -> bool {
        self.uses_bounce_buffer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaError {
    UnsupportedSchema,
    MissingIdentity,
    ReplayOrOutOfOrder,
    RegionTargetMismatch,
    TrustedTargetMismatch,
    EmptyTransfer,
    OutOfBounds,
    DirectionDenied,
    StaleGeneration,
    DeadlineExpired,
    RegionUnavailable,
    IsolationUnavailable,
}

pub fn compile(
    command: &DmaCommand,
    region: &RegionCapability,
    context: &mut CompileContext,
) -> Result<ValidatedCommand, DmaError> {
    if command.schema_major != SCHEMA_MAJOR
        || command.schema_minor != SCHEMA_MINOR
        || context.schema_major != SCHEMA_MAJOR
        || context.schema_minor != SCHEMA_MINOR
    {
        return Err(DmaError::UnsupportedSchema);
    }
    if command.command_id == 0
        || command.command_sequence == 0
        || command.device_id == 0
        || command.iommu_domain_id == 0
        || command.region_id == 0
        || region.id == 0
        || region.device_id == 0
        || region.iommu_domain_id == 0
        || context.trusted_device_id == 0
        || context.trusted_iommu_domain_id == 0
        || context.authorized_region_id == 0
        || command.generation == 0
        || region.generation == 0
        || context.device_generation == 0
    {
        return Err(DmaError::MissingIdentity);
    }
    if command.command_sequence <= context.last_accepted_command_sequence {
        return Err(DmaError::ReplayOrOutOfOrder);
    }
    if command.region_id != region.id
        || command.device_id != region.device_id
        || command.iommu_domain_id != region.iommu_domain_id
        || command.queue_id != region.queue_id
    {
        return Err(DmaError::RegionTargetMismatch);
    }
    if command.device_id != context.trusted_device_id
        || command.iommu_domain_id != context.trusted_iommu_domain_id
        || command.queue_id != context.trusted_queue_id
        || command.region_id != context.authorized_region_id
    {
        return Err(DmaError::TrustedTargetMismatch);
    }
    if command.length == 0 && !context.allow_zero_length {
        return Err(DmaError::EmptyTransfer);
    }
    if command.offset > region.size_bytes || command.length > region.size_bytes - command.offset {
        return Err(DmaError::OutOfBounds);
    }
    if command.direction != region.allowed && region.allowed != Direction::Bidirectional {
        return Err(DmaError::DirectionDenied);
    }
    if command.generation != region.generation || command.generation != context.device_generation {
        return Err(DmaError::StaleGeneration);
    }
    if command.deadline_monotonic_ns < context.now_monotonic_ns {
        return Err(DmaError::DeadlineExpired);
    }
    if !region.mapped || region.quarantined {
        return Err(DmaError::RegionUnavailable);
    }
    let uses_bounce_buffer = !context.iommu_isolated;
    if uses_bounce_buffer && !context.bounce_pool_available {
        return Err(DmaError::IsolationUnavailable);
    }
    let validated = ValidatedCommand {
        command_id: command.command_id,
        command_sequence: command.command_sequence,
        device_id: command.device_id,
        iommu_domain_id: command.iommu_domain_id,
        queue_id: command.queue_id,
        region_id: region.id,
        offset: command.offset,
        length: command.length,
        direction: command.direction,
        generation: command.generation,
        deadline_monotonic_ns: command.deadline_monotonic_ns,
        validated_at_monotonic_ns: context.now_monotonic_ns,
        uses_bounce_buffer,
    };
    context.last_accepted_command_sequence = command.command_sequence;
    Ok(validated)
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    fn region() -> RegionCapability {
        RegionCapability {
            id: 2,
            device_id: 11,
            iommu_domain_id: 12,
            queue_id: 7,
            size_bytes: 4096,
            generation: 13,
            allowed: Direction::ToDevice,
            mapped: true,
            quarantined: false,
        }
    }
    fn command() -> DmaCommand {
        DmaCommand {
            schema_major: SCHEMA_MAJOR,
            schema_minor: SCHEMA_MINOR,
            command_id: 21,
            command_sequence: 31,
            device_id: 11,
            iommu_domain_id: 12,
            queue_id: 7,
            region_id: 2,
            offset: 0,
            length: 4096,
            direction: Direction::ToDevice,
            generation: 13,
            deadline_monotonic_ns: 40,
        }
    }
    fn context() -> CompileContext {
        CompileContext {
            schema_major: SCHEMA_MAJOR,
            schema_minor: SCHEMA_MINOR,
            now_monotonic_ns: 20,
            last_accepted_command_sequence: 30,
            trusted_device_id: 11,
            trusted_iommu_domain_id: 12,
            trusted_queue_id: 7,
            authorized_region_id: 2,
            device_generation: 13,
            iommu_isolated: true,
            bounce_pool_available: false,
            allow_zero_length: false,
        }
    }
    #[test]
    fn legal_operation_preserves_complete_backend_target() {
        let command = command();
        let validated = compile(&command, &region(), &mut context()).unwrap();
        assert_eq!(validated.command_id(), command.command_id);
        assert_eq!(validated.device_id(), command.device_id);
    }
    #[test]
    fn replay_rejected() {
        let command = command();
        let region = region();
        let mut ctx = context();
        assert!(compile(&command, &region, &mut ctx).is_ok());
        assert_eq!(
            compile(&command, &region, &mut ctx),
            Err(DmaError::ReplayOrOutOfOrder)
        );
    }
    #[test]
    fn region_target_mismatch_rejected() {
        let mut cmd = command();
        cmd.device_id += 1;
        assert_eq!(
            compile(&cmd, &region(), &mut context()),
            Err(DmaError::RegionTargetMismatch)
        );
    }
    #[test]
    fn trusted_target_mismatch_rejected() {
        let mut cmd = command();
        let mut rgn = region();
        cmd.device_id += 1;
        rgn.device_id = cmd.device_id;
        assert_eq!(
            compile(&cmd, &rgn, &mut context()),
            Err(DmaError::TrustedTargetMismatch)
        );
    }
    #[test]
    fn overflow_bounds_rejected() {
        let mut cmd = command();
        cmd.offset = 4095;
        cmd.length = 2;
        assert_eq!(
            compile(&cmd, &region(), &mut context()),
            Err(DmaError::OutOfBounds)
        );
    }
    #[test]
    fn stale_generation_rejected() {
        let mut ctx = context();
        ctx.device_generation += 1;
        assert_eq!(
            compile(&command(), &region(), &mut ctx),
            Err(DmaError::StaleGeneration)
        );
    }
    #[test]
    fn bounce_buffer_requires_pool() {
        let mut ctx = context();
        ctx.iommu_isolated = false;
        assert_eq!(
            compile(&command(), &region(), &mut ctx),
            Err(DmaError::IsolationUnavailable)
        );
        ctx.bounce_pool_available = true;
        assert!(
            compile(&command(), &region(), &mut ctx)
                .unwrap()
                .uses_bounce_buffer()
        );
    }
}
