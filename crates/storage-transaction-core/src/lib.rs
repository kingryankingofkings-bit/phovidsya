#![no_std]
#![forbid(unsafe_code)]

//! Allocation-free transactional object and namespace storage core.
//!
//! This crate deliberately stops before any block driver, filesystem mount,
//! physical sector write, cache flush, FUA command, DMA, MMIO, or real
//! power-loss claim. The only constructible public commit mode in this slice is
//! `Durability::MemoryOnly`. The opaque `BarrierReceipt` path is deliberately
//! unissuable until a future trusted storage service binds it to a separately
//! validated ordering and durability barrier. No userspace/raw-enum decoder is
//! provided here.

use core::convert::TryFrom;

pub const MAX_OBJECTS: usize = 8;
pub const MAX_NAMES: usize = 8;
pub const MAX_NAME_BYTES: usize = 32;
pub const MAX_OBJECT_BYTES: usize = 128;
pub const MAX_IO_BYTES: usize = 64;
pub const MAX_SNAPSHOTS: usize = 2;
pub const MAX_WAL_RECORDS: usize = 64;
pub const LOGICAL_CAPACITY_BYTES: usize = MAX_OBJECTS * MAX_OBJECT_BYTES;
pub const COW_MAX_RECOVERY_STEPS: usize = 4;
pub const WAL_MAX_RECOVERY_STEPS: usize = MAX_WAL_RECORDS;

const SUPERBLOCK_MAGIC: u64 = 0x4e52_5354_4f52_4531;
const CHECKSUM_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const CHECKSUM_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectId(u64);

impl ObjectId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Generation(u64);

impl Generation {
    pub const ZERO: Self = Self(0);

    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, Error> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(Error::ArithmeticOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    id: ObjectId,
    generation: Generation,
}

impl ObjectHandle {
    pub const fn id(self) -> ObjectId {
        self.id
    }

    pub const fn generation(self) -> Generation {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionId {
    nonce: u64,
    base_generation: Generation,
}

impl TransactionId {
    pub const fn base_generation(self) -> Generation {
        self.base_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotId {
    slot: u8,
    generation: Generation,
    nonce: u64,
}

impl SnapshotId {
    pub const fn generation(self) -> Generation {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tick(u64);

impl Tick {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline(u64);

impl Deadline {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VariantId {
    Cow,
    Wal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierReceipt {
    variant: VariantId,
    transaction: TransactionId,
    target_generation: Generation,
    state_checksum: u64,
    barrier_epoch: u64,
    binding_checksum: u64,
}

impl BarrierReceipt {
    fn is_bound_to(
        self,
        variant: VariantId,
        transaction: TransactionId,
        target_generation: Generation,
        state_checksum: u64,
    ) -> bool {
        self.variant == variant
            && self.transaction == transaction
            && self.target_generation == target_generation
            && self.state_checksum == state_checksum
            && self.binding_checksum
                == barrier_binding_checksum(
                    variant,
                    transaction,
                    target_generation,
                    state_checksum,
                    self.barrier_epoch,
                )
    }

    // There is intentionally no public constructor. A future trusted block
    // service integration must add an issuer only after its barrier contract is
    // validated. This prevents mapping an untrusted raw bool/enum to durability.
    #[cfg(test)]
    fn synthetic_for_test(
        variant: VariantId,
        transaction: TransactionId,
        target_generation: Generation,
        state_checksum: u64,
        barrier_epoch: u64,
    ) -> Self {
        Self {
            variant,
            transaction,
            target_generation,
            state_checksum,
            barrier_epoch,
            binding_checksum: barrier_binding_checksum(
                variant,
                transaction,
                target_generation,
                state_checksum,
                barrier_epoch,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Durability {
    MemoryOnly,
    ExternalBarrier(BarrierReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDurability {
    MemoryOnly,
    ExternallyConfirmed,
}

impl VariantId {
    const fn tag(self) -> u64 {
        match self {
            Self::Cow => 1,
            Self::Wal => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    None,
    BeforeCommitReceipt,
    AfterCommitReceipt,
    CorruptCommitReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    InvalidName,
    NameTooLong,
    TransactionBusy,
    RecoveryRequired,
    NoActiveTransaction,
    StaleTransaction,
    DeadlineExceeded,
    Cancelled,
    ObjectCapacity,
    NamespaceCapacity,
    SnapshotCapacity,
    ObjectTooLarge,
    IoTooLarge,
    OffsetOutOfRange,
    ArithmeticOverflow,
    QuotaExceeded,
    RecoveryReserveProtected,
    StaleHandle,
    NameNotFound,
    StaleSnapshot,
    InvalidBarrierReceipt,
    WalFull,
    NoPendingRecovery,
    CorruptRecoveryMetadata,
    InvariantViolation,
    Interrupted(FaultPoint),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    quota_bytes: usize,
    recovery_reserve_bytes: usize,
}

impl Config {
    pub fn new(quota_bytes: usize, recovery_reserve_bytes: usize) -> Result<Self, Error> {
        if quota_bytes == 0
            || quota_bytes > LOGICAL_CAPACITY_BYTES
            || recovery_reserve_bytes >= quota_bytes
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            quota_bytes,
            recovery_reserve_bytes,
        })
    }

    pub const fn quota_bytes(self) -> usize {
        self.quota_bytes
    }

    pub const fn recovery_reserve_bytes(self) -> usize {
        self.recovery_reserve_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name {
    bytes: [u8; MAX_NAME_BYTES],
    len: u8,
}

impl Name {
    const EMPTY: Self = Self {
        bytes: [0; MAX_NAME_BYTES],
        len: 0,
    };

    pub fn new(value: &[u8]) -> Result<Self, Error> {
        if value.is_empty() {
            return Err(Error::InvalidName);
        }
        if value.len() > MAX_NAME_BYTES {
            return Err(Error::NameTooLong);
        }
        if value == b"."
            || value == b".."
            || value.iter().any(|byte| {
                *byte == 0 || *byte == b'/' || *byte == b'\\' || *byte < 0x20 || *byte == 0x7f
            })
            || matches!(value.last(), Some(b'.' | b' '))
        {
            return Err(Error::InvalidName);
        }
        let mut name = Self::EMPTY;
        name.bytes[..value.len()].copy_from_slice(value);
        name.len = u8::try_from(value.len()).map_err(|_| Error::NameTooLong)?;
        Ok(name)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    variant: VariantId,
    generation: Generation,
    state_checksum: u64,
    durability: CommitDurability,
    descriptor_checksum: u64,
}

impl CommitReceipt {
    fn new(
        variant: VariantId,
        generation: Generation,
        state_checksum: u64,
        durability: CommitDurability,
    ) -> Self {
        let descriptor_checksum = receipt_checksum(variant, generation, state_checksum, durability);
        Self {
            variant,
            generation,
            state_checksum,
            durability,
            descriptor_checksum,
        }
    }

    pub const fn generation(self) -> Generation {
        self.generation
    }

    pub const fn state_checksum(self) -> u64 {
        self.state_checksum
    }

    pub const fn durability(self) -> CommitDurability {
        self.durability
    }

    pub fn is_valid(self) -> bool {
        self.descriptor_checksum
            == receipt_checksum(
                self.variant,
                self.generation,
                self.state_checksum,
                self.durability,
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub selected_generation: Generation,
    pub changed: bool,
    pub rejected_corrupt_records: usize,
    pub discarded_uncommitted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcReport {
    pub snapshots_reclaimed: usize,
    pub recovery_records_reclaimed: usize,
}

#[derive(Clone, Copy)]
struct IntegrityChecksum(u64);

impl IntegrityChecksum {
    const fn new() -> Self {
        Self(CHECKSUM_OFFSET)
    }

    fn push_byte(&mut self, value: u8) {
        self.0 ^= u64::from(value);
        self.0 = self.0.wrapping_mul(CHECKSUM_PRIME);
    }

    fn push_bool(&mut self, value: bool) {
        self.push_byte(u8::from(value));
    }

    fn push_u64(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.push_byte(byte);
        }
    }

    fn push_bytes(&mut self, value: &[u8]) {
        self.push_u64(value.len() as u64);
        for byte in value {
            self.push_byte(*byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

fn commit_durability_tag(durability: CommitDurability) -> u64 {
    match durability {
        CommitDurability::MemoryOnly => 1,
        CommitDurability::ExternallyConfirmed => 2,
    }
}

fn receipt_checksum(
    variant: VariantId,
    generation: Generation,
    state_checksum: u64,
    durability: CommitDurability,
) -> u64 {
    let mut checksum = IntegrityChecksum::new();
    checksum.push_u64(variant.tag());
    checksum.push_u64(generation.get());
    checksum.push_u64(state_checksum);
    checksum.push_u64(commit_durability_tag(durability));
    checksum.finish()
}

fn barrier_binding_checksum(
    variant: VariantId,
    transaction: TransactionId,
    target_generation: Generation,
    state_checksum: u64,
    barrier_epoch: u64,
) -> u64 {
    let mut checksum = IntegrityChecksum::new();
    checksum.push_u64(variant.tag());
    checksum.push_u64(transaction.nonce);
    checksum.push_u64(transaction.base_generation.get());
    checksum.push_u64(target_generation.get());
    checksum.push_u64(state_checksum);
    checksum.push_u64(barrier_epoch);
    checksum.finish()
}

fn validate_durability(
    durability: Durability,
    variant: VariantId,
    transaction: TransactionId,
    target_generation: Generation,
    state_checksum: u64,
) -> Result<CommitDurability, Error> {
    match durability {
        Durability::MemoryOnly => Ok(CommitDurability::MemoryOnly),
        Durability::ExternalBarrier(receipt)
            if receipt.is_bound_to(variant, transaction, target_generation, state_checksum) =>
        {
            Ok(CommitDurability::ExternallyConfirmed)
        }
        Durability::ExternalBarrier(_) => Err(Error::InvalidBarrierReceipt),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageMetrics {
    pub state_bytes: usize,
    pub cow_store_bytes: usize,
    pub wal_store_bytes: usize,
    pub cow_max_recovery_steps: usize,
    pub wal_max_recovery_steps: usize,
}

#[derive(Clone, Copy)]
struct ObjectSlot {
    present: bool,
    id: ObjectId,
    generation: Generation,
    len: u16,
    data: [u8; MAX_OBJECT_BYTES],
}

impl ObjectSlot {
    const EMPTY: Self = Self {
        present: false,
        id: ObjectId(0),
        generation: Generation::ZERO,
        len: 0,
        data: [0; MAX_OBJECT_BYTES],
    };

    const fn handle(self) -> ObjectHandle {
        ObjectHandle {
            id: self.id,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Copy)]
struct NamespaceSlot {
    present: bool,
    name: Name,
    handle: ObjectHandle,
}

impl NamespaceSlot {
    const EMPTY: Self = Self {
        present: false,
        name: Name::EMPTY,
        handle: ObjectHandle {
            id: ObjectId(0),
            generation: Generation::ZERO,
        },
    };
}

#[derive(Clone, Copy)]
struct StoreState {
    generation: Generation,
    next_object_id: u64,
    next_object_generation: u64,
    objects: [ObjectSlot; MAX_OBJECTS],
    namespaces: [NamespaceSlot; MAX_NAMES],
}

impl StoreState {
    const fn empty() -> Self {
        Self {
            generation: Generation::ZERO,
            next_object_id: 1,
            next_object_generation: 1,
            objects: [ObjectSlot::EMPTY; MAX_OBJECTS],
            namespaces: [NamespaceSlot::EMPTY; MAX_NAMES],
        }
    }

    fn used_bytes(&self) -> Result<usize, Error> {
        let mut used = 0usize;
        for object in &self.objects {
            if object.present {
                used = used
                    .checked_add(usize::from(object.len))
                    .ok_or(Error::ArithmeticOverflow)?;
            }
        }
        Ok(used)
    }

    fn ensure_quota(&self, old_len: usize, new_len: usize, config: Config) -> Result<(), Error> {
        let without_old = self
            .used_bytes()?
            .checked_sub(old_len)
            .ok_or(Error::InvariantViolation)?;
        let proposed = without_old
            .checked_add(new_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if proposed > config.quota_bytes {
            return Err(Error::QuotaExceeded);
        }
        let with_reserve = proposed
            .checked_add(config.recovery_reserve_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        if with_reserve > config.quota_bytes {
            return Err(Error::RecoveryReserveProtected);
        }
        Ok(())
    }

    fn object_index(&self, handle: ObjectHandle) -> Result<usize, Error> {
        self.objects
            .iter()
            .position(|object| object.present && object.handle() == handle)
            .ok_or(Error::StaleHandle)
    }

    fn create(&mut self) -> Result<ObjectHandle, Error> {
        let index = self
            .objects
            .iter()
            .position(|object| !object.present)
            .ok_or(Error::ObjectCapacity)?;
        let next_id = self
            .next_object_id
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let next_generation = self
            .next_object_generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let handle = ObjectHandle {
            id: ObjectId(self.next_object_id),
            generation: Generation(self.next_object_generation),
        };
        self.next_object_id = next_id;
        self.next_object_generation = next_generation;
        self.objects[index] = ObjectSlot {
            present: true,
            id: handle.id,
            generation: handle.generation,
            len: 0,
            data: [0; MAX_OBJECT_BYTES],
        };
        Ok(handle)
    }

    fn replay_create(&mut self, handle: ObjectHandle) -> Result<(), Error> {
        if handle.id.get() != self.next_object_id
            || handle.generation.get() != self.next_object_generation
        {
            return Err(Error::CorruptRecoveryMetadata);
        }
        let index = self
            .objects
            .iter()
            .position(|object| !object.present)
            .ok_or(Error::ObjectCapacity)?;
        self.objects[index] = ObjectSlot {
            present: true,
            id: handle.id,
            generation: handle.generation,
            len: 0,
            data: [0; MAX_OBJECT_BYTES],
        };
        self.next_object_id = handle
            .id
            .get()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        self.next_object_generation = handle
            .generation
            .get()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    fn write(
        &mut self,
        handle: ObjectHandle,
        offset: u64,
        input: &[u8],
        config: Config,
    ) -> Result<(), Error> {
        if input.len() > MAX_IO_BYTES {
            return Err(Error::IoTooLarge);
        }
        let offset = usize::try_from(offset).map_err(|_| Error::OffsetOutOfRange)?;
        let end = offset
            .checked_add(input.len())
            .ok_or(Error::ArithmeticOverflow)?;
        if end > MAX_OBJECT_BYTES {
            return Err(Error::ObjectTooLarge);
        }
        let index = self.object_index(handle)?;
        let old_len = usize::from(self.objects[index].len);
        let new_len = old_len.max(end);
        self.ensure_quota(old_len, new_len, config)?;
        self.objects[index].data[offset..end].copy_from_slice(input);
        self.objects[index].len = u16::try_from(new_len).map_err(|_| Error::ObjectTooLarge)?;
        Ok(())
    }

    fn truncate(
        &mut self,
        handle: ObjectHandle,
        new_len: u64,
        config: Config,
    ) -> Result<(), Error> {
        let new_len = usize::try_from(new_len).map_err(|_| Error::ObjectTooLarge)?;
        if new_len > MAX_OBJECT_BYTES {
            return Err(Error::ObjectTooLarge);
        }
        let index = self.object_index(handle)?;
        let old_len = usize::from(self.objects[index].len);
        self.ensure_quota(old_len, new_len, config)?;
        if new_len < old_len {
            self.objects[index].data[new_len..old_len].fill(0);
        } else if new_len > old_len {
            self.objects[index].data[old_len..new_len].fill(0);
        }
        self.objects[index].len = u16::try_from(new_len).map_err(|_| Error::ObjectTooLarge)?;
        Ok(())
    }

    fn delete(&mut self, handle: ObjectHandle) -> Result<(), Error> {
        let index = self.object_index(handle)?;
        self.objects[index].present = false;
        self.objects[index].len = 0;
        self.objects[index].data.fill(0);
        for namespace in &mut self.namespaces {
            if namespace.present && namespace.handle == handle {
                *namespace = NamespaceSlot::EMPTY;
            }
        }
        Ok(())
    }

    fn bind(&mut self, name: Name, handle: ObjectHandle) -> Result<(), Error> {
        self.object_index(handle)?;
        if let Some(slot) = self
            .namespaces
            .iter_mut()
            .find(|slot| slot.present && slot.name == name)
        {
            slot.handle = handle;
            return Ok(());
        }
        let slot = self
            .namespaces
            .iter_mut()
            .find(|slot| !slot.present)
            .ok_or(Error::NamespaceCapacity)?;
        *slot = NamespaceSlot {
            present: true,
            name,
            handle,
        };
        Ok(())
    }

    fn lookup(&self, name: Name) -> Result<ObjectHandle, Error> {
        self.namespaces
            .iter()
            .find(|slot| slot.present && slot.name == name)
            .map(|slot| slot.handle)
            .ok_or(Error::NameNotFound)
    }

    fn read(&self, handle: ObjectHandle, offset: u64, output: &mut [u8]) -> Result<usize, Error> {
        let index = self.object_index(handle)?;
        let offset = usize::try_from(offset).map_err(|_| Error::OffsetOutOfRange)?;
        let len = usize::from(self.objects[index].len);
        if offset > len {
            return Err(Error::OffsetOutOfRange);
        }
        let count = output.len().min(len - offset);
        output[..count].copy_from_slice(&self.objects[index].data[offset..offset + count]);
        Ok(count)
    }

    fn checksum(&self) -> u64 {
        let mut checksum = IntegrityChecksum::new();
        checksum.push_u64(self.generation.get());
        checksum.push_u64(self.next_object_id);
        checksum.push_u64(self.next_object_generation);
        for object in &self.objects {
            checksum.push_bool(object.present);
            checksum.push_u64(object.id.get());
            checksum.push_u64(object.generation.get());
            checksum.push_u64(u64::from(object.len));
            checksum.push_bytes(&object.data);
        }
        for namespace in &self.namespaces {
            checksum.push_bool(namespace.present);
            checksum.push_bytes(&namespace.name.bytes);
            checksum.push_u64(u64::from(namespace.name.len));
            checksum.push_u64(namespace.handle.id.get());
            checksum.push_u64(namespace.handle.generation.get());
        }
        checksum.finish()
    }
}

#[derive(Clone, Copy)]
struct WorkingTransaction {
    id: TransactionId,
    deadline: Deadline,
    cancelled: bool,
    state: StoreState,
}

impl WorkingTransaction {
    fn check(&self, id: TransactionId, now: Tick) -> Result<(), Error> {
        if self.id != id {
            return Err(Error::StaleTransaction);
        }
        if now.0 >= self.deadline.0 {
            return Err(Error::DeadlineExceeded);
        }
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SnapshotSlot {
    present: bool,
    nonce: u64,
    state: StoreState,
}

impl SnapshotSlot {
    const EMPTY: Self = Self {
        present: false,
        nonce: 0,
        state: StoreState::empty(),
    };
}

#[derive(Clone, Copy)]
struct SnapshotSet {
    slots: [SnapshotSlot; MAX_SNAPSHOTS],
    next_nonce: u64,
}

impl SnapshotSet {
    const fn new() -> Self {
        Self {
            slots: [SnapshotSlot::EMPTY; MAX_SNAPSHOTS],
            next_nonce: 1,
        }
    }

    fn capture(&mut self, state: StoreState) -> Result<SnapshotId, Error> {
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.present)
            .ok_or(Error::SnapshotCapacity)?;
        let next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let nonce = self.next_nonce;
        self.next_nonce = next_nonce;
        self.slots[index] = SnapshotSlot {
            present: true,
            nonce,
            state,
        };
        Ok(SnapshotId {
            slot: u8::try_from(index).map_err(|_| Error::SnapshotCapacity)?,
            generation: state.generation,
            nonce,
        })
    }

    fn state(&self, id: SnapshotId) -> Result<&StoreState, Error> {
        let index = usize::from(id.slot);
        let slot = self.slots.get(index).ok_or(Error::StaleSnapshot)?;
        if !slot.present || slot.nonce != id.nonce || slot.state.generation != id.generation {
            return Err(Error::StaleSnapshot);
        }
        Ok(&slot.state)
    }

    fn gc(&mut self, retain_from: Generation) -> usize {
        let mut reclaimed = 0usize;
        for slot in &mut self.slots {
            if slot.present && slot.state.generation < retain_from {
                *slot = SnapshotSlot::EMPTY;
                reclaimed += 1;
            }
        }
        reclaimed
    }
}

pub trait TransactionalStore: Sized {
    fn new(config: Config) -> Result<Self, Error>;
    fn variant(&self) -> VariantId;
    fn generation(&self) -> Generation;
    fn begin(&mut self, now: Tick, deadline: Deadline) -> Result<TransactionId, Error>;
    fn create(&mut self, transaction: TransactionId, now: Tick) -> Result<ObjectHandle, Error>;
    fn write(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Error>;
    fn truncate(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
        new_len: u64,
    ) -> Result<(), Error>;
    fn delete(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
    ) -> Result<(), Error>;
    fn bind(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        name: Name,
        handle: ObjectHandle,
    ) -> Result<(), Error>;
    fn read(&self, handle: ObjectHandle, offset: u64, output: &mut [u8]) -> Result<usize, Error>;
    fn lookup(&self, name: Name) -> Result<ObjectHandle, Error>;
    fn commit(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        durability: Durability,
    ) -> Result<CommitReceipt, Error>;
    fn abort(&mut self, transaction: TransactionId) -> Result<(), Error>;
    fn cancel(&mut self, transaction: TransactionId) -> Result<(), Error>;
    fn snapshot(&mut self) -> Result<SnapshotId, Error>;
    fn read_snapshot(
        &self,
        snapshot: SnapshotId,
        handle: ObjectHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, Error>;
    fn gc(&mut self, retain_from: Generation) -> GcReport;
    #[cfg(test)]
    fn inject_fault(&mut self, fault: FaultPoint);
    #[cfg(test)]
    fn corrupt_pending_metadata(&mut self) -> Result<(), Error>;
    fn recover(&mut self) -> Result<RecoveryReport, Error>;
}

#[derive(Clone, Copy)]
struct Superblock {
    present: bool,
    magic: u64,
    generation: Generation,
    bank: u8,
    state_checksum: u64,
    descriptor_checksum: u64,
}

impl Superblock {
    const EMPTY: Self = Self {
        present: false,
        magic: 0,
        generation: Generation::ZERO,
        bank: 0,
        state_checksum: 0,
        descriptor_checksum: 0,
    };

    fn new(bank: usize, state: &StoreState) -> Result<Self, Error> {
        let bank = u8::try_from(bank).map_err(|_| Error::InvariantViolation)?;
        let state_checksum = state.checksum();
        let mut descriptor = Self {
            present: true,
            magic: SUPERBLOCK_MAGIC,
            generation: state.generation,
            bank,
            state_checksum,
            descriptor_checksum: 0,
        };
        descriptor.descriptor_checksum = descriptor.expected_checksum();
        Ok(descriptor)
    }

    fn expected_checksum(self) -> u64 {
        let mut checksum = IntegrityChecksum::new();
        checksum.push_bool(self.present);
        checksum.push_u64(self.magic);
        checksum.push_u64(self.generation.get());
        checksum.push_u64(u64::from(self.bank));
        checksum.push_u64(self.state_checksum);
        checksum.finish()
    }

    fn verify(self, bank: usize, state: &StoreState) -> bool {
        self.present
            && self.magic == SUPERBLOCK_MAGIC
            && usize::from(self.bank) == bank
            && self.generation == state.generation
            && self.state_checksum == state.checksum()
            && self.descriptor_checksum == self.expected_checksum()
    }
}

pub struct CowStore {
    config: Config,
    banks: [StoreState; 2],
    superblocks: [Superblock; 2],
    active_bank: usize,
    active: Option<WorkingTransaction>,
    next_transaction: u64,
    snapshots: SnapshotSet,
    fault: FaultPoint,
}

impl CowStore {
    fn committed(&self) -> &StoreState {
        &self.banks[self.active_bank]
    }

    fn check_transaction(&self, transaction: TransactionId, now: Tick) -> Result<(), Error> {
        self.active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .check(transaction, now)
    }

    fn working_mut(&mut self) -> Result<&mut WorkingTransaction, Error> {
        self.active.as_mut().ok_or(Error::NoActiveTransaction)
    }

    #[cfg(test)]
    fn inject_split_brain_for_test(&mut self) -> Result<(), Error> {
        let other = 1usize
            .checked_sub(self.active_bank)
            .ok_or(Error::InvariantViolation)?;
        let mut conflicting = *self.committed();
        conflicting.next_object_id = conflicting
            .next_object_id
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        self.banks[other] = conflicting;
        self.superblocks[other] = Superblock::new(other, &conflicting)?;
        Ok(())
    }
}

impl TransactionalStore for CowStore {
    fn new(config: Config) -> Result<Self, Error> {
        Config::new(config.quota_bytes, config.recovery_reserve_bytes)?;
        let state = StoreState::empty();
        let first = Superblock::new(0, &state)?;
        Ok(Self {
            config,
            banks: [state; 2],
            superblocks: [first, Superblock::EMPTY],
            active_bank: 0,
            active: None,
            next_transaction: 1,
            snapshots: SnapshotSet::new(),
            fault: FaultPoint::None,
        })
    }

    fn variant(&self) -> VariantId {
        VariantId::Cow
    }

    fn generation(&self) -> Generation {
        self.committed().generation
    }

    fn begin(&mut self, now: Tick, deadline: Deadline) -> Result<TransactionId, Error> {
        if self.active.is_some() {
            return Err(Error::TransactionBusy);
        }
        if now.0 >= deadline.0 {
            return Err(Error::DeadlineExceeded);
        }
        let next = self
            .next_transaction
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let id = TransactionId {
            nonce: self.next_transaction,
            base_generation: self.generation(),
        };
        self.next_transaction = next;
        let state = *self.committed();
        self.active = Some(WorkingTransaction {
            id,
            deadline,
            cancelled: false,
            state,
        });
        Ok(id)
    }

    fn create(&mut self, transaction: TransactionId, now: Tick) -> Result<ObjectHandle, Error> {
        self.check_transaction(transaction, now)?;
        self.working_mut()?.state.create()
    }

    fn write(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        let config = self.config;
        self.working_mut()?
            .state
            .write(handle, offset, input, config)
    }

    fn truncate(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
        new_len: u64,
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        let config = self.config;
        self.working_mut()?.state.truncate(handle, new_len, config)
    }

    fn delete(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        self.working_mut()?.state.delete(handle)
    }

    fn bind(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        name: Name,
        handle: ObjectHandle,
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        self.working_mut()?.state.bind(name, handle)
    }

    fn read(&self, handle: ObjectHandle, offset: u64, output: &mut [u8]) -> Result<usize, Error> {
        self.committed().read(handle, offset, output)
    }

    fn lookup(&self, name: Name) -> Result<ObjectHandle, Error> {
        self.committed().lookup(name)
    }

    fn commit(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        durability: Durability,
    ) -> Result<CommitReceipt, Error> {
        self.check_transaction(transaction, now)?;
        let mut candidate = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        candidate.generation = transaction.base_generation.next()?;
        let state_checksum = candidate.checksum();
        let commit_durability = validate_durability(
            durability,
            VariantId::Cow,
            transaction,
            candidate.generation,
            state_checksum,
        )?;
        let inactive = 1usize
            .checked_sub(self.active_bank)
            .ok_or(Error::InvariantViolation)?;
        self.superblocks[inactive] = Superblock::EMPTY;
        self.banks[inactive] = candidate;
        let fault = self.fault;
        self.fault = FaultPoint::None;
        self.active = None;
        if fault == FaultPoint::BeforeCommitReceipt {
            return Err(Error::Interrupted(fault));
        }
        let mut descriptor = Superblock::new(inactive, &candidate)?;
        if fault == FaultPoint::CorruptCommitReceipt {
            descriptor.descriptor_checksum ^= 1;
        }
        self.superblocks[inactive] = descriptor;
        if matches!(
            fault,
            FaultPoint::AfterCommitReceipt | FaultPoint::CorruptCommitReceipt
        ) {
            return Err(Error::Interrupted(fault));
        }
        self.active_bank = inactive;
        Ok(CommitReceipt::new(
            VariantId::Cow,
            candidate.generation,
            state_checksum,
            commit_durability,
        ))
    }

    fn abort(&mut self, transaction: TransactionId) -> Result<(), Error> {
        let current = self.active.as_ref().ok_or(Error::NoActiveTransaction)?;
        if current.id != transaction {
            return Err(Error::StaleTransaction);
        }
        self.active = None;
        Ok(())
    }

    fn cancel(&mut self, transaction: TransactionId) -> Result<(), Error> {
        let current = self.active.as_mut().ok_or(Error::NoActiveTransaction)?;
        if current.id != transaction {
            return Err(Error::StaleTransaction);
        }
        current.cancelled = true;
        Ok(())
    }

    fn snapshot(&mut self) -> Result<SnapshotId, Error> {
        let state = *self.committed();
        self.snapshots.capture(state)
    }

    fn read_snapshot(
        &self,
        snapshot: SnapshotId,
        handle: ObjectHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.snapshots.state(snapshot)?.read(handle, offset, output)
    }

    fn gc(&mut self, retain_from: Generation) -> GcReport {
        let snapshots_reclaimed = self.snapshots.gc(retain_from);
        let mut recovery_records_reclaimed = 0usize;
        for (index, descriptor) in self.superblocks.iter_mut().enumerate() {
            if index != self.active_bank
                && descriptor.present
                && descriptor.generation < retain_from
            {
                *descriptor = Superblock::EMPTY;
                recovery_records_reclaimed += 1;
            }
        }
        GcReport {
            snapshots_reclaimed,
            recovery_records_reclaimed,
        }
    }

    #[cfg(test)]
    fn inject_fault(&mut self, fault: FaultPoint) {
        self.fault = fault;
    }

    #[cfg(test)]
    fn corrupt_pending_metadata(&mut self) -> Result<(), Error> {
        let current = self.generation();
        let pending = self
            .superblocks
            .iter_mut()
            .find(|descriptor| descriptor.present && descriptor.generation > current)
            .ok_or(Error::NoPendingRecovery)?;
        pending.descriptor_checksum ^= 1;
        Ok(())
    }

    fn recover(&mut self) -> Result<RecoveryReport, Error> {
        self.active = None;
        self.fault = FaultPoint::None;
        let mut selected: Option<(usize, Generation, u64)> = None;
        let mut rejected = 0usize;
        let mut changed = false;
        let descriptors = self.superblocks;
        for (index, descriptor) in descriptors.into_iter().enumerate() {
            if !descriptor.present {
                continue;
            }
            if descriptor.verify(index, &self.banks[index]) {
                if let Some((_, generation, state_checksum)) = selected {
                    if descriptor.generation == generation
                        && descriptor.state_checksum != state_checksum
                    {
                        return Err(Error::CorruptRecoveryMetadata);
                    }
                    if descriptor.generation > generation {
                        selected = Some((index, descriptor.generation, descriptor.state_checksum));
                    }
                } else {
                    selected = Some((index, descriptor.generation, descriptor.state_checksum));
                }
            } else {
                self.superblocks[index] = Superblock::EMPTY;
                rejected += 1;
                changed = true;
            }
        }
        let (bank, generation, _) = selected.ok_or(Error::CorruptRecoveryMetadata)?;
        let selected_state = self.banks[bank];
        let mut discarded_uncommitted = false;
        let bank_states = self.banks;
        for (index, state) in bank_states.into_iter().enumerate() {
            if !self.superblocks[index].present && state.generation > generation {
                self.banks[index] = selected_state;
                discarded_uncommitted = true;
                changed = true;
            }
        }
        if bank != self.active_bank {
            self.active_bank = bank;
            changed = true;
        }
        Ok(RecoveryReport {
            selected_generation: generation,
            changed,
            rejected_corrupt_records: rejected,
            discarded_uncommitted,
        })
    }
}

#[derive(Clone, Copy)]
struct WritePayload {
    len: u8,
    bytes: [u8; MAX_IO_BYTES],
}

impl WritePayload {
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0; MAX_IO_BYTES],
    };

    fn new(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_IO_BYTES {
            return Err(Error::IoTooLarge);
        }
        let mut payload = Self::EMPTY;
        payload.bytes[..input.len()].copy_from_slice(input);
        payload.len = u8::try_from(input.len()).map_err(|_| Error::IoTooLarge)?;
        Ok(payload)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy)]
enum WalRecord {
    Empty,
    Begin {
        transaction: TransactionId,
    },
    Create {
        handle: ObjectHandle,
    },
    Write {
        handle: ObjectHandle,
        offset: u64,
        payload: WritePayload,
    },
    Truncate {
        handle: ObjectHandle,
        new_len: u64,
    },
    Delete {
        handle: ObjectHandle,
    },
    Bind {
        name: Name,
        handle: ObjectHandle,
    },
    Commit {
        generation: Generation,
        state_checksum: u64,
    },
}

impl WalRecord {
    fn checksum(self) -> u64 {
        let mut checksum = IntegrityChecksum::new();
        match self {
            Self::Empty => checksum.push_u64(0),
            Self::Begin { transaction } => {
                checksum.push_u64(1);
                checksum.push_u64(transaction.nonce);
                checksum.push_u64(transaction.base_generation.get());
            }
            Self::Create { handle } => {
                checksum.push_u64(2);
                checksum.push_u64(handle.id.get());
                checksum.push_u64(handle.generation.get());
            }
            Self::Write {
                handle,
                offset,
                payload,
            } => {
                checksum.push_u64(3);
                checksum.push_u64(handle.id.get());
                checksum.push_u64(handle.generation.get());
                checksum.push_u64(offset);
                checksum.push_bytes(payload.as_bytes());
            }
            Self::Truncate { handle, new_len } => {
                checksum.push_u64(4);
                checksum.push_u64(handle.id.get());
                checksum.push_u64(handle.generation.get());
                checksum.push_u64(new_len);
            }
            Self::Delete { handle } => {
                checksum.push_u64(5);
                checksum.push_u64(handle.id.get());
                checksum.push_u64(handle.generation.get());
            }
            Self::Bind { name, handle } => {
                checksum.push_u64(6);
                checksum.push_bytes(name.as_bytes());
                checksum.push_u64(handle.id.get());
                checksum.push_u64(handle.generation.get());
            }
            Self::Commit {
                generation,
                state_checksum,
            } => {
                checksum.push_u64(7);
                checksum.push_u64(generation.get());
                checksum.push_u64(state_checksum);
            }
        }
        checksum.finish()
    }
}

#[derive(Clone, Copy)]
struct WalEntry {
    present: bool,
    record: WalRecord,
    checksum: u64,
}

impl WalEntry {
    const EMPTY: Self = Self {
        present: false,
        record: WalRecord::Empty,
        checksum: 0,
    };

    fn new(record: WalRecord) -> Self {
        Self {
            present: true,
            checksum: record.checksum(),
            record,
        }
    }

    fn verify(self) -> bool {
        self.present && self.checksum == self.record.checksum()
    }
}

pub struct WalStore {
    config: Config,
    base: StoreState,
    active: Option<WorkingTransaction>,
    next_transaction: u64,
    snapshots: SnapshotSet,
    log: [WalEntry; MAX_WAL_RECORDS],
    log_len: usize,
    fault: FaultPoint,
}

impl WalStore {
    fn check_transaction(&self, transaction: TransactionId, now: Tick) -> Result<(), Error> {
        self.active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .check(transaction, now)
    }

    fn append(&mut self, record: WalRecord) -> Result<(), Error> {
        let slot = self.log.get_mut(self.log_len).ok_or(Error::WalFull)?;
        *slot = WalEntry::new(record);
        self.log_len = self
            .log_len
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    fn clear_log(&mut self) {
        for entry in &mut self.log[..self.log_len] {
            *entry = WalEntry::EMPTY;
        }
        self.log_len = 0;
    }

    fn replace_working_state(&mut self, state: StoreState) -> Result<(), Error> {
        self.active
            .as_mut()
            .ok_or(Error::NoActiveTransaction)?
            .state = state;
        Ok(())
    }

    fn reject_log(&mut self, rejected: usize, discarded_uncommitted: bool) -> RecoveryReport {
        self.clear_log();
        RecoveryReport {
            selected_generation: self.base.generation,
            changed: true,
            rejected_corrupt_records: rejected,
            discarded_uncommitted,
        }
    }
}

impl TransactionalStore for WalStore {
    fn new(config: Config) -> Result<Self, Error> {
        Config::new(config.quota_bytes, config.recovery_reserve_bytes)?;
        Ok(Self {
            config,
            base: StoreState::empty(),
            active: None,
            next_transaction: 1,
            snapshots: SnapshotSet::new(),
            log: [WalEntry::EMPTY; MAX_WAL_RECORDS],
            log_len: 0,
            fault: FaultPoint::None,
        })
    }

    fn variant(&self) -> VariantId {
        VariantId::Wal
    }

    fn generation(&self) -> Generation {
        self.base.generation
    }

    fn begin(&mut self, now: Tick, deadline: Deadline) -> Result<TransactionId, Error> {
        if self.active.is_some() {
            return Err(Error::TransactionBusy);
        }
        if self.log_len != 0 {
            return Err(Error::RecoveryRequired);
        }
        if now.0 >= deadline.0 {
            return Err(Error::DeadlineExceeded);
        }
        let next = self
            .next_transaction
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let id = TransactionId {
            nonce: self.next_transaction,
            base_generation: self.base.generation,
        };
        self.append(WalRecord::Begin { transaction: id })?;
        self.next_transaction = next;
        self.active = Some(WorkingTransaction {
            id,
            deadline,
            cancelled: false,
            state: self.base,
        });
        Ok(id)
    }

    fn create(&mut self, transaction: TransactionId, now: Tick) -> Result<ObjectHandle, Error> {
        self.check_transaction(transaction, now)?;
        let mut state = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        let handle = state.create()?;
        self.append(WalRecord::Create { handle })?;
        self.replace_working_state(state)?;
        Ok(handle)
    }

    fn write(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        let payload = WritePayload::new(input)?;
        let mut state = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        state.write(handle, offset, input, self.config)?;
        self.append(WalRecord::Write {
            handle,
            offset,
            payload,
        })?;
        self.replace_working_state(state)
    }

    fn truncate(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
        new_len: u64,
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        let mut state = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        state.truncate(handle, new_len, self.config)?;
        self.append(WalRecord::Truncate { handle, new_len })?;
        self.replace_working_state(state)
    }

    fn delete(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        handle: ObjectHandle,
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        let mut state = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        state.delete(handle)?;
        self.append(WalRecord::Delete { handle })?;
        self.replace_working_state(state)
    }

    fn bind(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        name: Name,
        handle: ObjectHandle,
    ) -> Result<(), Error> {
        self.check_transaction(transaction, now)?;
        let mut state = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        state.bind(name, handle)?;
        self.append(WalRecord::Bind { name, handle })?;
        self.replace_working_state(state)
    }

    fn read(&self, handle: ObjectHandle, offset: u64, output: &mut [u8]) -> Result<usize, Error> {
        self.base.read(handle, offset, output)
    }

    fn lookup(&self, name: Name) -> Result<ObjectHandle, Error> {
        self.base.lookup(name)
    }

    fn commit(
        &mut self,
        transaction: TransactionId,
        now: Tick,
        durability: Durability,
    ) -> Result<CommitReceipt, Error> {
        self.check_transaction(transaction, now)?;
        let mut candidate = self
            .active
            .as_ref()
            .ok_or(Error::NoActiveTransaction)?
            .state;
        candidate.generation = transaction.base_generation.next()?;
        let state_checksum = candidate.checksum();
        let commit_durability = validate_durability(
            durability,
            VariantId::Wal,
            transaction,
            candidate.generation,
            state_checksum,
        )?;
        let fault = self.fault;
        self.fault = FaultPoint::None;
        if fault == FaultPoint::BeforeCommitReceipt {
            self.active = None;
            return Err(Error::Interrupted(fault));
        }
        self.append(WalRecord::Commit {
            generation: candidate.generation,
            state_checksum,
        })?;
        self.active = None;
        if fault == FaultPoint::CorruptCommitReceipt {
            let last = self
                .log_len
                .checked_sub(1)
                .ok_or(Error::InvariantViolation)?;
            self.log[last].checksum ^= 1;
        }
        if matches!(
            fault,
            FaultPoint::AfterCommitReceipt | FaultPoint::CorruptCommitReceipt
        ) {
            return Err(Error::Interrupted(fault));
        }
        self.base = candidate;
        self.clear_log();
        Ok(CommitReceipt::new(
            VariantId::Wal,
            candidate.generation,
            state_checksum,
            commit_durability,
        ))
    }

    fn abort(&mut self, transaction: TransactionId) -> Result<(), Error> {
        let current = self.active.as_ref().ok_or(Error::NoActiveTransaction)?;
        if current.id != transaction {
            return Err(Error::StaleTransaction);
        }
        self.active = None;
        self.clear_log();
        Ok(())
    }

    fn cancel(&mut self, transaction: TransactionId) -> Result<(), Error> {
        let current = self.active.as_mut().ok_or(Error::NoActiveTransaction)?;
        if current.id != transaction {
            return Err(Error::StaleTransaction);
        }
        current.cancelled = true;
        Ok(())
    }

    fn snapshot(&mut self) -> Result<SnapshotId, Error> {
        self.snapshots.capture(self.base)
    }

    fn read_snapshot(
        &self,
        snapshot: SnapshotId,
        handle: ObjectHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.snapshots.state(snapshot)?.read(handle, offset, output)
    }

    fn gc(&mut self, retain_from: Generation) -> GcReport {
        GcReport {
            snapshots_reclaimed: self.snapshots.gc(retain_from),
            recovery_records_reclaimed: 0,
        }
    }

    #[cfg(test)]
    fn inject_fault(&mut self, fault: FaultPoint) {
        self.fault = fault;
    }

    #[cfg(test)]
    fn corrupt_pending_metadata(&mut self) -> Result<(), Error> {
        let last = self
            .log_len
            .checked_sub(1)
            .ok_or(Error::NoPendingRecovery)?;
        self.log[last].checksum ^= 1;
        Ok(())
    }

    fn recover(&mut self) -> Result<RecoveryReport, Error> {
        self.active = None;
        self.fault = FaultPoint::None;
        if self.log_len == 0 {
            return Ok(RecoveryReport {
                selected_generation: self.base.generation,
                changed: false,
                rejected_corrupt_records: 0,
                discarded_uncommitted: false,
            });
        }
        if self.log[..self.log_len].iter().any(|entry| !entry.verify()) {
            return Ok(self.reject_log(1, true));
        }
        let first = self.log[0].record;
        let transaction = match first {
            WalRecord::Begin { transaction }
                if transaction.base_generation == self.base.generation =>
            {
                transaction
            }
            _ => return Ok(self.reject_log(1, true)),
        };
        let mut replayed = self.base;
        let mut committed = false;
        let mut index = 1usize;
        while index < self.log_len {
            let entry = self.log[index];
            match entry.record {
                WalRecord::Empty | WalRecord::Begin { .. } => {
                    return Ok(self.reject_log(1, true));
                }
                WalRecord::Create { handle } => {
                    if replayed.replay_create(handle).is_err() {
                        return Ok(self.reject_log(1, true));
                    }
                }
                WalRecord::Write {
                    handle,
                    offset,
                    payload,
                } => {
                    if replayed
                        .write(handle, offset, payload.as_bytes(), self.config)
                        .is_err()
                    {
                        return Ok(self.reject_log(1, true));
                    }
                }
                WalRecord::Truncate { handle, new_len } => {
                    if replayed.truncate(handle, new_len, self.config).is_err() {
                        return Ok(self.reject_log(1, true));
                    }
                }
                WalRecord::Delete { handle } => {
                    if replayed.delete(handle).is_err() {
                        return Ok(self.reject_log(1, true));
                    }
                }
                WalRecord::Bind { name, handle } => {
                    if replayed.bind(name, handle).is_err() {
                        return Ok(self.reject_log(1, true));
                    }
                }
                WalRecord::Commit {
                    generation,
                    state_checksum,
                } => {
                    if committed
                        || generation != transaction.base_generation.next()?
                        || entry.checksum != entry.record.checksum()
                    {
                        return Ok(self.reject_log(1, true));
                    }
                    replayed.generation = generation;
                    if replayed.checksum() != state_checksum {
                        return Ok(self.reject_log(1, true));
                    }
                    committed = true;
                }
            }
            if committed && index.checked_add(1).ok_or(Error::ArithmeticOverflow)? != self.log_len {
                return Ok(self.reject_log(1, true));
            }
            index = index.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        }
        if !committed {
            self.clear_log();
            return Ok(RecoveryReport {
                selected_generation: self.base.generation,
                changed: true,
                rejected_corrupt_records: 0,
                discarded_uncommitted: true,
            });
        }
        self.base = replayed;
        self.clear_log();
        Ok(RecoveryReport {
            selected_generation: self.base.generation,
            changed: true,
            rejected_corrupt_records: 0,
            discarded_uncommitted: false,
        })
    }
}

pub fn storage_metrics() -> StorageMetrics {
    StorageMetrics {
        state_bytes: core::mem::size_of::<StoreState>(),
        cow_store_bytes: core::mem::size_of::<CowStore>(),
        wal_store_bytes: core::mem::size_of::<WalStore>(),
        cow_max_recovery_steps: COW_MAX_RECOVERY_STEPS,
        wal_max_recovery_steps: WAL_MAX_RECOVERY_STEPS,
    }
}

#[cfg(test)]
mod tests;
