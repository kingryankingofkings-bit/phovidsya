use super::*;

fn default_config() -> Config {
    Config::new(512, 64).expect("valid fixed-capacity test config")
}

fn new_store<S: TransactionalStore>() -> S {
    S::new(default_config()).expect("store construction")
}

fn commit_bytes<S: TransactionalStore>(bytes: &[u8]) -> (S, ObjectHandle) {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(0), Deadline::new(10)).expect("begin");
    let handle = store.create(transaction, Tick::new(0)).expect("create");
    store
        .write(transaction, Tick::new(0), handle, 0, bytes)
        .expect("write");
    store
        .commit(transaction, Tick::new(0), Durability::MemoryOnly)
        .expect("commit");
    (store, handle)
}

fn read_exact<S: TransactionalStore>(store: &S, handle: ObjectHandle, expected: &[u8]) {
    let mut output = [0u8; MAX_OBJECT_BYTES];
    let count = store.read(handle, 0, &mut output).expect("read");
    assert_eq!(&output[..count], expected);
}

fn round_trip_create_write_read_bind<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(1), Deadline::new(10)).expect("begin");
    let handle = store.create(transaction, Tick::new(1)).expect("create");
    store
        .write(transaction, Tick::new(2), handle, 0, b"hello")
        .expect("write");
    let name = Name::new(b"model").expect("name");
    store
        .bind(transaction, Tick::new(2), name, handle)
        .expect("bind");
    let receipt = store
        .commit(transaction, Tick::new(3), Durability::MemoryOnly)
        .expect("commit");
    assert!(receipt.is_valid());
    assert_eq!(receipt.generation(), Generation(1));
    assert_eq!(store.lookup(name), Ok(handle));
    read_exact(&store, handle, b"hello");
}

fn truncate_delete_and_stale_handle<S: TransactionalStore>() {
    let (mut store, handle) = commit_bytes::<S>(b"abcdef");
    let name = Name::new(b"object").expect("name");
    let bind_transaction = store
        .begin(Tick::new(1), Deadline::new(10))
        .expect("begin bind");
    store
        .bind(bind_transaction, Tick::new(1), name, handle)
        .expect("bind");
    store
        .truncate(bind_transaction, Tick::new(1), handle, 3)
        .expect("truncate");
    store
        .commit(bind_transaction, Tick::new(1), Durability::MemoryOnly)
        .expect("commit truncate");
    read_exact(&store, handle, b"abc");

    let delete_transaction = store
        .begin(Tick::new(2), Deadline::new(10))
        .expect("begin delete");
    store
        .delete(delete_transaction, Tick::new(2), handle)
        .expect("delete");
    store
        .commit(delete_transaction, Tick::new(2), Durability::MemoryOnly)
        .expect("commit delete");
    let mut output = [0u8; 8];
    assert_eq!(store.read(handle, 0, &mut output), Err(Error::StaleHandle));
    assert_eq!(store.lookup(name), Err(Error::NameNotFound));
}

fn abort_does_not_publish<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(0), Deadline::new(10)).expect("begin");
    let handle = store.create(transaction, Tick::new(0)).expect("create");
    store
        .write(transaction, Tick::new(0), handle, 0, b"uncommitted")
        .expect("write");
    store.abort(transaction).expect("abort");
    assert_eq!(store.generation(), Generation::ZERO);
    let mut output = [0u8; 16];
    assert_eq!(store.read(handle, 0, &mut output), Err(Error::StaleHandle));
    assert_eq!(
        store.recover().expect("recover").selected_generation,
        Generation::ZERO
    );
}

fn durability_is_explicit<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(0), Deadline::new(10)).expect("begin");
    let handle = store.create(transaction, Tick::new(0)).expect("create");
    store
        .write(transaction, Tick::new(0), handle, 0, b"durable")
        .expect("write");
    let receipt = store
        .commit(transaction, Tick::new(1), Durability::MemoryOnly)
        .expect("explicit memory-only commit");
    assert!(receipt.is_valid());
    assert_eq!(receipt.durability(), CommitDurability::MemoryOnly);
    read_exact(&store, handle, b"durable");
}

fn cancellation_and_deadline<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(0), Deadline::new(1)).expect("begin");
    let handle = store.create(transaction, Tick::new(0)).expect("create");
    assert_eq!(
        store.write(transaction, Tick::new(2), handle, 0, b"late"),
        Err(Error::DeadlineExceeded)
    );
    store.cancel(transaction).expect("cancel");
    assert_eq!(
        store.write(transaction, Tick::new(0), handle, 0, b"cancelled"),
        Err(Error::Cancelled)
    );
    store.abort(transaction).expect("abort cancelled");
    assert_eq!(
        store.begin(Tick::new(5), Deadline::new(4)),
        Err(Error::DeadlineExceeded)
    );
    assert_eq!(
        store.begin(Tick::new(5), Deadline::new(5)),
        Err(Error::DeadlineExceeded)
    );

    let mut operation_store = new_store::<S>();
    let operation = operation_store
        .begin(Tick::new(0), Deadline::new(2))
        .expect("begin operation deadline");
    let operation_handle = operation_store
        .create(operation, Tick::new(0))
        .expect("create operation deadline");
    assert_eq!(
        operation_store.write(operation, Tick::new(2), operation_handle, 0, b"exact"),
        Err(Error::DeadlineExceeded)
    );
    operation_store
        .abort(operation)
        .expect("abort expired operation");

    let mut commit_store = new_store::<S>();
    let commit_transaction = commit_store
        .begin(Tick::new(0), Deadline::new(2))
        .expect("begin commit deadline");
    commit_store
        .create(commit_transaction, Tick::new(0))
        .expect("create commit deadline");
    assert_eq!(
        commit_store.commit(commit_transaction, Tick::new(2), Durability::MemoryOnly),
        Err(Error::DeadlineExceeded)
    );
    commit_store
        .abort(commit_transaction)
        .expect("abort expired commit");
}

fn quota_and_recovery_reserve<S: TransactionalStore>() {
    let mut store = S::new(Config::new(100, 16).expect("config")).expect("store");
    let transaction = store.begin(Tick::new(0), Deadline::new(10)).expect("begin");
    let handle = store.create(transaction, Tick::new(0)).expect("create");
    let chunk = [7u8; MAX_IO_BYTES];
    store
        .write(transaction, Tick::new(0), handle, 0, &chunk)
        .expect("first bounded write");
    assert_eq!(
        store.write(transaction, Tick::new(0), handle, 64, &[8u8; 21]),
        Err(Error::RecoveryReserveProtected)
    );
    store
        .write(transaction, Tick::new(0), handle, 64, &[8u8; 20])
        .expect("reserve-respecting write");
    store
        .commit(transaction, Tick::new(0), Durability::MemoryOnly)
        .expect("commit");

    let mut quota_store = S::new(Config::new(64, 0).expect("config")).expect("store");
    let first = quota_store
        .begin(Tick::new(0), Deadline::new(10))
        .expect("begin");
    let quota_handle = quota_store.create(first, Tick::new(0)).expect("create");
    quota_store
        .write(first, Tick::new(0), quota_handle, 0, &chunk)
        .expect("fill quota");
    quota_store
        .commit(first, Tick::new(0), Durability::MemoryOnly)
        .expect("commit full quota");
    let second = quota_store
        .begin(Tick::new(1), Deadline::new(10))
        .expect("begin second");
    assert_eq!(
        quota_store.write(second, Tick::new(1), quota_handle, 64, b"x"),
        Err(Error::QuotaExceeded)
    );
    quota_store.abort(second).expect("abort");
}

fn length_offset_and_overflow<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(0), Deadline::new(10)).expect("begin");
    let handle = store.create(transaction, Tick::new(0)).expect("create");
    assert_eq!(
        store.write(
            transaction,
            Tick::new(0),
            handle,
            0,
            &[0u8; MAX_IO_BYTES + 1]
        ),
        Err(Error::IoTooLarge)
    );
    assert_eq!(
        store.write(transaction, Tick::new(0), handle, u64::MAX, b"x"),
        Err(Error::ArithmeticOverflow)
    );
    assert_eq!(
        store.truncate(
            transaction,
            Tick::new(0),
            handle,
            (MAX_OBJECT_BYTES as u64) + 1,
        ),
        Err(Error::ObjectTooLarge)
    );
    assert_eq!(Name::new(b""), Err(Error::InvalidName));
    assert_eq!(Name::new(b"bad/name"), Err(Error::InvalidName));
    assert_eq!(Name::new(b"bad\\name"), Err(Error::InvalidName));
    assert_eq!(Name::new(b"."), Err(Error::InvalidName));
    assert_eq!(Name::new(b".."), Err(Error::InvalidName));
    assert_eq!(Name::new(b"trailing."), Err(Error::InvalidName));
    assert_eq!(Name::new(b"trailing "), Err(Error::InvalidName));
    assert_eq!(Name::new(b"control\n"), Err(Error::InvalidName));
    store.abort(transaction).expect("abort");
}

fn torn_commit_before_receipt_recovers_old_generation<S: TransactionalStore>() {
    let (mut store, handle) = commit_bytes::<S>(b"old");
    let transaction = store.begin(Tick::new(1), Deadline::new(10)).expect("begin");
    store
        .write(transaction, Tick::new(1), handle, 0, b"new")
        .expect("write");
    store.inject_fault(FaultPoint::BeforeCommitReceipt);
    assert_eq!(
        store.commit(transaction, Tick::new(1), Durability::MemoryOnly,),
        Err(Error::Interrupted(FaultPoint::BeforeCommitReceipt))
    );
    let report = store.recover().expect("recover old generation");
    assert_eq!(report.selected_generation, Generation(1));
    assert!(report.discarded_uncommitted);
    read_exact(&store, handle, b"old");
}

fn interrupted_after_receipt_recovers_new_generation_idempotently<S: TransactionalStore>() {
    let (mut store, handle) = commit_bytes::<S>(b"old");
    let transaction = store.begin(Tick::new(1), Deadline::new(10)).expect("begin");
    store
        .write(transaction, Tick::new(1), handle, 0, b"new")
        .expect("write");
    store.inject_fault(FaultPoint::AfterCommitReceipt);
    assert_eq!(
        store.commit(transaction, Tick::new(1), Durability::MemoryOnly,),
        Err(Error::Interrupted(FaultPoint::AfterCommitReceipt))
    );
    assert_eq!(store.generation(), Generation(1));
    let first = store.recover().expect("recover new generation");
    assert_eq!(first.selected_generation, Generation(2));
    assert!(first.changed);
    read_exact(&store, handle, b"new");
    let second = store.recover().expect("idempotent recovery");
    assert_eq!(second.selected_generation, Generation(2));
    assert!(!second.changed);
    read_exact(&store, handle, b"new");
}

fn corrupt_pending_metadata_is_rejected<S: TransactionalStore>() {
    let (mut store, handle) = commit_bytes::<S>(b"old");
    let transaction = store.begin(Tick::new(1), Deadline::new(10)).expect("begin");
    store
        .write(transaction, Tick::new(1), handle, 0, b"bad")
        .expect("write");
    store.inject_fault(FaultPoint::AfterCommitReceipt);
    assert_eq!(
        store.commit(transaction, Tick::new(1), Durability::MemoryOnly,),
        Err(Error::Interrupted(FaultPoint::AfterCommitReceipt))
    );
    store
        .corrupt_pending_metadata()
        .expect("corrupt pending metadata");
    let report = store.recover().expect("reject corrupt metadata");
    assert_eq!(report.selected_generation, Generation(1));
    assert_eq!(report.rejected_corrupt_records, 1);
    assert!(report.discarded_uncommitted);
    read_exact(&store, handle, b"old");
    let second = store.recover().expect("idempotent repaired recovery");
    assert_eq!(second.rejected_corrupt_records, 0);
    assert!(!second.changed);
}

fn snapshot_and_gc<S: TransactionalStore>() {
    let (mut store, handle) = commit_bytes::<S>(b"one");
    let snapshot = store.snapshot().expect("snapshot");
    let transaction = store.begin(Tick::new(1), Deadline::new(10)).expect("begin");
    store
        .write(transaction, Tick::new(1), handle, 0, b"two")
        .expect("write");
    store
        .commit(transaction, Tick::new(1), Durability::MemoryOnly)
        .expect("commit");
    read_exact(&store, handle, b"two");
    let mut output = [0u8; 8];
    let count = store
        .read_snapshot(snapshot, handle, 0, &mut output)
        .expect("snapshot read");
    assert_eq!(&output[..count], b"one");
    let report = store.gc(Generation(2));
    assert_eq!(report.snapshots_reclaimed, 1);
    assert_eq!(
        store.read_snapshot(snapshot, handle, 0, &mut output),
        Err(Error::StaleSnapshot)
    );
}

fn stale_transaction_is_rejected<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let old = store
        .begin(Tick::new(0), Deadline::new(10))
        .expect("begin old");
    store.abort(old).expect("abort old");
    let current = store
        .begin(Tick::new(1), Deadline::new(10))
        .expect("begin current");
    assert_eq!(
        store.create(old, Tick::new(1)),
        Err(Error::StaleTransaction)
    );
    store.abort(current).expect("abort current");
}

fn commit_receipt_checksum_detects_corruption<S: TransactionalStore>() {
    let mut store = new_store::<S>();
    let transaction = store.begin(Tick::new(0), Deadline::new(10)).expect("begin");
    store.create(transaction, Tick::new(0)).expect("create");
    let mut receipt = store
        .commit(transaction, Tick::new(0), Durability::MemoryOnly)
        .expect("commit");
    assert!(receipt.is_valid());
    receipt.descriptor_checksum ^= 1;
    assert!(!receipt.is_valid());
}

fn common_acceptance_suite<S: TransactionalStore>() {
    round_trip_create_write_read_bind::<S>();
    truncate_delete_and_stale_handle::<S>();
    abort_does_not_publish::<S>();
    durability_is_explicit::<S>();
    cancellation_and_deadline::<S>();
    quota_and_recovery_reserve::<S>();
    length_offset_and_overflow::<S>();
    torn_commit_before_receipt_recovers_old_generation::<S>();
    interrupted_after_receipt_recovers_new_generation_idempotently::<S>();
    corrupt_pending_metadata_is_rejected::<S>();
    snapshot_and_gc::<S>();
    stale_transaction_is_rejected::<S>();
    commit_receipt_checksum_detects_corruption::<S>();
}

#[test]
fn cow_equal_generation_conflict_fails_closed() {
    let (mut store, _) = commit_bytes::<CowStore>(b"authoritative");
    store
        .inject_split_brain_for_test()
        .expect("inject test-only equal-generation conflict");
    assert_eq!(store.recover(), Err(Error::CorruptRecoveryMetadata));
    assert_eq!(store.recover(), Err(Error::CorruptRecoveryMetadata));
}

#[test]
fn synthetic_barrier_receipt_is_bound_to_variant_transaction_generation_and_state() {
    let mut cow = new_store::<CowStore>();
    let cow_transaction = cow
        .begin(Tick::new(0), Deadline::new(10))
        .expect("begin cow");
    cow.create(cow_transaction, Tick::new(0))
        .expect("create cow");
    let mut cow_candidate = cow.active.expect("working cow").state;
    cow_candidate.generation = cow_transaction
        .base_generation
        .next()
        .expect("next cow generation");
    let receipt = BarrierReceipt::synthetic_for_test(
        VariantId::Cow,
        cow_transaction,
        cow_candidate.generation,
        cow_candidate.checksum(),
        7,
    );
    let committed = cow
        .commit(
            cow_transaction,
            Tick::new(1),
            Durability::ExternalBarrier(receipt),
        )
        .expect("synthetic bound barrier accepted only in unit test");
    assert_eq!(
        committed.durability(),
        CommitDurability::ExternallyConfirmed
    );

    let mut wal = new_store::<WalStore>();
    let wal_transaction = wal
        .begin(Tick::new(0), Deadline::new(10))
        .expect("begin wal");
    wal.create(wal_transaction, Tick::new(0))
        .expect("create wal");
    assert_eq!(
        wal.commit(
            wal_transaction,
            Tick::new(1),
            Durability::ExternalBarrier(receipt),
        ),
        Err(Error::InvalidBarrierReceipt)
    );
    wal.abort(wal_transaction).expect("abort rejected barrier");
}

#[test]
fn fixed_capacity_layout_and_recovery_work_are_bounded() {
    let metrics = storage_metrics();
    assert!(metrics.state_bytes > LOGICAL_CAPACITY_BYTES);
    assert!(metrics.cow_store_bytes <= 16 * 1024);
    assert!(metrics.wal_store_bytes <= 32 * 1024);
    assert_eq!(metrics.cow_max_recovery_steps, 4);
    assert_eq!(metrics.wal_max_recovery_steps, MAX_WAL_RECORDS);
}

#[test]
fn cow_variant_passes_common_acceptance_suite() {
    common_acceptance_suite::<CowStore>();
}

#[test]
fn wal_variant_passes_common_acceptance_suite() {
    common_acceptance_suite::<WalStore>();
}
