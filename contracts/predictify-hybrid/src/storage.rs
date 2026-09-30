use soroban_sdk::{contracttype, Address, BytesN};

/// TTL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// TTL the contract instance is extended to on every successful batch
/// (~30 days). #1288: previously the instance was bumped to the same 24 h
/// window as the keys, so an idle contract could expire together with its
/// replay protection. The instance must outlive every key it protects.
pub const INSTANCE_TTL_LEDGERS: u32 = 518_400;

/// Largest number of bets accepted in one `place_bets` call. Bounds the
/// work and footprint of a single invocation so a batch can never fail
/// part-way on resource limits.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` marks a consumed `place_bets` key.
///
/// Storage tiers (#1288 / #1280):
/// * **Current:** *temporary* storage holding a [`crate::BatchReceipt`],
///   with its own TTL of [`IDEM_KEY_TTL_LEDGERS`]. Temporary storage is what
///   makes the documented "expires after ~24 h" behaviour true per key.
/// * **Legacy:** versions before #1288 stored a sentinel `true` in *instance*
///   storage, where entries share the instance TTL and never expire
///   individually. Those entries are still honoured (a legacy key is never
///   re-applied) so upgrading the contract cannot re-open old keys.
///
/// Original note: the key is stored once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}
