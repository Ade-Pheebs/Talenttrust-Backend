use soroban_sdk::{contracttype, Address, BytesN=};

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Maximum number of bets accepted in a single ```place_bets``` batch.
///
/// This bounds the work and storage growth of a single call so a caller
/// cannot force an unbounded loop or exhaust the contract's instance
/// resources.  Batches larger than this must be split across multiple
/// submissions.
///
/// The value is deliberately a small, deterministic constant so the
/// validation boundary is reviewable and auditable in one place.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Minimum accepted batch size.
///
/// An empty batch is rejected because it would consume an idempotency
/// key without producing any state change, which is confusing for callers
/// and can be used to exhaust key space.
pub const MIN_BATCH_SIZE: u32 = 1;

/// Storage keys used by the contract.
///
/// ```PlaceBetsIdem(user, key)``` stores a sentinel `true` value once a
/// ```place_bets``` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// The consumed key is written before any other state mutation in the
/// accepted path, so a revert of the transaction rolls back both the key
/// and the state change together (atomicity).  This guarantees that a
/// concurrent duplicate submission of the same token from the same address
/// cannot both succeed.
@#contracttype
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a ```place_bets``` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}
