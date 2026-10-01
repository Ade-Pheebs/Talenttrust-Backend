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
/// This is a validation boundary: batches larger than this are rejected
/// outright rather than being truncated, so callers can never silently lose
/// bets. It also bounds the work (and thus the gas) of a single call.
pub const MAX_BATCH_SIZE: u32 = 50;

/// Minimum number of bets accepted in a single ```place_bets``` batch.
///
/// An empty batch is rejected because it would consume an idempotency
/// key without effect, allowing a caller to burn their own token accidentally.
pub const MIN_BATCH_SIZE: u32 = 1;

/// Maximum length of the optional memo attached to a batch.
///
/// The memo is purely diagnostic and is not part of the idempotency key.
/// It is bounded to keep event payloads small and to prevent abuse.
pub const MAX_MEMO_LEN: u32 = 64;

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// The consumed sentinel is written only after all validation and state
/// transitions for the batch have succeeded, so a reverted call never burns
/// the idempotency key and the caller may retry safely.
///
/// Additional keys are reserved for per-caller counters so the contract can
/// enforce batch boundaries without relying on off-chain indexing.
#contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
    /// Monotonically increasing counter of accepted batches for a caller.
    /// Used to enforce per-caller batch limits and to expose deterministic
    /// observability for indexers.
    BatchCounter(Address),
}
