use soroban_sdk::{contracttype, Address, BytesN, Symbol};

/// TTL for consumed idempotency keys, expressed in ledgers.
//
// At ~5 s/ledger this gives roughly 24 hours of replay protection.
// After expiry the key is eligible for eviction from instance storage
// and a fresh submission with the same token is treated as a new batch.
//
// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Maximum number of [`Bet`] entries allowed in a single `place_bets` call.
///
/// This bound protects the contract against accidental or adversarial
/// resource exhaustion.  A batch that exceeds this limit is rejected with
/// [`crate::errors::Error::BatchTooLarge`] before any state mutation, so
/// the call is atomic: either the full (valid) batch is applied or nothing
/// is written.
///
/// Callers that need to submit more than `MAX_BATCH_SIZE` bets must split
/// the work into multiple invocations, each with a distinct idempotency key.
///
/// The value 50 was chosen to stay well within Soroban's per-invocation
/// CPU and memory limits while still accommodating realistic batch sizes.
/// Increase with care and validate against the current Soroban host limits.
///
/// [`Bet`]: crate::bets::Bet
pub const MAX_BATCH_SIZE: u32 = 50;

/// Storage keys used by the contract.
///
/// This bound is enforced before any state mutation so that an
/// oversized batch is rejected atomically without consuming the
/// caller's idempotency key. The value is deliberately small enough
/// to keep the batch and its emitted events well within the network'
/// transaction resource limits, and large enough for realistic use.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Storage keys used by the contract.
//
// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
// ```place_bets``` batch has been accepted.  The composite key binds the
// token to the submitting address so two different callers may reuse the
// same 32-byte token independently without conflict.
//
// ```Bet(user, outcome)``` stores the cumulated wager amount for a
// given caller on a given outcome label.  This is the authoritative
// state that bet application mutates.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Idempotency receipt for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN <32>),

    /// Authoritative bet record. Keyed by (caller address, outcome label).
    Bet(Address, Symbol),
}
