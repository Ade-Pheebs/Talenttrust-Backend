use soroban_sdk::{contracttype, Address, BytesN};

/// TTL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
///
/// ## Compatibility contract
///
/// This constant is part of the public API and is re-exported from
/// `lib.rs`.  Changing it changes the replay-protection window for
/// any future deployment.  It must not be lowered without a migration
/// plan, because that would allow a replay of an already-applied batch.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// ## Compatibility contract
///
/// The constructor shape of `DataKey` is part of the on-chain state
/// layout.  Adding new variants is allowed (they must be appended),
/// but reordering or removing existing variants would invalidate
/// persisted state and break existing deployments.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}
