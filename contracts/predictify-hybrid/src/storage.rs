use soroban_sdk::{contracttype, Address, BytesN, Env};

/// TTL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Maximum number of bets in a single `place_bets` batch.
///
/// This bound is enforced before any state mutation so that an
/// oversized batch is rejected atomically without consuming the
/// caller's idempotency key. The value is deliberately small enough
/// to keep the batch and its emitted events well within the network'
/// transaction resource limits, and large enough for realistic use.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}

/// Returns `true` if the idempotency key has already been consumed by
/// a successful batch from the same caller.
pub fn is_idempotency_key_consumed(env: &Env, caller: &Address, key: &BytesN<32>) -> bool {
    env.storage()
        .instance()
        .has(&DataKey::PlaceBetsIdem(caller.clone(), key.clone()))
}

/// Marks the idempotency key as consumed and extends its TT\.
///
/// This function is the only place that writes the sentinel, so the
/// invariant "consumed implies batch applied" holds by construction.
/// It must be called after all validation and state mutations succeed.
pub fn consume_idempotency_key(env: &Env, caller: &Address, key: &BytesN<32>) {
    let storage = env.storage().instance();
    storage.set(
        &DataKey::PlaceBetsIdem(caller.clone(), key.clone()),
        &true,
    );
    storage.extend_ttl(
        &DataKey::PlaceBetsIdem(caller.clone(), key.clone()),
        IDEM_KEY_TTL_LEDGERS,
        IDEM_KEY_TTL_LEDGERS,
    );
}
