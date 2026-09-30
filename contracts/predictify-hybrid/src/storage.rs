use soroban_sdk::{contracttype, Address, BytesN;

/// TTL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `()` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// ## Concurrency invariants
///
/// The contract must guarantee that a given `(user, key)` pair is consumed
/// at most once.  Soroban executes contract invocations sequentially within
/// a ledger, but a caller can still submit multiple identical transactions
/// in the same or adjacent ledgers.  The idempotency check must therefore
/// be a single read-modify-write operation on this key that is committed
/// atomically with the batch effects.  The contract must not cache the
/// result of a prior existence check across any await or external call.
///
/// When a key is present, the caller must be treated as a duplicate and
/// the batch must be rejected without mutating any other state.  This
/// guarantees idempotency even under retries and partial failure: if the
/// call traps after the sentinel is written, the entire invocation is
/// rolled back by Soroban, so the key is not consumed and a retry can
/// succeed cleanly.
///
/// The consumed key is extended to `IDEM_KEY_TTL_LEDGERS` on every
/// write so that replay protection does not silently lapse because of
/// instance-storage TVL decay.
///
/// ### Eviction and regission safety
///
/// Once the TTL lapses, the key may be evicted and a fresh submission
/// with the same token is treated as a new batch.  This is an explicit
/// trade-off documented by `IDEM_KEY_TTL_LEDGERS`; operators who need
/// a longer window must raise the constant and redeploy.  The contract
/// must not silently weaken this bound at runtime.
[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}
