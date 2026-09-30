use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS},
};

/// A single bet submitted inside a batch.
///
/// Extend this struct with market-specific fields as the contract grows.
///
/// # Validation boundaries
///
/// * `market_id` must be non-zero; `0` is reserved as an invalid sentinel.
/// * `amount` must be strictly positive (`> 0`). Zero and negative amounts
///   are rejected to prevent no-op or refund-style state transitions.
/// * Duplicate `market_id` entries within the same batch are rejected so a
///   single submission cannot silently double-apply to the same market.
#[soroban_sdk::contracttype]
#[derive(Clone)]
pub struct Bet {
    /// Identifier of the prediction market being bet on.
    pub market_id: u64,
    /// Amount of the base asset staked, in stroops.
    pub amount: i128,
}

/// Process a batch of bets atomically with an idempotency guarantee.
///
/// # Arguments
///
/// * `env`             – Soroban host environment.
/// * `caller`          – Address of the submitting account; `require_auth` is
///                       called to authenticate the caller.
/// * `bets`            – Non-empty vector of [`Bet`] entries.
/// * `idempotency_key` – 32-byte caller-generated token that makes this
///                       submission unique.  The key is bound to `caller` so
///                       the same token may be used by different callers
///                       without conflict.
///
/// # Errors
///
/// * [`Error::EmptyBatch`]                   – `bets` is empty.
/// * [`Error::InvalidMarketId`]              – a bet has `market_id == 0`.
/// * [`Error::InvalidAmount`]                – a bet has `amount <= 0`.
/// * [`Error::DuplicateMarketInBatch`]       – the batch contains the same
///                                              `market_id` more than once.
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///                                              pair has already been consumed.
///
/// # Idempotency semantics
///
/// The key is written to instance storage **before** processing the bets.
/// If a previous call with the same key succeeded, the function returns
/// [`Error::IdempotentBatchAlreadyApplied`] immediately without re-applying
/// the batch.  Once written, the key expires after [`IDEM_KEY_TTL_LEDGERS`]
/// ledgers; after expiry a new submission with the same token is accepted as
/// a fresh batch.
///
/// # Deprecation note — zero-key backward path
///
/// Passing `[0u8; 32]` as the key disables idempotency checking and
/// processes the batch unconditionally.  **This path is deprecated** and
/// will be removed in a future version.  Callers should generate a random
/// 32-byte token for every batch.
pub fn place_bets(
    env: &Env,
    caller: Address,
    bets: Vec<Bet>,
    idempotency_key: BytesN<32>,
) -> Result<(), Error> {
    // Authenticate the caller.
    caller.require_auth();

    // Reject empty batches early.
    if bets.is_empty() {
        return Err(Error::EmptyBatch);
    }

    // ------------------------------------------------------------------
    // Per-bet validation (deterministic, order-independent)
    // ------------------------------------------------------------------
    // Validate every entry before touching idempotency state or emitting
    // events so that a rejected batch leaves no observable side effects.
    //
    // Invariants enforced here:
    //   1. `market_id != 0` (0 is a reserved invalid sentinel).
    //   2. `amount > 0` (no zero-value or negative-value stakes).
    //   3. No duplicate `market_id` within the same batch.
    //
    // The duplicate check is O(n^2) over the batch length. Batches are
    // expected to be small; if this becomes a hot path, replace with a
    // sorted scan or a temporary `Map<u64, ()>` in temporary storage.
    let len = bets.len();
    for i in 0..len {
        let bet = bets.get(i).ok_or(Error::EmptyBatch)?;

        if bet.market_id == 0 {
            return Err(Error::InvalidMarketId);
        }
        if bet.amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Duplicate detection: compare against all previous entries.
        for j in 0..i {
            let prev = bets.get(j).ok_or(Error::EmptyBatch)?;
            if prev.market_id == bet.market_id {
                return Err(Error::DuplicateMarketInBatch);
            }
        }
    }

    // ------------------------------------------------------------------
    // Idempotency check
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    if idempotency_key != zero_key {
        let idem_key = DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());

        if env.storage().instance().has(&idem_key) {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }

        // Mark the key as consumed before applying the batch so that
        // concurrent invocations on the same ledger also fail fast.
        env.storage().instance().set(&idem_key, &true);
        env.storage()
            .instance()
            .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
    }

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    env.events()
        .publish((Symbol::new(env, "place_bets"), caller), bets.len());

    Ok(())
}
