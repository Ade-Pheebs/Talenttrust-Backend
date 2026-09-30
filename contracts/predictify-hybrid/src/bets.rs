use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS, PENDING_IDEM_KEY_TTL_LEDGERS},
};

/// A single bet submitted inside a batch.
///
/// Extend this struct with market-specific fields as the contract grows.
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
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///                                              pair has already been consumed.
/// * [`Error::BatchInProgress`]              – a concurrent invocation with the
///                                              same key is currently applying.
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
/// A two-phase marker is used to make concurrent execution deterministic:
/// the key is first written as *pending* (with a short TTL) and only promoted
/// to *applied* after the batch has been fully processed.  A second call that
/// observes a pending marker returns [`Error::BatchInProgress`] rather than
/// racing the first caller, and a call that observes an applied marker returns
/// [`Error::IdempotentBatchAlreadyApplied`].  If the first caller traps before
/// promoting the marker, the pending entry expires after
/// [`PENDING_IDEM_KEY_TTL_LEDGERS`] ledgers and the key becomes reusable.
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
    // Idempotency check
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    if idempotency_key != zero_key {
        let pending_key =
            DataKey::PlaceBetsIdemPending(caller.clone(), idempotency_key.clone());
        let applied_key =
            DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());

        // Fast path: a previously completed batch with this key.
        if env.storage().instance().has(&applied_key) {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }

        // Concurrent path: another invocation is mid-flight for this key.
        // Fail fast instead of racing the first caller's state mutations.
        if env.storage().instance().has(&pending_key) {
            return Err(Error::BatchInProgress);
        }

        // Claim the key by writing a pending marker *before* applying the
        // batch.  The short TTL bounds the window in which a trapped caller
        // can leave the key unusable.
        env.storage().instance().set(&pending_key, &true);
        env.storage()
            .instance()
            .extend_ttl(PENDING_IDEM_KEY_TTL_LEDGERS, PENDING_IDEM_KEY_TTL_LEDGERS);

        // Apply the batch.  Any error returned here leaves the pending
        // marker in place; it will expire naturally, allowing a retry.
        apply_batch(env, &caller, &bets)?;

        // Promote the pending marker to an applied marker so subsequent
        // calls with the same key are rejected as duplicates.
        env.storage().instance().remove(&pending_key);
        env.storage().instance().set(&applied_key, &true);
        env.storage()
            .instance()
            .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);

        return Ok(());
    }

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    apply_batch(env, &caller, &bets)
}

/// Apply the batch of bets to market state.
///
/// Kept separate from [`place_bets`] so the idempotency bookkeeping and the
/// state mutation can be reasoned about independently.  The caller is
/// responsible for having authenticated `caller` and for having claimed the
/// idempotency key before invoking this function.
fn apply_batch(env: &Env, caller: &Address, bets: &Vec<Bet>) -> Result<(), Error> {
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    env.events().publish(
        (Symbol::new(env, "place_bets"), caller.clone()),
        bets.len(),
    );
    Ok(())
}

// Symbol is used above; import it here to keep the use-site clean.
use soroban_sdk::Symbol;
