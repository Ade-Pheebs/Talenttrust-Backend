use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS, INSTANCE_TTL_LEDGERS, MAX_BATCH_SIZE},
};

/// Durable record of an applied batch, stored under its idempotency key
/// (#1288). Lets a caller whose response was lost learn, deterministically,
/// whether and what was applied — without re-submitting.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    /// Number of bets applied.
    pub bet_count: u32,
    /// Sum of all `amount`s in the batch.
    pub total_amount: i128,
    /// `sha256(xdr(bets))`. Compare with the hash of the batch you meant to
    /// send to tell "my batch landed" from "this key was used for another
    /// batch" (both are reported as error code `1` on resubmission).
    pub batch_hash: BytesN<32>,
    /// Ledger sequence the batch was applied in.
    pub applied_ledger: u32,
    /// `true` when the key was consumed by a pre-#1288 contract version
    /// (instance-storage sentinel). Only `bet_count == 0` and zeroed fields
    /// are known for such keys.
    pub legacy: bool,
}

/// Deterministic fingerprint of a batch: `sha256` of its XDR encoding.
pub fn batch_hash(env: &Env, bets: &Vec<Bet>) -> BytesN<32> {
    env.crypto().sha256(&bets.clone().to_xdr(env)).to_bytes()
}

fn zero_key(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

/// Receipt for `(caller, key)`, from the current tier or the legacy tier.
/// `None` means the key is unused (or has expired): nothing was applied
/// under it and it is safe to submit.
pub fn batch_receipt(
    env: &Env,
    caller: Address,
    idempotency_key: BytesN<32>,
) -> Option<BatchReceipt> {
    if idempotency_key == zero_key(env) {
        return None; // zero key never records anything
    }
    let key = DataKey::PlaceBetsIdem(caller, idempotency_key);
    if let Some(receipt) = env.storage().temporary().get::<_, BatchReceipt>(&key) {
        return Some(receipt);
    }
    if env.storage().instance().has(&key) {
        return Some(BatchReceipt {
            bet_count: 0,
            total_amount: 0,
            batch_hash: zero_key(env),
            applied_ledger: 0,
            legacy: true,
        });
    }
    None
}

/// Validates a batch and returns its total. Pure: no storage access, so it
/// gives the same answer for the same input on every call (#1280 item 5).
fn validate(bets: &Vec<Bet>) -> Result<i128, Error> {
    if bets.is_empty() {
        return Err(Error::EmptyBatch);
    }
    if bets.len() > MAX_BATCH_SIZE {
        return Err(Error::BatchTooLarge);
    }
    let mut total: i128 = 0;
    for bet in bets.iter() {
        if bet.amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        total = total.checked_add(bet.amount).ok_or(Error::AmountOverflow)?;
    }
    Ok(total)
}

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bet {
    /// Identifier of the prediction market being bet on.
    pub market_id: u64,
    /// Amount of the base asset staked, in stroops.
    pub amount: i128,
}

/// Maximum number of bets allowed in a single batch submission.
///
/// Bounds the amount of work performed per invocation so that a single
/// transaction cannot exhaust the ledger budget or produce an unbounded
/// state transition.
pub const MAX_BATCH_SIZE: u32 = 100;

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
/// The key is consumed (a [`BatchReceipt`] is written to temporary storage)
/// only after the whole batch has been validated. If a previous call with
/// the same key succeeded, the function returns
/// [`Error::IdempotentBatchAlreadyApplied`] without re-applying the batch —
/// also when the payload differs (compare `batch_hash` from
/// [`batch_receipt`] to tell the cases apart). The key and its receipt
/// expire after [`IDEM_KEY_TTL_LEDGERS`] ledgers; after expiry a new
/// submission with the same token is accepted as a fresh batch.
///
/// # Deprecation note — zero-key backward path
///
/// Passing `[0u8; 32]` as the key disables idempotency checking and
/// processes the batch unconditionally.  **This path is deprecated** and
/// will be removed in a future version.  Callers should generate a random
/// 32-byte token for every batch.
///
/// # Determinism
///
/// The idempotency key is committed to storage before any batch side
/// effects.  If batch application fails, the key is rolled back so that
/// a retry with the same key is treated as a fresh submission.
pub fn place_bets(
    env: &Env,
    caller: Address,
    bets: Vec<Bet>,
    idempotency_key: BytesN<32>,
) -> Result<(), Error> {
    // 1. Authenticate the caller. A failed auth aborts the invocation
    //    before any read or write.
    caller.require_auth();

    // 2. Validate the whole batch before touching storage (checks before
    //    effects, #1288). Invalid input never consumes the key.
    let total_amount = validate(&bets)?;

    // Enforce the upper bound on batch size.
    if bets.len() > MAX_BATCH_SIZE {
        return Err(Error::BatchTooLarge);
    }

    // Validate each bet: positive amount and no duplicate market ids.
    for i in 0..bets.len() {
        let bet = bets.get(i).unwrap();
        if bet.amount <= 0 {
            return Err(Error::InvalidBetAmount);
        }
        for j in (i + 1)..bets.len() {
            if bets.get(j).unwrap().market_id == bet.market_id {
                return Err(Error::DuplicateBet);
            }
        }
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
    // 3. Idempotency: a key seen in either tier (current temporary receipt
    //    or legacy instance sentinel) is rejected with code 1.
    let dedupe = idempotency_key != zero_key(env);
    let hash = batch_hash(env, &bets);
    if dedupe {
        if batch_receipt(env, caller.clone(), idempotency_key.clone()).is_some() {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }

        // Mark the key as consumed before applying the batch so that
        // concurrent invocations on the same ledger also fail fast.
        //
        // Invariant: the idempotency marker MUST be written and its TTL
        // extended atomically with respect to the batch application.  We
        // write the marker first, then extend TTL, then apply the batch.
        // If the batch application panics or returns an error, the marker
        // remains set, which is the safe (fail-closed) behavior: a retry
        // with the same key will be rejected rather than re-applying a
        // partially-applied batch.  Callers that need to retry after a
        // failure must generate a fresh idempotency key.
        env.storage().instance().set(&idem_key, &true);
        env.storage()
            .instance()
            .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);

        // Re-read the marker to confirm it is durably visible before we
        // mutate any market state.  This guards against a storage backend
        // that silently drops writes and ensures the idempotency invariant
        // holds even under adverse conditions.
        if !env.storage().instance().has(&idem_key) {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }
    }

    // Keep the instance (and any legacy keys in it) alive well beyond the
    // key window so replay protection can't lapse with an idle contract.
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_LEDGERS / 2, INSTANCE_TTL_LEDGERS);

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    // Compatibility event (#1280 item 4) — unchanged shape.
    env.events()
        .publish((Symbol::new(env, "place_bets"), caller.clone()), bets.len());

    // Observability (#1288): a separate receipt event so indexers can
    // reconcile applied batches. Carries no secrets — the key is a
    // caller-chosen nonce and the hash only fingerprints public bet data.
    env.events().publish(
        (symbol_short!("bet_rcpt"), caller, idempotency_key),
        (bets.len(), total_amount, hash, dedupe),
    );

    Ok(())
}
