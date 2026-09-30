//! Batch bet placement.
//!
//! # Compatibility contract (#1280)
//!
//! These are public and must not change without a versioned migration:
//!
//! 1. **`Bet` wire layout** — a `contracttype` struct encoded as an XDR map
//!    keyed by field name (`amount`, `market_id`). Renaming, removing or
//!    retyping a field breaks every existing caller; add new data as a new
//!    type or a new entry point instead.
//! 2. **Error codes** — `1` (`IdempotentBatchAlreadyApplied`) and `2`
//!    (`EmptyBatch`) keep their exact meaning. New failures use new codes
//!    (3, 4, 5). A reused key is *always* code `1`, whatever the payload.
//! 3. **Zero key** — `[0u8; 32]` disables deduplication (deprecated but
//!    still supported; no receipt is stored).
//! 4. **Event** — every applied batch still publishes topics
//!    `("place_bets", caller)` with data `bets.len(): u32`, byte-for-byte as
//!    before. The receipt event added by #1288 is a *separate* event.
//! 5. **Validation order** — auth → empty → size → amounts → overflow →
//!    idempotency. The order is fixed so the same input always yields the
//!    same error.
//!
//! # Failure model (#1288)
//!
//! Checks happen before effects. A failed invocation (returned `Err`,
//! failed auth, host error) is rolled back by Soroban: no key consumed, no
//! receipt written, no event emitted. Partial application is therefore
//! impossible, and retrying the *same* key after any failure is safe.
//! Two transactions with the same key are serialised by the ledger (same
//! storage footprint), so the second always sees the first's key and
//! returns code `1` — never a double application.

use soroban_sdk::{contracttype, symbol_short, xdr::ToXdr, Address, BytesN, Env, Vec};

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
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
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
/// * [`Error::BatchTooLarge`]                – more than [`MAX_BATCH_SIZE`] bets.
/// * [`Error::InvalidAmount`]                – a bet with `amount <= 0`.
/// * [`Error::AmountOverflow`]               – the batch total overflows `i128`.
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

        // 4. Consume the key by storing the receipt with its own TTL. Because
        //    the invocation is atomic, this write survives only if the
        //    batch below is applied too.
        let idem_key = DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());
        let receipt = BatchReceipt {
            bet_count: bets.len(),
            total_amount,
            batch_hash: hash.clone(),
            applied_ledger: env.ledger().sequence(),
            legacy: false,
        };
        env.storage().temporary().set(&idem_key, &receipt);
        env.storage()
            .temporary()
            .extend_ttl(&idem_key, IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
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

// Symbol is used above; import it here to keep the use-site clean.
use soroban_sdk::Symbol;
