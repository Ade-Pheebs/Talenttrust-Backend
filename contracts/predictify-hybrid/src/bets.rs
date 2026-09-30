//! `place_bets` — batch bet submission and the state it owns.
//!
//! # State model
//!
//! This module owns exactly one piece of durable state: the
//! **idempotency receipt** for a `(caller, key)` pair, stored under
//! [`DataKey::PlaceBetsIdem`]. A receipt exists **if and only if** a
//! batch was fully validated and applied for that pair. Market state is
//! deliberately not written here yet — see *Market mutations* below —
//! and this module never writes speculative state to compensate for the
//! gap.
//!
//! # Invariants
//!
//! * **I1 — authorized submitter.** The batch is attributed to `caller`,
//!   which must have signed via [`Address::require_auth`]. No other
//!   principal can spend or replay a caller's receipt, and the receipt
//!   key is scoped to the caller, so a token is not a bearer token.
//! * **I2 — receipt ⇔ applied batch.** A `(caller, key)` receipt exists
//!   exactly when a batch for that pair was accepted. A *rejected* batch
//!   leaves no receipt, so the caller can safely fix the payload and
//!   retry with the same token.
//! * **I3 — at most once per window.** While a receipt is live, a
//!   `(caller, key)` pair is accepted at most once. Replays fail with
//!   [`Error::IdempotentBatchAlreadyApplied`] before any mutation, so a
//!   replay is read-only.
//! * **I4 — all-or-nothing.** The whole batch is validated before the
//!   first write. Soroban additionally reverts every write when a
//!   contract call returns `Err`, so no failure path can leave a
//!   half-applied batch or a receipt without its batch.
//! * **I5 — positive stake, real market.** Every `Bet` has
//!   `amount > 0` and `market_id != 0`, and the batch total is checked
//!   for `i128` overflow. Zero/negative amounts and the sentinel market
//!   are refused rather than recorded.
//! * **I6 — bounded work.** `bets.len() <= MAX_BETS_PER_BATCH` keeps the
//!   cost of a single invocation deterministic and stops one transaction
//!   from monopolizing the ledger.
//! * **I7 — bounded durable state.** Receipts live in temporary storage
//!   (one ledger entry per `(caller, key)`) under a TTL, so the contract
//!   instance entry stays a constant size no matter how many batches
//!   succeed and expired receipts are deleted by the network rather than
//!   archived. See [`DataKey`] for why instance and persistent storage are
//!   both unsafe here.
//!
//! # Failure modes
//!
//! Every rejection is a typed [`Error`] returned *before* any state is
//! written: empty batch, oversized batch, `market_id == 0`, non-positive
//! `amount`, total overflow, and duplicate idempotency key. Because I2
//! and I4 hold, a caller may retry the *same* token after a rejection —
//! the token was never consumed. A caller that loses the response of a
//! *successful* call cannot retry with that token; it should submit a
//! new batch under a fresh token, which is the only state change a
//! replay could cause.

use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{
        DataKey, CONTRACT_TTL_LEDGERS, CONTRACT_TTL_THRESHOLD_LEDGERS, IDEM_KEY_TTL_LEDGERS,
        IDEM_KEY_TTL_THRESHOLD_LEDGERS,
    },
};

/// Maximum number of bets accepted in a single `place_bets` batch.
///
/// Mirrors the API-layer policy cap
/// (`BULK_OPERATION_MAX_BATCH_SIZE` in
/// `src/modules/contracts/dto/bulk-operations.dto.ts`) so a batch the
/// HTTP layer accepts is never rejected for size on-chain, and a
/// hand-built transaction cannot force unbounded per-call work.
pub const MAX_BETS_PER_BATCH: u32 = 100;

/// A single bet submitted inside a batch.
///
/// Extend this struct with market-specific fields as the contract grows.
/// Any new field is covered by I5: it must be validated in
/// [`validate_bets`] before the first write.
#[soroban_sdk::contracttype]
#[derive(Clone)]
pub struct Bet {
    /// Identifier of the prediction market being bet on.
    ///
    /// `0` is reserved as the "no market" sentinel and is rejected with
    /// [`Error::InvalidMarketId`].
    pub market_id: u64,
    /// Amount of the base asset staked, in stroops.
    ///
    /// Must be strictly positive; `0` and negative values are rejected
    /// with [`Error::InvalidBetAmount`].
    pub amount: i128,
}

/// Durable record written when a batch is accepted.
///
/// Stored under [`DataKey::PlaceBetsIdem`], so "this key was consumed"
/// and "this is what was applied" are the same fact. An operator can
/// reconcile a receipt against the emitted `bets_placed` event without
/// trusting an off-chain index. The fields carry no data beyond what the
/// caller already revealed by submitting the batch, and the idempotency
/// token itself is deliberately **not** stored here or published in any
/// event — see [`place_bets`].
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    /// Number of bets applied. Equal to the `bet_count` of the
    /// `bets_placed` event for the same call.
    pub bet_count: u32,
    /// Sum of every `Bet::amount` in the batch, in stroops. Always `> 0`
    /// for an accepted batch, and equal to the event's `total_amount`.
    pub total_amount: i128,
    /// Ledger sequence the batch was applied on, for reconciling a
    /// receipt with the ledger it landed in.
    pub applied_at_ledger: u32,
}

/// Process a batch of bets atomically with an idempotency guarantee.
///
/// # Arguments
///
/// * `env`             – Soroban host environment.
/// * `caller`          – Address of the submitting account; `require_auth` is
///                       called to authenticate the caller.
/// * `bets`            – Non-empty vector of [`Bet`] entries, at most
///                       [`MAX_BETS_PER_BATCH`] of them.
/// * `idempotency_key` – 32-byte caller-generated token that makes this
///                       submission unique.  The key is bound to `caller` so
///                       the same token may be used by different callers
///                       without conflict.
///
/// # Errors
///
/// * [`Error::EmptyBatch`]                  – `bets` is empty.
/// * [`Error::BatchTooLarge`]               – `bets.len() > MAX_BETS_PER_BATCH`.
/// * [`Error::InvalidMarketId`]             – a bet referenced `market_id == 0`.
/// * [`Error::InvalidBetAmount`]            – a bet had `amount <= 0`.
/// * [`Error::BatchAmountOverflow`]         – the batch total does not fit in an `i128`.
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///                                              pair has already been consumed.
///
/// All six are returned *before* any state is written, so the caller may
/// correct the payload and retry with the same idempotency key.
///
/// # Idempotency semantics
///
/// The receipt is written to temporary storage **before** the batch is
/// applied, and only after the batch has fully validated. If a previous
/// call with the same key succeeded, the function returns
/// [`Error::IdempotentBatchAlreadyApplied`] immediately without
/// re-applying the batch. Once written, the receipt expires after
/// [`IDEM_KEY_TTL_LEDGERS`] ledgers; after expiry the network has deleted
/// it, a new submission with the same token is accepted as a fresh
/// batch, and a client that lost the response of a successful call can
/// safely retry inside the window or resubmit under a new token after it.
/// See [`DataKey`] for why the receipt lives in temporary rather than
/// instance or persistent storage.
///
/// Writing the receipt before applying is what makes the guarantee hold
/// under same-ledger concurrency: a second transaction that touches the
/// same receipt entry conflicts in the host's transaction footprint and
/// is rejected before it executes; resubmitted in a later ledger it then
/// fails the `has` check below. If this call instead fails, the host
/// reverts the receipt together with everything else, so a rejected batch
/// never burns a token.
///
/// # Deprecation note — zero-key backward path
///
/// Passing `[0u8; 32]` as the key disables idempotency checking and
/// processes the batch unconditionally.  **This path is deprecated** and
/// will be removed in a future version.  Callers should generate a random
/// 32-byte token for every batch. It offers no replay protection and no
/// same-ledger dedup, but all validation in I5/I6 still applies, and the
/// `bets_placed` event reports `deduplicated == false` so indexers can
/// account for these submissions separately.
pub fn place_bets(
    env: &Env,
    caller: Address,
    bets: Vec<Bet>,
    idempotency_key: BytesN<32>,
) -> Result<(), Error> {
    // I1 — authenticate before doing anything observable. A caller that
    // cannot authorize must not be able to burn its own token.
    caller.require_auth();

    // ------------------------------------------------------------------
    // Shape validation (I6)
    // ------------------------------------------------------------------
    // Bound the batch before any per-bet work, so the cost of a rejected
    // oversized batch is O(1).
    let bet_count = bets.len();
    if bet_count == 0 {
        return Err(Error::EmptyBatch);
    }
    if bet_count > MAX_BETS_PER_BATCH {
        return Err(Error::BatchTooLarge);
    }

    // ------------------------------------------------------------------
    // Content validation (I5), completing before the first write (I4)
    // ------------------------------------------------------------------
    // The total is returned from validation and written verbatim into the
    // receipt and the event, so the aggregate that was checked and the
    // aggregate that is recorded cannot diverge.
    let total_amount = validate_bets(&bets)?;

    // ------------------------------------------------------------------
    // Idempotency claim (I2, I3, I7)
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    let deduplicated = idempotency_key != zero_key;

    if deduplicated {
        let idem_key = DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());

        // A live receipt means this pair was already applied. Reject
        // before any mutation so a replay is read-only (I3).
        if env.storage().temporary().has(&idem_key) {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }

        // Claim the key *before* the batch is applied. See the module
        // documentation for why, and for why a later failure does not
        // burn the token.
        env.storage().temporary().set(
            &idem_key,
            &BatchReceipt {
                bet_count,
                total_amount,
                applied_at_ledger: env.ledger().sequence(),
            },
        );
        env.storage().temporary().extend_ttl(
            &idem_key,
            IDEM_KEY_TTL_THRESHOLD_LEDGERS,
            IDEM_KEY_TTL_LEDGERS,
        );
    }

    // Keep the contract itself reachable. The instance/code entry has its
    // own TTL that no per-key receipt bump renews, so an accepted batch
    // refreshes it here; see CONTRACT_TTL_LEDGERS. Done for the
    // zero-key path too — that path writes no receipt, so this is the
    // only thing keeping the contract alive for those callers.
    env.storage()
        .instance()
        .extend_ttl(CONTRACT_TTL_THRESHOLD_LEDGERS, CONTRACT_TTL_LEDGERS);

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // Market mutations belong here, once the market-state module exists.
    // Everything above is total and side-effect free apart from the
    // idempotency claim, so the batch is all-or-nothing by construction
    // and the recorded `total_amount` is exactly the amount that will be
    // applied. Keep this section free of `unwrap`/panics: a panic here
    // would revert the receipt too, and the caller would see a generic
    // host failure instead of a typed error.
    let _ = total_amount;

    // ------------------------------------------------------------------
    // Observability
    // ------------------------------------------------------------------
    // Emitted only on the success path, and only with values the caller
    // already supplied. The idempotency token is never published: it is
    // a replay credential, and on-chain logs are public and permanent.
    publish_bets_placed(env, &caller, bet_count, total_amount, deduplicated);
    publish_legacy_place_bets(env, &caller, bet_count);

    Ok(())
}

/// Validate a batch and return its total stake in stroops.
///
/// Runs to completion before [`place_bets`] performs any write, so a
/// rejection can never leave partial state (I4). Every failure is a
/// typed [`Error`] that says which bet was wrong without echoing its
/// contents.
///
/// Duplicate `market_id`s inside one batch are **allowed** and simply
/// add up: each [`Bet`] is an independent stake, and rejecting
/// duplicates would break callers that already submit them.
fn validate_bets(bets: &Vec<Bet>) -> Result<i128, Error> {
    let mut total: i128 = 0;

    for bet in bets.iter() {
        // I5a — `market_id` 0 is the reserved "no market" sentinel.
        // Stake recorded against it could never be resolved or paid out,
        // so it is refused rather than stored.
        if bet.market_id == 0 {
            return Err(Error::InvalidMarketId);
        }

        // I5b — a bet is a transfer of value. Zero would be a no-op that
        // still consumes an idempotency key; negative would credit one
        // side of a market and debit the other.
        if bet.amount <= 0 {
            return Err(Error::InvalidBetAmount);
        }

        // I5c — checked addition. `a + b` wraps on `i128` overflow once
        // debug assertions are off (which they are in the release
        // profile), turning a large batch into a negative recorded total.
        total = total
            .checked_add(bet.amount)
            .ok_or(Error::BatchAmountOverflow)?;
    }

    Ok(total)
}

/// Publish the post-apply `bets_placed` event.
///
/// Topics: `("bets_placed", caller)`. Data: `(bet_count, total_amount,
/// deduplicated)`.
///
/// The payload mirrors [`BatchReceipt`] field for field, so an indexer can
/// verify a receipt against the event that was emitted with it.
/// `deduplicated` is `false` only for the deprecated zero-key path, which
/// makes those submissions visible as a separate class instead of
/// silently weakening replay accounting.
fn publish_bets_placed(
    env: &Env,
    caller: &Address,
    bet_count: u32,
    total_amount: i128,
    deduplicated: bool,
) {
    env.events().publish(
        (Symbol::new(env, "bets_placed"), caller.clone()),
        (bet_count, total_amount, deduplicated),
    );
}

/// Publish the pre-#1277 `place_bets` event.
///
/// Topics: `("place_bets", caller)`. Data: `bet_count`.
///
/// # Deprecation
///
/// Superseded by [`publish_bets_placed`], which additionally carries the
/// batch total and the dedup marker. This event is still emitted so
/// indexers written against the previous contract build keep working;
/// it will be removed once consumers have migrated. Note that it cannot
/// be used to distinguish a deduplicated submission from a zero-key one,
/// which is precisely why `bets_placed` exists.
fn publish_legacy_place_bets(env: &Env, caller: &Address, bet_count: u32) {
    env.events()
        .publish((Symbol::new(env, "place_bets"), caller.clone()), bet_count);
}
