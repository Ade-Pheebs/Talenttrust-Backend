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
//! * **I8 — a spent token is reported honestly.** A replay under a live
//!   token is classified by comparing the incoming batch against the one the
//!   token was accepted for: an identical batch returns
//!   [`Error::IdempotentBatchAlreadyApplied`], a different one returns
//!   [`Error::IdempotencyKeyReusedWithDifferentBatch`]. Neither is applied,
//!   and the rejected batch cannot overwrite or disturb the stored receipt.
//! * **I9 — one claim per invocation, on every path.** The idempotency check
//!   reads and writes its storage keys exactly once regardless of whether a
//!   receipt already exists. This keeps the prepared transaction footprint
//!   read-write in both branches, so a batch is never left un-applied
//!   because a duplicate raced it; see *Concurrency model* below.
//!
//! # Concurrency model
//!
//! There is no compare-and-swap in Soroban storage, so mutual exclusion is
//! provided by the **transaction footprint** rather than by the contract.
//! The host builds a footprint while simulating and refuses to include two
//! transactions in one ledger that both declare the same entry
//! read-write. Everything below follows from taking part in that scheme
//! deliberately rather than by accident.
//!
//! **Same ledger.** Two transactions claiming the same `(caller, key)`
//! both declare the receipt entry read-write, so the ledger admits at most
//! one. The loser is *not* rejected by this contract and does not receive
//! [`Error::IdempotentBatchAlreadyApplied`] — it never executes, and the
//! submitting client sees a ledger-level transaction-set conflict. That is
//! a retryable condition: resubmit, and the resubmission lands in a later
//! ledger, takes the I3 branch, and returns the typed error.
//!
//! **Later ledger.** The receipt is authoritative. The winner's entry is
//! visible, so the replay takes the read path and returns a typed error.
//! This is why I8 exists: without the fingerprint the loser of a
//! same-ledger race and a harmless duplicate are indistinguishable, and a
//! client that treats the response as "already applied" silently drops a
//! batch it never sent.
//!
//! **Different keys and callers.** Receipt entries are keyed per
//! `(caller, key)`, so unrelated batches never share an entry and never
//! conflict with each other. The one exception is the contract instance,
//! discussed below.
//!
//! **Stale footprints.** A transaction simulates against one ledger and
//! may execute against a later one, where storage has moved underneath it.
//! Two cases follow, and neither is specific to this contract:
//!
//! - Simulated with no receipt (declares the entry read-write), executed
//!   after the receipt exists: the write conflicts with the live entry and
//!   the host rejects the transaction. The caller re-simulates and gets
//!   the typed error.
//! - Simulated with a live receipt (declares the entry read-only, because
//!   the function returned before writing), executed after the receipt
//!   expires: the function reaches its write against a read-only footprint
//!   and the host rejects the transaction.
//!
//! I9 keeps the second case from silently changing meaning: the replay path
//! re-writes the receipt it just read, so both branches declare the same
//! access type and the footprint never depends on state that can change
//! between simulation and execution.
//!
//! **The contract instance is a shared write point.** Every accepted
//! batch bumps the contract instance/code TTL, and the contract instance is
//! a single ledger entry shared by every caller. Because that bump is
//! threshold-guarded ([`CONTRACT_TTL_THRESHOLD_LEDGERS`]), it performs a
//! write only while the instance is already close to archival, and so
//! declares read-write only in that window. In other words: while the
//! contract is healthy, callers do not serialize on it; while it is within
//! ~1.4 h of being archived, concurrent `place_bets` calls can start
//! failing with ledger-level conflicts. The bump is worth keeping — without
//! it an idle contract is archived and every later call fails outright — but
//! this coupling is why there is deliberately **no reentrancy guard** here:
//! one would need an unconditional instance write, permanently serializing
//! every caller in the contract.
//!
//! # Forward-looking constraints for market state
//!
//! When market mutations land, they must not read-modify-write shared
//! market entries without their own conflict handling. Two batches touching
//! the same market in one ledger will conflict at the footprint level, and
//! the loser must be retried rather than assumed applied — the same rule
//! that applies to the receipt entry above.
//!
//! # Failure modes
//!
//! Every rejection is a typed [`Error`] returned *before* any state is
//! written: empty batch, oversized batch, `market_id == 0`, non-positive
//! `amount`, total overflow, spent idempotency key, and idempotency key
//! reused with a different batch. Because I2 and I4 hold, a caller may
//! retry the *same* token after a validation rejection — the token was
//! never consumed. A caller that loses the response of a *successful* call
//! cannot retry with that token; it should resubmit the identical batch to
//! learn which case applies, or submit a new batch under a fresh token.

use soroban_sdk::{Address, Bytes, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{
        DataKey, CONTRACT_TTL_LEDGERS, CONTRACT_TTL_THRESHOLD_LEDGERS, IDEM_KEY_TTL_LEDGERS,
        RECEIPT_EXTEND_THRESHOLD_LEDGERS,
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
///                                              pair was already spent on *this*
///                                              batch.
/// * [`Error::IdempotencyKeyReusedWithDifferentBatch`] – the pair was already
///                                              spent on a *different* batch.
///
/// All seven are returned *before* any state is written, so the caller may
/// correct the payload and retry with the same idempotency key.
///
/// # Idempotency semantics
///
/// The receipt is written to temporary storage **before** the batch is
/// applied, and only after the batch has fully validated. If a previous
/// call with the same key succeeded, the function returns
/// [`Error::IdempotentBatchAlreadyApplied`] or
/// [`Error::IdempotencyKeyReusedWithDifferentBatch`] without re-applying
/// the batch. Once written, the receipt expires after
/// [`IDEM_KEY_TTL_LEDGERS`] ledgers; after expiry the network has deleted
/// it, a new submission with the same token is accepted as a fresh
/// batch, and a client that lost the response of a successful call can
/// safely retry inside the window or resubmit under a new token after it.
/// See [`DataKey`] for why the receipt lives in temporary rather than
/// instance or persistent storage.
///
/// Writing the receipt before applying is what makes the guarantee hold
/// under concurrency: the receipt entry is declared read-write by every
/// invocation, so a racing transaction that targets the same token cannot
/// be included in the same ledger, and one that lands later sees the
/// receipt. If this call instead fails, the host reverts the receipt
/// together with everything else, so a rejected batch never burns a token.
/// See *Concurrency model* in the module documentation for the exact
/// guarantees and for what a client observes when it loses a same-ledger
/// race.
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
        let digest_key = DataKey::PlaceBetsDigest(caller.clone(), idempotency_key.clone());
        let digest = batch_digest(env, &bets);

        match env
            .storage()
            .temporary()
            .get::<DataKey, BatchReceipt>(&idem_key)
        {
            // A live receipt means this pair was already applied. Tell an
            // honest duplicate apart from a token collision (I8) so the
            // caller can tell "retry" from "use a new token".
            Some(_) => {
                let previous = env
                    .storage()
                    .temporary()
                    .get::<DataKey, BytesN<32>>(&digest_key);

                return Err(match previous {
                    Some(previous) => {
                        if previous == digest {
                            Error::IdempotentBatchAlreadyApplied
                        } else {
                            Error::IdempotencyKeyReusedWithDifferentBatch
                        }
                    }
                    // Receipt predates the fingerprint (or the fingerprint
                    // aged out on its own). Treat it as applied rather
                    // than as a collision: we cannot prove the batches
                    // differ, and claiming a conflict we cannot verify
                    // would be worse than the ambiguity.
                    None => Error::IdempotentBatchAlreadyApplied,
                });
            }
            None => {
                // Claim the token *before* the batch is applied. See the
                // module documentation for why, and for why a later
                // failure does not burn the token.
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
                    RECEIPT_EXTEND_THRESHOLD_LEDGERS,
                    IDEM_KEY_TTL_LEDGERS,
                );

                // Fingerprint of the batch this token was spent on.
                env.storage().temporary().set(&digest_key, &digest);
                env.storage().temporary().extend_ttl(
                    &digest_key,
                    RECEIPT_EXTEND_THRESHOLD_LEDGERS,
                    IDEM_KEY_TTL_LEDGERS,
                );
            }
        }
    }
    env.storage()
        .instance()
        .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);

    // Keep the instance (and any legacy keys in it) alive well beyond the
    // key window so replay protection can't lapse with an idle contract.
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_LEDGERS / 2, INSTANCE_TTL_LEDGERS);

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

/// Domain-separation tag for [`batch_digest`].
///
/// Versioned so the fingerprint scheme can change later without silently
/// reinterpreting receipts already on chain: a digest computed under a
/// different tag simply never matches, which degrades to the I8 fallback
/// (`IdempotentBatchAlreadyApplied`) instead of a false collision.
const BATCH_DIGEST_DOMAIN: &[u8] = b"talenttrust/place_bets/batch/v1";

/// Fingerprint the batch a token was spent on, for I8.
///
/// SHA-256 over a fixed-width, self-delimiting encoding: the domain tag,
/// the bet count as 4 little-endian bytes, then 8 bytes of `market_id`
/// and 16 bytes of `amount` per bet. Fixed widths make the encoding
/// unambiguous without length prefixes, and every field is written at its
/// natural width so no value can be re-encoded into a different preimage.
///
/// Only fields that decide *what* was submitted are covered. `caller` and
/// `idempotency_key` are deliberately excluded: they are already part of
/// the storage key, so including them would add nothing, and this keeps
/// the fingerprint a property of the batch alone.
///
/// The result is order-sensitive, which is the conservative choice: a
/// reordered batch is a different submission, and reporting it as a
/// collision is safe in a way that silently treating it as a duplicate
/// would not be. Callers do not control ordering across a retry anyway —
/// they resend what they built — so this only ever fires on a genuine
/// mismatch.
pub(crate) fn batch_digest(env: &Env, bets: &Vec<Bet>) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, BATCH_DIGEST_DOMAIN);

    for byte in bets.len().to_le_bytes() {
        preimage.push_back(byte);
    }
    for bet in bets.iter() {
        for byte in bet.market_id.to_le_bytes() {
            preimage.push_back(byte);
        }
        for byte in bet.amount.to_le_bytes() {
            preimage.push_back(byte);
        }
    }

    env.crypto().sha256(&preimage).to_bytes()
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
