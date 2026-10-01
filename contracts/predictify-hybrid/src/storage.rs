use soroban_sdk::{contracttype, Address, BytesN=};

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the network deletes the receipt and a fresh submission
/// with the same token is treated as a new batch.
///
/// **Network floor.** A temporary entry can never live for less than the
/// network's `min_temp_entry_ttl` setting. A receipt is therefore written
/// with `extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS)` — see
/// [`RECEIPT_EXTEND_THRESHOLD_LEDGERS`] — which renews it to exactly this
/// window on every network where `min_temp_entry_ttl` does not already
/// exceed it. If `min_temp_entry_ttl` were ever configured above
/// [`IDEM_KEY_TTL_LEDGERS`], the extension is skipped and the entry
/// simply outlives the target window, which is safe. A caller must not
/// assume a token becomes reusable sooner than this, nor later.
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

/// Threshold passed to `extend_ttl` when a receipt is written.
///
/// A receipt is written exactly once and is never re-extended: a replay
/// is rejected outright rather than renewing the window. So the threshold
/// is only ever compared against a *freshly created* entry, whose
/// remaining TTL is the network's `min_temp_entry_ttl`, not an arbitrary
/// caller-supplied value.
///
/// That makes the target TTL the correct threshold, and a lower one a
/// latent bug: with a threshold below `min_temp_entry_ttl` the extension
/// is skipped and the receipt silently dies after `min_temp_entry_ttl`
/// instead of the documented [`IDEM_KEY_TTL_LEDGERS`]. Setting the
/// threshold to the target makes the window independent of network
/// configuration: it fires whenever the entry does not already outlive the
/// window, and the no-op case is the one where it does not matter.
pub const RECEIPT_EXTEND_THRESHOLD_LEDGERS: u32 = IDEM_KEY_TTL_LEDGERS;

/// Retained so existing imports keep compiling.
///
/// This threshold used to guard the receipt extension, which made the
/// replay window depend on the network's `min_temp_entry_ttl` — see
/// [`RECEIPT_EXTEND_THRESHOLD_LEDGERS`] for why that was wrong. It is no
/// longer used for the receipt; do not reintroduce it there.
pub const IDEM_KEY_TTL_THRESHOLD_LEDGERS: u32 = 1_000; // ~1.4 h at 5 s/ledger

/// TTL applied to the contract instance and its Wasm code every time a
/// batch is accepted.
///
/// The contract instance is a persistent-durability ledger entry with its
/// own TTL, and it is *not* kept alive by the per-receipt TTLs above.
/// Without bumping it here, a contract that fell idle long enough would
/// be archived by the network, and every subsequent `place_bets` would
/// fail with a host error — including calls whose receipts are still
/// live. Recovery would need a paid restore transaction, so the contract
/// would be unavailable exactly when users are trying to submit bets.
///
/// Set comfortably **above** [`IDEM_KEY_TTL_LEDGERS`] so a live receipt
/// never outlives the contract that minted it in ordinary operation.
pub const CONTRACT_TTL_LEDGERS: u32 = 34_560; // ~48 h at 5 s/ledger

/// Lower bound on the *remaining* TTL of the contract instance and code
/// before [`CONTRACT_TTL_LEDGERS`] is (re)applied to them.
///
/// Must be far *below* [`CONTRACT_TTL_LEDGERS`]: the bump only fires when
/// an entry is already close to expiring, so a threshold at or above the
/// network's initial instance TTL would never fire and would also risk
/// *shortening* a longer-lived instance.
pub const CONTRACT_TTL_THRESHOLD_LEDGERS: u32 = 1_000; // ~1.4 h at 5 s/ledger

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(caller, key)` stores a [`crate::bets::BatchReceipt`]
/// once a `place_bets` batch has been accepted. The composite key binds
/// the token to the submitting address so two different callers may
/// reuse the same 32-byte token independently without conflict, and no
/// caller can consume or replay another caller's token.
///
/// `PlaceBetsDigest(caller, key)` is written in the same transaction and
/// under the same TTL, and holds a hash of the batch the token was
/// accepted for. It is what lets a replay distinguish "the same batch,
/// submitted twice" from "a different batch submitted under a token that
/// is already spent" — see [`crate::bets`] for the concurrency model.
/// The two entries cannot diverge: they are written together, and a
/// failed transaction reverts both.
///
/// # Why temporary storage, and not instance or persistent
///
/// **Not instance storage.** The contract instance is a *single* ledger
/// entry. Every key written under it grows that one entry, and the host
/// rejects the write once the serialized entry exceeds `max_entry_size`
/// (64 KiB by default). That rejection is not per-key: it fails *every*
/// subsequent mutation of the instance, so a caller who merely kept
/// submitting batches with fresh tokens would eventually push the entry
/// over the limit and permanently disable `place_bets` for everybody.
/// There is no on-chain remedy short of a contract upgrade, and stake
/// already accepted by users would be stranded. This is the defect the
/// idempotency feature shipped with.
///
/// **Not persistent storage.** Deduplication requires *reading* the
/// receipt, and an expired persistent entry cannot be read at all: the
/// host rejects the whole transaction, because the entry has been
/// archived and restoring it costs a fee. A persistent receipt would
/// therefore turn the documented "after expiry the token may be reused"
/// behavior into "after expiry the token is permanently unusable, with an
/// opaque ledger-level failure" — worse than either reusing the token or
/// losing the response would have been. (The test host surfaces the same
/// condition as `accessed a key that has been archived`.)
///
/// **Temporary storage** gives exactly the required semantics: one
/// ledger entry per key, so the instance entry stays a constant size
/// however many batches succeed; an entry that has aged out simply reads
/// as absent; and the network deletes it at `liveUntil`, so receipts
/// cannot accumulate either.
///
/// See the module documentation in [`crate::bets`] for the invariants
/// that depend on this choice.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency receipt for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
    /// SHA-256 fingerprint of the batch accepted under
    /// `PlaceBetsIdem(caller, key)`.
    ///
    /// Stored separately rather than as a field on
    /// [`crate::bets::BatchReceipt`] so that the receipt's serialized
    /// shape is unchanged. Adding a field would make every previously
    /// written receipt undecodable, and the host's `get` decodes through
    /// `unwrap_optimized`, which traps on wasm rather than returning an
    /// error — so an in-place migration would turn every live receipt
    /// into a contract-wide failure for as long as the entry exists.
    PlaceBetsDigest(Address, BytesN<32>),
}
