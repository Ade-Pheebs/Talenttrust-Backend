use soroban_sdk::{contracttype, Address, BytesN};

/// TTL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// TTL applied to the contract instance whenever a batch is accepted.
///
/// Soroban instance storage shares a single ledger entry — and therefore a
/// single `liveUntilLedger` — with the contract instance itself, so the
/// replay window cannot outlive the contract.  The instance is extended to
/// twice [`IDEM_KEY_TTL_LEDGERS`] so it stays invokable for a full extra
/// window after the newest key expires; without that headroom, advancing the
/// ledger past the replay window would archive the contract and it could no
/// longer be called to observe the expiry at all.
pub const INSTANCE_TTL_LEDGERS: u32 = IDEM_KEY_TTL_LEDGERS * 2; // ~48 h

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// `PlaceBetsIdemLedger(user, key)` records the ledger sequence at which
/// that sentinel was written, which is what makes the replay window
/// enforceable (see [`IDEM_KEY_TTL_LEDGERS`]).
///
/// # Compatibility
///
/// The ledger variant is **appended** after the sentinel variant so the
/// discriminant of `PlaceBetsIdem` is unchanged and previously written
/// keys keep decoding.  A sentinel with no matching ledger entry is a key
/// written by an earlier version of the contract and is treated as a
/// durable (non-expiring) replay guard, so upgrading can never make a
/// previously consumed token replayable.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
    /// Ledger sequence at which the matching `PlaceBetsIdem` sentinel was
    /// consumed, used to enforce [`IDEM_KEY_TTL_LEDGERS`] in contract code.
    PlaceBetsIdemLedger(Address, BytesN<32>),
}
