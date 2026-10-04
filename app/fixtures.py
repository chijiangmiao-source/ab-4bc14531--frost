"""Signing-side FROST helpers — TEST FIXTURES / DEMO ONLY.

The product is an offline *verification* console and never holds secret
material.  This module exists solely so the acceptance service and the
demo endpoint can mint well-formed threshold countersigning packages
(and deliberate mutations of them) to exercise the real verification API.

Produces a t-of-t signing subset (the submitted packet always contains
exactly the threshold number of signers), per RFC 9591 Section 5.
"""

from __future__ import annotations

import copy
import hashlib
import os

from . import frost9591 as f


def _le(scalar: int) -> str:
    return f.serialize_scalar(scalar % f.L).hex()


def make_countersign_package(
    message: bytes,
    threshold: int = 2,
    identifiers=(1, 3),
    *,
    rng_seed: bytes | None = None,
    audit_id: str = "AUDIT-DEMO-0001",
):
    """Build a valid FROST(Ed25519, SHA-512) countersigning packet.

    A degree-(t-1) Shamir polynomial is created for the group secret;
    only the submitted signers' shares are used.
    """
    if len(identifiers) != threshold:
        raise ValueError("submitted signer count must equal the threshold")

    def make_rng():
        counter = 0

        def next_rand() -> int:
            nonlocal counter
            if rng_seed is None:
                return int.from_bytes(os.urandom(32), "little") % f.L
            out = hashlib.sha256(rng_seed + counter.to_bytes(4, "little")).digest()
            counter += 1
            return int.from_bytes(out, "little") % f.L

        return next_rand

    next_rand = make_rng()

    # Secret polynomial f(x) = s + a1 x + ... + a_{t-1} x^(t-1).
    coeffs = [next_rand() for _ in range(threshold)]
    group_secret = coeffs[0]
    gpk = f.base_mul(group_secret)

    shares = {}
    for i in identifiers:
        y = 0
        for power, a in enumerate(coeffs):
            y = (y + a * pow(i, power, f.L)) % f.L
        shares[i] = y

    # Round one: hiding + binding nonces and commitments per signer.
    nonces = {}
    comms = []
    for i in identifiers:
        h_nonce = next_rand()
        b_nonce = next_rand()
        nonces[i] = (h_nonce, b_nonce)
        comms.append((i, f.base_mul(h_nonce), f.base_mul(b_nonce)))
    comms.sort(key=lambda t: t[0])

    factors = f.compute_binding_factors(gpk, comms, message)
    factor_by_id = dict(factors)
    r_point = f.compute_group_commitment(comms, factors)
    challenge = f.compute_challenge(r_point, gpk, message)

    ids_sorted = [i for i, _h, _b in comms]
    sig_shares = {}
    participants = []
    for idx, i in enumerate(ids_sorted):
        lam = f.derive_interpolating_value(ids_sorted, i)
        h_nonce, b_nonce = nonces[i]
        z_i = (h_nonce + b_nonce * factor_by_id[i]
               + lam * shares[i] * challenge) % f.L
        sig_shares[i] = z_i
        _, h_comm, b_comm = comms[idx]
        participants.append({
            "identifier": _le(i),
            "public_key_share": f.serialize_element(f.base_mul(shares[i])).hex(),
            "hiding_commitment": f.serialize_element(h_comm).hex(),
            "binding_commitment": f.serialize_element(b_comm).hex(),
            "signature_share": _le(z_i),
        })

    z = sum(sig_shares.values()) % f.L
    return {
        "audit_id": audit_id,
        "message": message.decode("utf-8", errors="replace"),
        "message_hex": message.hex(),
        "ciphersuite": "FROST-ED25519-SHA512-v1",
        "group_public_key": f.serialize_element(gpk).hex(),
        "threshold": threshold,
        "participants": participants,
        "aggregate_signature": {
            "R": f.serialize_element(r_point).hex(),
            "z": _le(z),
        },
    }


def tamper(package: dict, *, kind: str, index: int | None = None) -> dict:
    """Return a deep-ish copy with one mutation applied.

    kind in:
      share_flip      - flip one bit in one participant's signature share
      share_add_one   - add 1 mod L to a signature share, keep canonical
      commitment_swap  - swap hiding commitments between two participants
      aggregate_z_swap - replace aggregate z with a value from another run
      message_change   - alter the message (used for conflict tests too)
      noncanonical_scalar - force top bits on in a signature share
      non_subgroup_point - replace a public key share encoding
    """
    p = copy.deepcopy(package)
    if index is None:
        index = 0

    if kind in ("share_flip", "share_add_one"):
        raw = bytearray(bytes.fromhex(p["participants"][index]["signature_share"]))
        if kind == "share_flip":
            raw[0] ^= 0x01
        else:
            s = (int.from_bytes(raw, "little") + 1) % f.L
            raw = bytearray(f.serialize_scalar(s))
        p["participants"][index]["signature_share"] = bytes(raw).hex()
    elif kind == "commitment_swap":
        if len(p["participants"]) < 2:
            raise ValueError("need at least two participants")
        a = p["participants"][0]["hiding_commitment"]
        b = p["participants"][1]["hiding_commitment"]
        p["participants"][0]["hiding_commitment"] = b
        p["participants"][1]["hiding_commitment"] = a
    elif kind == "aggregate_z_swap":
        other = make_countersign_package(b"different message contents",
                                         rng_seed=b"other-run")
        p["aggregate_signature"]["z"] = other["aggregate_signature"]["z"]
    elif kind == "message_change":
        p["message"] = p["message"] + " [ALTERED]"
        p.pop("message_hex", None)
    elif kind == "noncanonical_scalar":
        raw = bytearray(bytes.fromhex(p["participants"][index]["signature_share"]))
        raw[31] |= 0xE0  # top three bits set: MUST be rejected
        p["participants"][index]["signature_share"] = bytes(raw).hex()
    elif kind == "non_subgroup_point":
        # Low-order point encoding (all zeros except... use the identity
        # encoding, which is explicitly excluded by DeserializeElement).
        p["participants"][index]["public_key_share"] = "00" * 32
    else:
        raise ValueError(f"unknown tamper kind: {kind}")
    return p
