"""Cross-check against the official RFC 9591 Appendix E.1 vector for
FROST(Ed25519, SHA-512): t=2 of n=3, signers P1 and P3, message "test".
Run directly: python3 tests/rfc9591_vectors.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import frost9591 as f  # noqa: E402

GROUP_PK = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"
P1_SHARE = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"
P3_SHARE = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"
P1_HIDING_COMMIT = "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3"
P1_BINDING_COMMIT = "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932"
P3_HIDING_COMMIT = "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91"
P3_BINDING_COMMIT = "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552"
P1_BINDING_FACTOR = "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603"
P3_BINDING_FACTOR = "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f"
P1_SIG_SHARE = "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603"
P3_SIG_SHARE = "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007"
SIG_R = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"
SIG_Z = "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"

failures = []


def check(name, got, want):
    ok = got == want
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        failures.append(name)
        print(f"      got : {got}")
        print(f"      want: {want}")


def main():
    msg = bytes.fromhex("74657374")  # "test"
    gpk = f.deserialize_element(bytes.fromhex(GROUP_PK))

    # Participant public keys derive from their secret shares.
    p1_pk = f.base_mul(f.deserialize_scalar(bytes.fromhex(P1_SHARE)))
    p3_pk = f.base_mul(f.deserialize_scalar(bytes.fromhex(P3_SHARE)))

    comms = [
        (1, f.deserialize_element(bytes.fromhex(P1_HIDING_COMMIT)),
         f.deserialize_element(bytes.fromhex(P1_BINDING_COMMIT))),
        (3, f.deserialize_element(bytes.fromhex(P3_HIDING_COMMIT)),
         f.deserialize_element(bytes.fromhex(P3_BINDING_COMMIT))),
    ]

    factors = f.compute_binding_factors(gpk, comms, msg)
    bf = {i: f.serialize_scalar(v).hex() for i, v in factors}
    check("binding factor P1", bf[1], P1_BINDING_FACTOR)
    check("binding factor P3", bf[3], P3_BINDING_FACTOR)

    r = f.compute_group_commitment(comms, factors)
    check("group commitment R", f.serialize_element(r).hex(), SIG_R)

    z1 = f.deserialize_scalar(bytes.fromhex(P1_SIG_SHARE))
    z3 = f.deserialize_scalar(bytes.fromhex(P3_SIG_SHARE))

    ok1, ev1 = f.verify_signature_share(1, p1_pk, (comms[0][1], comms[0][2]),
                                        z1, comms, gpk, msg)
    ok3, ev3 = f.verify_signature_share(3, p3_pk, (comms[1][1], comms[1][2]),
                                        z3, comms, gpk, msg)
    check("share P1 verifies", ok1, True)
    check("share P3 verifies", ok3, True)

    z = (z1 + z3) % f.L
    check("aggregate z", f.serialize_scalar(z).hex(), SIG_Z)
    ok, _ev = f.verify_aggregate(r, gpk, msg, z)
    check("aggregate signature verifies", ok, True)

    # RFC 8032 single-key sanity: the group PK matches the group secret.
    gsk = f.deserialize_scalar(bytes.fromhex(
        "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"))
    check("group public key derivation",
          f.serialize_element(f.base_mul(gsk)).hex(), GROUP_PK)

    # A tampered share must be pinpointed to its participant.
    ok_bad, _ = f.verify_signature_share(
        3, p3_pk, (comms[1][1], comms[1][2]), (z3 + 1) % f.L,
        comms, gpk, msg)
    check("tampered P3 share rejected", ok_bad, False)
    ok1_still, _ = f.verify_signature_share(
        1, p1_pk, (comms[0][1], comms[0][2]), z1, comms, gpk, msg)
    check("untampered P1 still valid", ok1_still, True)

    print()
    if failures:
        print(f"{len(failures)} RFC 9591 vector check(s) FAILED")
        return 1
    print("All RFC 9591 Appendix E.1 vector checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
