"""RFC 9591 FROST(Ed25519, SHA-512) verification primitives.

Implements exactly the ciphersuite in Section 6.1 of RFC 9591:

* group: edwards25519 (RFC 8032), Ne = Ns = 32, cofactor 8
* H = SHA-512 with contextString "FROST-ED25519-SHA512-v1"
* H1 = H(context || "rho"  || m) reduced mod L  (binding factors)
* H2 = H(m)                       reduced mod L  (challenge, no domain
                                                 separator for RFC 8032
                                                 compatibility)
* H4 = H(context || "msg" || m), 64 raw bytes
* H5 = H(context || "com" || m), 64 raw bytes
* aggregate check: [8][z]B = [8]R + [8][c]PK

Only operations needed by the offline countersigning verifier are
included; this module never handles any signing secret material.
"""

from __future__ import annotations

import hashlib
import hmac

CONTEXT_STRING = b"FROST-ED25519-SHA512-v1"

# --- edwards25519 field / group constants ---------------------------------
P = 2 ** 255 - 19
# Prime subgroup order L = 2^252 + 27742317777372353535851937790883648493
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
D2 = (2 * D) % P

# Standard base point B, y = 4/5 mod p, x parity even.
_BY = (4 * pow(5, P - 2, P)) % P


def _x_for_y(y: int) -> int:
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    # x = (u/v)^((p+3)/8)
    x = pow(u * pow(v, P - 2, P) % P, (P + 3) // 8, P)
    if (x * x * v - u) % P != 0:
        x = (x * pow(2, (P - 1) // 4, P)) % P
    if (x * x * v - u) % P != 0:
        raise ValueError("not a point on the curve")
    if x % 2 != 0:
        x = P - x
    return x


_BX = _x_for_y(_BY)
B = (_BX, _BY, 1, (_BX * _BY) % P)  # extended coordinates (X, Y, Z, T)


# --- field / point arithmetic ---------------------------------------------
class DecodeError(ValueError):
    """Raised on non-canonical scalar or point encodings."""


def _add(p, q):
    """Unified addition in extended twisted-Edwards coordinates
    (add-2008-hwcd-2); valid also for doubling."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * D2 * t2) % P
    dd = (z1 * 2 * z2) % P
    e = (b - a) % P
    f = (dd - c) % P
    g = (dd + c) % P
    h = (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(p):
    x1, y1, z1, _t1 = p
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    d = (-a) % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalar_mul(point, scalar: int):
    # NOTE: no implicit reduction here.  Prime-subgroup points have order
    # L so reduction would be harmless for them, but the deserialization
    # subgroup check needs the literal multiple [L]P (and cofactor checks
    # use [8]*); reducing would make [L]P trivially identity.
    if scalar == 0:
        return (0, 1, 1, 0)
    q = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            q = _add(q, point)
        point = _double(point)
        scalar >>= 1
    return q


def base_mul(scalar: int):
    return _scalar_mul(B, scalar)


def _affine(point):
    x, y, z, _t = point
    zi = pow(z, P - 2, P)
    return (x * zi % P, y * zi % P)


def point_eq(p, q) -> bool:
    xp, yp = _affine(p)
    xq, yq = _affine(q)
    return xp == xq and yp == yq


def is_identity(point) -> bool:
    return point_eq(point, (0, 1, 1, 0))


def _z_of(point):
    return point[2]


# --- RFC 8032 encoding ------------------------------------------------------
def serialize_element(point) -> bytes:
    if point_eq(point, (0, 1, 1, 0)):
        # RFC 9591 SerializeElement raises on identity; callers that need
        # an identity marker use identity_marker().
        raise DecodeError("cannot serialize the identity element")
    x, y = _affine(point)
    out = y.to_bytes(32, "little")
    if x & 1:
        out = bytearray(out)
        out[31] |= 0x80
        out = bytes(out)
    return out


def identity_marker(point) -> str:
    """Stable textual placeholder for an identity equation side."""
    return "INFINITY" if point_eq(point, (0, 1, 1, 0)) else serialize_element(point).hex()


def deserialize_element(buf: bytes):
    """RFC 8032 5.1.3 decode + prime-order subgroup check ([L]P = I)."""
    if not isinstance(buf, (bytes, bytearray)) or len(buf) != 32:
        raise DecodeError("element encoding must be exactly 32 bytes")
    sign = buf[31] >> 7
    y = int.from_bytes(bytes(buf[:32]), "little") & ((1 << 255) - 1)
    if y >= P:
        raise DecodeError("y coordinate out of field")
    try:
        x = _x_for_y(y)
    except ValueError as exc:
        raise DecodeError("point not on curve") from exc
    if sign:
        x = P - x
    if x == 0 and y == 1:
        # RFC 9591: DeserializeElement rejects the identity element.
        raise DecodeError("encoded element is the identity")
    point = (x, y, 1, x * y % P)
    # Cofactor/subgroup validation: multiply by prime subgroup order.
    if not point_eq(_scalar_mul(point, L), (0, 1, 1, 0)):
        raise DecodeError("point is not in the prime-order subgroup")
    return point


def serialize_scalar(scalar: int) -> bytes:
    scalar %= L
    return scalar.to_bytes(32, "little")


def deserialize_scalar(buf: bytes, *, nonzero: bool = False) -> int:
    """Strict canonical 32-byte little-endian scalar in [0, L-1].

    The three most significant bits MUST be zero, and the integer MUST be
    below the group order; anything else (including reduced-but-noncanonical
    encodings) is rejected.
    """
    if not isinstance(buf, (bytes, bytearray)) or len(buf) != 32:
        raise DecodeError("scalar encoding must be exactly 32 bytes")
    raw = bytes(buf)
    if raw[31] & 0xE0:
        raise DecodeError("non-canonical scalar: top three bits are set")
    s = int.from_bytes(raw, "little")
    if s >= L:
        raise DecodeError("non-canonical scalar: value >= group order")
    if nonzero and s == 0:
        raise DecodeError("scalar must be non-zero")
    return s


# --- domain-separated hashes (RFC 9591 6.1) --------------------------------
def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _hash_to_scalar(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % L


def h1(data: bytes) -> int:
    return _hash_to_scalar(CONTEXT_STRING + b"rho" + data)


def h2(data: bytes) -> int:
    # Deliberately no contextString, per Section 6.1 (RFC 8032 compat).
    return _hash_to_scalar(data)


def h4(data: bytes) -> bytes:
    return _sha512(CONTEXT_STRING + b"msg" + data)


def h5(data: bytes) -> bytes:
    return _sha512(CONTEXT_STRING + b"com" + data)


# --- FROST list / factor / commitment helpers ------------------------------
def encode_group_commitment_list(commitment_list) -> bytes:
    """commitment_list: sorted [(id, H_i, E_i)] tuples of decoded values."""
    out = b""
    for identifier, hiding, binding in commitment_list:
        out += serialize_scalar(identifier)
        out += serialize_element(hiding)
        out += serialize_element(binding)
    return out


def compute_binding_factors(group_public_key, commitment_list, msg: bytes):
    gpk_enc = serialize_element(group_public_key)
    msg_hash = h4(msg)
    comm_hash = h5(encode_group_commitment_list(commitment_list))
    prefix = gpk_enc + msg_hash + comm_hash
    factors = []
    for identifier, _h, _b in commitment_list:
        factors.append((identifier, h1(prefix + serialize_scalar(identifier))))
    return factors


def compute_group_commitment(commitment_list, binding_factor_list):
    factors = dict(binding_factor_list)
    r = (0, 1, 1, 0)
    for identifier, hiding, binding in commitment_list:
        r = _add(r, _add(hiding, _scalar_mul(binding, factors[identifier])))
    return r


def compute_challenge(group_commitment, group_public_key, msg: bytes) -> int:
    return h2(
        serialize_element(group_commitment)
        + serialize_element(group_public_key)
        + msg
    )


def derive_interpolating_value(identifiers, x_i: int) -> int:
    """Lagrange coefficient at 0 over GF(L) for the given signer set."""
    if x_i not in identifiers:
        raise ValueError("invalid parameters: identifier not in list")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("invalid parameters: duplicate identifier")
    num, den = 1, 1
    for x_j in identifiers:
        if x_j == x_i:
            continue
        num = num * x_j % L
        den = den * (x_j - x_i) % L
    return num * pow(den, L - 2, L) % L


def verify_signature_share(identifier, pk_i, comm_i, sig_share,
                           commitment_list, group_public_key, msg):
    """RFC 9591 Section 5.3. Returns (valid, evidence_dict)."""
    factors = compute_binding_factors(group_public_key, commitment_list, msg)
    factor = dict(factors)[identifier]
    group_commitment = compute_group_commitment(commitment_list, factors)
    hiding, binding = comm_i
    comm_share = _add(hiding, _scalar_mul(binding, factor))
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    lam = derive_interpolating_value(
        [i for i, _h, _b in commitment_list], identifier)

    left = base_mul(sig_share)
    right = _add(comm_share, _scalar_mul(pk_i, challenge * lam % L))
    valid = point_eq(left, right)
    evidence = {
        "binding_factor": serialize_scalar(factor).hex(),
        "lambda": serialize_scalar(lam).hex(),
        "challenge": serialize_scalar(challenge).hex(),
        "left": identity_marker(left),
        "right": identity_marker(right),
        "residual_digest": hashlib.sha256(
            b"share-residual|"
            + identity_marker(left).encode()
            + b"|"
            + identity_marker(right).encode()
        ).hexdigest()[:32],
    }
    return valid, evidence


def verify_aggregate(group_commitment, group_public_key, msg, z):
    """RFC 9591 6.1 cofactor equation [8]z B = [8]R + [8]c PK."""
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    left = _scalar_mul(base_mul(z), 8)
    right = _add(_scalar_mul(group_commitment, 8),
                 _scalar_mul(group_public_key, (8 * challenge) % L))
    valid = point_eq(left, right)
    evidence = {
        "challenge": serialize_scalar(challenge).hex(),
        "left": identity_marker(left),
        "right": identity_marker(right),
        "residual_digest": hashlib.sha256(
            b"aggregate-residual|"
            + identity_marker(left).encode()
            + b"|"
            + identity_marker(right).encode()
        ).hexdigest()[:32],
    }
    return valid, evidence


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
