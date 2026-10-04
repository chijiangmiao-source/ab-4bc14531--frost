"""Offline countersigning verification logic.

Takes a parsed countersigning packet and applies, in order:

1. Envelope / structural rules (at most eight participants, threshold
   consistency, duplicate identifiers, strict RFC 9591 decodability).
2. Per-participant share verification in the stable ascending identifier
   order mandated by RFC 9591 (Section 4.3 / 5.3).
3. Aggregate checks: the group commitment R is recomputed from the FULL
   commitment set, z is recomputed as the sum of the submitted shares
   (anti-splicing), and the cofactor equation [8]zB = [8]R + [8]cPK is
   evaluated (RFC 9591 Section 6.1).

Every equation contributes a residual summary so a rejection names the
participant and the exact relation that failed.
"""

from __future__ import annotations

import hashlib
import json
import re

from . import frost9591 as f

MAX_PARTICIPANTS = 8
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
HEX32_RE = re.compile(r"^[0-9a-fA-F]{64}$")

REQUIRED_PARTICIPANT_FIELDS = (
    "identifier",
    "public_key_share",
    "hiding_commitment",
    "binding_commitment",
    "signature_share",
)


class PacketShapeError(ValueError):
    """The JSON packet itself is missing required fields."""


def canonical_packet_bytes(packet: dict) -> bytes:
    return json.dumps(packet, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def packet_digest(packet: dict) -> str:
    return hashlib.sha256(canonical_packet_bytes(packet)).hexdigest()


def _hex32(value, what: str, reasons: list):
    if not isinstance(value, str) or not HEX32_RE.fullmatch(value):
        reasons.append(f"{what}: expected 64 hex chars (32 bytes)")
        return None
    return bytes.fromhex(value)


def _message_bytes(packet: dict, reasons: list):
    msg_hex = packet.get("message_hex")
    msg_text = packet.get("message")
    if msg_hex is not None:
        if not isinstance(msg_hex, str):
            reasons.append("message_hex: must be a hex string")
            return None
        try:
            raw = bytes.fromhex(msg_hex)
        except ValueError:
            reasons.append("message_hex: malformed hexadecimal")
            return None
        if msg_text is not None:
            try:
                if msg_text.encode("utf-8") != raw:
                    reasons.append("message and message_hex disagree")
                    return None
            except AttributeError:
                reasons.append("message: must be a UTF-8 string")
                return None
        return raw
    if isinstance(msg_text, str):
        return msg_text.encode("utf-8")
    reasons.append("message: original message string is required")
    return None


def _residual(left_hex: str, right_hex: str, equal: bool) -> dict:
    return {
        "equation_left": left_hex,
        "equation_right": right_hex,
        "equal": equal,
        "residual_digest": hashlib.sha256(
            b"eq|" + left_hex.encode() + b"|" + right_hex.encode()
        ).hexdigest()[:32],
    }


def verify_packet(packet: dict) -> dict:
    """Verify one countersigning packet. Never raises for rule failures."""
    reasons: list[str] = []
    participant_results = []
    aggregate_result = {"status": "skipped", "reasons": []}
    first_failed = None

    audit_id = packet.get("audit_id")
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.fullmatch(audit_id):
        reasons.append("audit_id: required, 1-128 chars [A-Za-z0-9_.-]")

    threshold = packet.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) \
            or not 1 <= threshold <= MAX_PARTICIPANTS:
        reasons.append(f"threshold: integer in [1,{MAX_PARTICIPANTS}] required")
        threshold = None

    msg = _message_bytes(packet, reasons)

    gpk_raw = _hex32(packet.get("group_public_key"),
                     "group_public_key", reasons)
    gpk = None
    if gpk_raw is not None:
        try:
            gpk = f.deserialize_element(gpk_raw)
        except f.DecodeError as exc:
            reasons.append(f"group_public_key: {exc}")

    raw_participants = packet.get("participants")
    if not isinstance(raw_participants, list) or not raw_participants:
        reasons.append("participants: non-empty list required")
        raw_participants = []
    if len(raw_participants) > MAX_PARTICIPANTS:
        reasons.append(
            f"participants: at most {MAX_PARTICIPANTS} signers are accepted")

    agg = packet.get("aggregate_signature")
    if not isinstance(agg, dict):
        reasons.append("aggregate_signature: object with R and z required")
        agg = {}

    # Decode every participant's fields first; malformed rows stay visible.
    decoded_rows = []
    seen_ids = set()
    for submitted_index, row in enumerate(raw_participants):
        row_reasons = []
        if not isinstance(row, dict):
            reasons.append(f"participant[{submitted_index}]: must be an object")
            continue
        for field_name in REQUIRED_PARTICIPANT_FIELDS:
            if field_name not in row:
                row_reasons.append(f"missing field {field_name}")
        ident_raw = _hex32(row.get("identifier"), "identifier", row_reasons)
        pk_raw = _hex32(row.get("public_key_share"),
                        "public_key_share", row_reasons)
        hide_raw = _hex32(row.get("hiding_commitment"),
                          "hiding_commitment", row_reasons)
        bind_raw = _hex32(row.get("binding_commitment"),
                          "binding_commitment", row_reasons)
        share_raw = _hex32(row.get("signature_share"),
                           "signature_share", row_reasons)

        ident = pk_p = hide_p = bind_p = share = None
        if ident_raw is not None:
            try:
                ident = f.deserialize_scalar(ident_raw, nonzero=True)
            except f.DecodeError as exc:
                row_reasons.append(f"identifier: {exc}")
            else:
                if ident in seen_ids:
                    reasons.append(
                        f"duplicate participant identifier "
                        f"{f.serialize_scalar(ident).hex()}")
                seen_ids.add(ident)
        if pk_raw is not None:
            try:
                pk_p = f.deserialize_element(pk_raw)
            except f.DecodeError as exc:
                row_reasons.append(f"public_key_share: {exc}")
        if hide_raw is not None:
            try:
                hide_p = f.deserialize_element(hide_raw)
            except f.DecodeError as exc:
                row_reasons.append(f"hiding_commitment: {exc}")
        if bind_raw is not None:
            try:
                bind_p = f.deserialize_element(bind_raw)
            except f.DecodeError as exc:
                row_reasons.append(f"binding_commitment: {exc}")
        if share_raw is not None:
            try:
                share = f.deserialize_scalar(share_raw)
            except f.DecodeError as exc:
                row_reasons.append(f"signature_share: {exc}")

        decoded_rows.append({
            "submitted_index": submitted_index,
            "identifier": ident,
            "pk": pk_p,
            "hiding": hide_p,
            "binding": bind_p,
            "share": share,
            "row_reasons": row_reasons,
        })
        reasons.extend(f"participant[{submitted_index}]: {r}"
                       for r in row_reasons)

    if (threshold is not None and raw_participants
            and len(raw_participants) != threshold):
        reasons.append(
            f"threshold mismatch: threshold={threshold} but "
            f"{len(raw_participants)} participant packets were submitted")

    # Stable RFC 9591 order: ascending identifier; undecodable ids sink last
    # in submitted order.
    decoded_rows.sort(key=lambda r: (r["identifier"] is None,
                                     r["identifier"] if r["identifier"] is not None else 0,
                                     r["submitted_index"]))

    commitment_list = None
    factors = None
    group_commitment = None
    challenge = None
    can_evaluate = (gpk is not None and msg is not None
                    and all(r["identifier"] is not None
                            and r["hiding"] is not None
                            and r["binding"] is not None
                            for r in decoded_rows)
                    and len({r["identifier"] for r in decoded_rows})
                    == len(decoded_rows))
    if can_evaluate:
        commitment_list = [(r["identifier"], r["hiding"], r["binding"])
                           for r in decoded_rows]
        try:
            factors = f.compute_binding_factors(gpk, commitment_list, msg)
            group_commitment = f.compute_group_commitment(
                commitment_list, factors)
            challenge = f.compute_challenge(
                group_commitment, gpk, msg)
        except (f.DecodeError, ValueError) as exc:
            reasons.append(f"binding-factor computation failed: {exc}")
            can_evaluate = False

    for order, r in enumerate(decoded_rows, start=1):
        entry = {
            "order": order,
            "submitted_index": r["submitted_index"],
            "identifier": (f.serialize_scalar(r["identifier"]).hex()
                           if r["identifier"] is not None
                           else _raw_or_none(raw_participants, r, "identifier")),
            "status": "malformed",
            "binding_factor": None,
            "lagrange_lambda": None,
            "residual": None,
            "reasons": list(r["row_reasons"]),
        }
        if (not r["row_reasons"] and can_evaluate and r["pk"] is not None
                and r["share"] is not None):
            valid, ev = f.verify_signature_share(
                r["identifier"], r["pk"], (r["hiding"], r["binding"]),
                r["share"], commitment_list, gpk, msg)
            entry.update({
                "status": "valid" if valid else "invalid",
                "binding_factor": ev["binding_factor"],
                "lagrange_lambda": ev["lambda"],
                "residual": _residual(ev["left"], ev["right"], valid),
            })
            if not valid:
                entry["reasons"].append(
                    "share equation [z_i]B = comm_share + [c*lambda_i]PK_i "
                    "does not hold")
                if first_failed is None:
                    first_failed = entry["identifier"]
        elif not r["row_reasons"]:
            entry["reasons"].append(
                "share not evaluated: packet-level inputs undecodable")
        participant_results.append(entry)

    # --- aggregate ------------------------------------------------------
    r_raw = _hex32(agg.get("R"), "aggregate_signature.R", reasons)
    z_raw = _hex32(agg.get("z"), "aggregate_signature.z", reasons)
    submitted_r = submitted_z = None
    if r_raw is not None:
        try:
            submitted_r = f.deserialize_element(r_raw)
        except f.DecodeError as exc:
            reasons.append(f"aggregate_signature.R: {exc}")
    if z_raw is not None:
        try:
            submitted_z = f.deserialize_scalar(z_raw)
        except f.DecodeError as exc:
            reasons.append(f"aggregate_signature.z: {exc}")

    if can_evaluate:
        agg_reasons = []
        r_match = z_match = cofactor_ok = False
        if submitted_r is not None:
            r_match = f.point_eq(submitted_r, group_commitment)
            if not r_match:
                agg_reasons.append(
                    "submitted R != commitment computed from the full "
                    "dual-nonce commitment set (possible commitment splicing)")
        shares_all_decode = all(r["share"] is not None for r in decoded_rows)
        recomputed_z = None
        if shares_all_decode:
            recomputed_z = sum(r["share"] for r in decoded_rows) % f.L
            if submitted_z is not None:
                z_match = recomputed_z == submitted_z
                if not z_match:
                    agg_reasons.append(
                        "submitted z != sum of submitted signature shares "
                        "(possible share/aggregate splicing)")
        else:
            agg_reasons.append("cannot recompute z: malformed signature share")

        if submitted_r is not None and submitted_z is not None:
            cofactor_ok, ev = f.verify_aggregate(
                submitted_r, gpk, msg, submitted_z)
            residual = _residual(ev["left"], ev["right"], cofactor_ok)
            if not cofactor_ok:
                agg_reasons.append(
                    "cofactor equation [8]zB = [8]R + [8]cPK does not hold")
        else:
            residual = None

        aggregate_result = {
            "status": "evaluated",
            "submitted_R": agg.get("R"),
            "computed_R": f.serialize_element(group_commitment).hex(),
            "R_matches_commitment_set": r_match,
            "submitted_z": agg.get("z"),
            "recomputed_z": (f.serialize_scalar(recomputed_z).hex()
                             if recomputed_z is not None else None),
            "z_matches_share_sum": z_match,
            "cofactor_equation_holds": cofactor_ok if residual else False,
            "challenge": f.serialize_scalar(challenge).hex(),
            "residual": residual,
            "reasons": agg_reasons,
        }
        reasons.extend(f"aggregate: {x}" for x in agg_reasons)

    verdict = "ACCEPTED" if not reasons else "REJECTED"
    return {
        "audit_id": audit_id,
        "ciphersuite": f.CONTEXT_STRING.decode(),
        "verdict": verdict,
        "rejected_reasons": reasons,
        "first_failed_participant": first_failed,
        "participant_count": len(raw_participants),
        "threshold": threshold,
        "participants": participant_results,
        "aggregate": aggregate_result,
    }


def _raw_or_none(raw_participants, row, field):
    try:
        return raw_participants[row["submitted_index"]].get(field)
    except (IndexError, AttributeError):
        return None
