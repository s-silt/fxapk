"""Bounded independent checks of explicit AES hypotheses, never key discovery."""
from __future__ import annotations

from .common import hex_bytes, json_value, result, sha256


def review(data: bytes, options: dict) -> dict:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    document = json_value(data)
    if not isinstance(document, dict):
        raise ValueError("crypto_input_invalid")
    algorithm = document.get("algorithm")
    if algorithm not in {"AES-GCM", "AES-CBC-PKCS7"}:
        return result("unsupported", ["algorithm_unsupported"])
    key = hex_bytes(document.get("key_hex"), 32)
    if len(key) not in {16, 24, 32}:
        raise ValueError("aes_key_size_invalid")
    vectors = document.get("vectors")
    if not isinstance(vectors, list) or not 1 <= len(vectors) <= 32:
        raise ValueError("vector_budget_or_shape")
    rows, seen, roles = [], set(), set()
    for index, vector in enumerate(vectors):
        row = {"index": index, "state": "failed", "provided_output_match": None}
        rows.append(row)
        try:
            if not isinstance(vector, dict) or vector.get("role") not in {"fit", "validation"}:
                raise ValueError("vector_role_invalid")
            role = vector["role"]
            cipher = hex_bytes(vector.get("ciphertext_hex"))
            iv = hex_bytes(vector.get("iv_hex"), 128)
            aad = hex_bytes(vector.get("aad_hex", ""))
            expected = hex_bytes(vector["expected_plaintext_hex"]) if "expected_plaintext_hex" in vector else None
            identity = (cipher, iv, aad)
            if identity in seen:
                raise ValueError("duplicate_vector_not_independent")
            seen.add(identity)
            row.update(role=role, ciphertext_sha256=sha256(cipher))
            if algorithm == "AES-GCM":
                if not 8 <= len(iv) <= 128 or len(cipher) < 16:
                    raise ValueError("gcm_input_size_invalid")
                plaintext = AESGCM(key).decrypt(iv, cipher, aad)
                changed = cipher[:-1] + bytes([cipher[-1] ^ 1])
                try:
                    AESGCM(key).decrypt(iv, changed, aad)
                    row["tamper_rejected"] = False
                except InvalidTag:
                    row["tamper_rejected"] = True
                row["authenticated"] = True
            else:
                if len(iv) != 16 or not cipher or len(cipher) % 16 or aad:
                    raise ValueError("cbc_input_size_or_aad_invalid")
                decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                padded = decryptor.update(cipher) + decryptor.finalize()
                unpad = padding.PKCS7(128).unpadder()
                plaintext = unpad.update(padded) + unpad.finalize()
                row.update(authenticated=False, tamper_rejected=None)
            row.update(plaintext_sha256=sha256(plaintext), plaintext_size=len(plaintext), state="ok")
            if expected is not None:
                row["provided_output_match"] = plaintext == expected
                if plaintext != expected:
                    row.update(state="failed", reason_code="output_mismatch")
            if row.get("tamper_rejected") is False:
                row.update(state="failed", reason_code="negative_control_not_rejected")
            if row["state"] == "ok":
                roles.add(role)
        except InvalidTag:
            row["reason_code"] = "authentication_failed"
        except (TypeError, ValueError):
            row["reason_code"] = "invalid_vector_or_padding"
    reasons = []
    if any(row["state"] == "failed" for row in rows):
        reasons.append("counterexample_or_invalid_vector")
    if roles != {"fit", "validation"}:
        reasons.append("independent_validation_vector_missing")
    if any(row["provided_output_match"] is None for row in rows):
        reasons.append("provided_output_comparison_missing")
    if algorithm == "AES-CBC-PKCS7":
        reasons.append("unauthenticated_cipher")
    state = "failed" if any(row["state"] == "failed" for row in rows) else "partial" if reasons else "ok"
    return result(state, reasons, algorithm=algorithm, vectors=rows,
                  source_binding_verified=False, coverage="supplied_vectors_only",
                  hypothesis_confirmed_for_supplied_vectors=state == "ok")
