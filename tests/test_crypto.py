"""Tests Phase 2.4.b : chiffrement AES-256-GCM de la quarantaine.

Tous les tests utilisent de vrais fichiers, vrais bytes, vraies clés
aléatoires. Pas de mock de la crypto.

Vérifications critiques :
  - round-trip encrypt → decrypt restitue exactement les bytes
  - tag GCM détecte modification du ciphertext (TamperedError)
  - tag GCM détecte clé incorrecte (TamperedError)
  - associated_data divergent → TamperedError
  - absence de clé claire (KeyMissingError)
  - intégration quarantine_file(encrypt=True) → fichier stocké est
    chiffré (magic BCE1 en tête, plaintext absent)
  - restore_file déchiffre transparent avec la bonne clé
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

pytest.importorskip("cryptography")


# --------------------------------------------------------------------- #
# Module crypto : bas niveau
# --------------------------------------------------------------------- #


def test_generate_key_is_32_bytes():
    from biocybe.crypto import KEY_SIZE, generate_key

    k1 = generate_key()
    k2 = generate_key()
    assert len(k1) == KEY_SIZE == 32
    assert k1 != k2  # randomness


def test_key_base64_roundtrip():
    from biocybe.crypto import generate_key, key_from_base64, key_to_base64

    k = generate_key()
    b64 = key_to_base64(k)
    assert isinstance(b64, str)
    assert key_from_base64(b64) == k


def test_key_base64_invalid_raises():
    from biocybe.crypto import key_from_base64

    with pytest.raises(ValueError):
        key_from_base64("not_base64!!!@@@")
    with pytest.raises(ValueError):
        key_from_base64("dG9vc2hvcnQ=")  # 'tooshort' base64, < 32 bytes


def test_load_key_from_env(monkeypatch):
    from biocybe.crypto import KEY_ENV_VAR, generate_key, key_to_base64, load_key

    k = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key_to_base64(k))
    assert load_key() == k


def test_load_key_missing_raises(monkeypatch):
    from biocybe.crypto import KEY_ENV_VAR, KeyMissingError, load_key

    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    with pytest.raises(KeyMissingError):
        load_key()


def test_load_key_explicit_bytes_overrides_env(monkeypatch):
    from biocybe.crypto import KEY_ENV_VAR, generate_key, key_to_base64, load_key

    env_key = generate_key()
    arg_key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key_to_base64(env_key))
    assert load_key(arg_key) == arg_key  # arg gagne sur env


def test_encrypt_decrypt_roundtrip(tmp_path):
    from biocybe.crypto import decrypt_file, encrypt_file, generate_key

    plain = tmp_path / "plain.bin"
    enc = tmp_path / "out.enc"
    restored = tmp_path / "restored.bin"

    data = b"super secret payload " * 1000  # ~22 KB
    plain.write_bytes(data)
    key = generate_key()

    encrypt_file(plain, enc, key=key)
    # Le fichier chiffré commence par le magic BCE1
    assert enc.read_bytes()[:4] == b"BCE1"
    # Et NE contient PAS le plaintext
    assert b"super secret payload" not in enc.read_bytes()

    decrypt_file(enc, restored, key=key)
    assert restored.read_bytes() == data


def test_decrypt_with_wrong_key_raises_tampered(tmp_path):
    from biocybe.crypto import (
        TamperedError,
        decrypt_file,
        encrypt_file,
        generate_key,
    )

    plain = tmp_path / "x.bin"
    enc = tmp_path / "x.enc"
    restored = tmp_path / "y.bin"
    plain.write_bytes(b"hello")
    encrypt_file(plain, enc, key=generate_key())

    with pytest.raises(TamperedError):
        decrypt_file(enc, restored, key=generate_key())  # clé différente


def test_decrypt_detects_ciphertext_tampering(tmp_path):
    from biocybe.crypto import (
        TamperedError,
        decrypt_file,
        encrypt_file,
        generate_key,
    )

    plain = tmp_path / "x.bin"
    enc = tmp_path / "x.enc"
    restored = tmp_path / "y.bin"
    key = generate_key()
    plain.write_bytes(b"hello world " * 100)
    encrypt_file(plain, enc, key=key)

    # On flip 1 byte au milieu du ciphertext
    data = bytearray(enc.read_bytes())
    # header = 4 + 2 + 12 + 16 = 34 octets, on touche après
    data[50] ^= 0xFF
    enc.write_bytes(bytes(data))

    with pytest.raises(TamperedError):
        decrypt_file(enc, restored, key=key)


def test_associated_data_must_match(tmp_path):
    from biocybe.crypto import (
        TamperedError,
        decrypt_file,
        encrypt_file,
        generate_key,
    )

    plain = tmp_path / "x.bin"
    enc = tmp_path / "x.enc"
    restored = tmp_path / "y.bin"
    key = generate_key()
    plain.write_bytes(b"data")

    encrypt_file(plain, enc, key=key, associated_data=b"context-A")
    with pytest.raises(TamperedError):
        decrypt_file(enc, restored, key=key, associated_data=b"context-B")


def test_is_encrypted_detects_magic(tmp_path):
    from biocybe.crypto import encrypt_file, generate_key, is_encrypted

    enc = tmp_path / "x.enc"
    plain = tmp_path / "p.bin"
    plain.write_bytes(b"x")
    encrypt_file(plain, enc, key=generate_key())
    assert is_encrypted(enc) is True

    other = tmp_path / "other.txt"
    other.write_bytes(b"plain text data")
    assert is_encrypted(other) is False


# --------------------------------------------------------------------- #
# Intégration quarantine_file(encrypt=True) ↔ restore_file
# --------------------------------------------------------------------- #


def test_quarantine_encrypted_stores_ciphertext_only(tmp_path, monkeypatch):
    from biocybe.crypto import generate_key
    from biocybe.isolation import quarantine_file

    monkeypatch.chdir(tmp_path)
    src = tmp_path / "evil.bin"
    src.write_text("VERY_SENSITIVE_MALWARE_PAYLOAD", encoding="ascii")

    key = generate_key()
    entry = quarantine_file(src, reason="test", encrypt=True, key=key)

    assert entry.encrypted is True
    assert entry.stored_filename.endswith(".quarantine.enc")
    # Le fichier en quarantaine contient le magic BCE1
    stored = tmp_path / "quarantine" / entry.stored_filename
    assert stored.exists()
    assert stored.read_bytes()[:4] == b"BCE1"
    # Le plaintext n'est plus accessible
    assert b"VERY_SENSITIVE_MALWARE_PAYLOAD" not in stored.read_bytes()
    # Le clair original a disparu
    assert not src.exists()


def test_restore_encrypted_with_good_key(tmp_path, monkeypatch):
    from biocybe.crypto import generate_key
    from biocybe.isolation import quarantine_file, restore_file

    monkeypatch.chdir(tmp_path)
    src = tmp_path / "evil.bin"
    content = "MALWARE_X_PAYLOAD\nbinary\x00data"
    src.write_text(content, encoding="ascii")
    original_path = src.resolve()
    key = generate_key()

    entry = quarantine_file(src, reason="t", encrypt=True, key=key)
    dest = restore_file(entry.quarantine_id, key=key)
    assert dest == original_path
    assert dest.read_text(encoding="ascii") == content


def test_restore_encrypted_with_wrong_key_raises_integrity(tmp_path, monkeypatch):
    from biocybe.crypto import generate_key
    from biocybe.isolation import QuarantineIntegrityError, quarantine_file, restore_file

    monkeypatch.chdir(tmp_path)
    src = tmp_path / "evil.bin"
    src.write_bytes(b"payload")
    key1 = generate_key()
    key2 = generate_key()

    entry = quarantine_file(src, reason="t", encrypt=True, key=key1)
    with pytest.raises(QuarantineIntegrityError):
        restore_file(entry.quarantine_id, key=key2)


def test_restore_encrypted_via_env_var(tmp_path, monkeypatch):
    from biocybe.crypto import KEY_ENV_VAR, generate_key, key_to_base64
    from biocybe.isolation import quarantine_file, restore_file

    monkeypatch.chdir(tmp_path)
    src = tmp_path / "evil.bin"
    src.write_bytes(b"hello world")
    key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key_to_base64(key))

    # Pas de key= passé : doit utiliser l'env
    entry = quarantine_file(src, reason="t", encrypt=True)
    dest = restore_file(entry.quarantine_id)
    assert dest.read_bytes() == b"hello world"


def test_quarantine_encrypted_without_key_raises(tmp_path, monkeypatch):
    from biocybe.crypto import KEY_ENV_VAR, KeyMissingError
    from biocybe.isolation import quarantine_file

    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "evil.bin"
    src.write_bytes(b"payload")

    with pytest.raises(KeyMissingError):
        quarantine_file(src, reason="t", encrypt=True)
    # Le fichier source ne doit PAS avoir été déplacé/supprimé
    assert src.exists()


def test_non_encrypted_quarantine_still_works(tmp_path, monkeypatch):
    """Régression : le mode non-chiffré (par défaut) reste inchangé."""
    from biocybe.isolation import quarantine_file, restore_file

    monkeypatch.chdir(tmp_path)
    src = tmp_path / "evil.bin"
    src.write_text("plain payload", encoding="ascii")
    original = src.resolve()
    entry = quarantine_file(src, reason="t")  # encrypt=False par défaut
    assert entry.encrypted is False
    assert entry.stored_filename.endswith(".quarantine")
    assert not entry.stored_filename.endswith(".enc")

    dest = restore_file(entry.quarantine_id)
    assert dest == original
    assert dest.read_text() == "plain payload"
