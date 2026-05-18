"""Chiffrement AES-256-GCM pour la quarantaine BioCybe.

Quand `encrypt_quarantine: true` est activé dans la config, les
fichiers en quarantaine sont **chiffrés au repos** avec AES-256-GCM.
Conséquences pratiques :

  - Un attaquant qui obtient un shell sur la machine (même root) ne
    peut PAS récupérer les payloads malveillants directement depuis
    `quarantine/`.
  - L'opérateur SOC qui restaure un fichier doit fournir la clé.
  - Le hash SHA-256 enregistré reste celui du **clair** (avant chiffrement),
    donc la vérification d'intégrité existante continue de fonctionner
    après déchiffrement.

Choix cryptographiques (auditables) :
  - AES-256-GCM (AEAD authentifié — détecte aussi le tampering du
    cipher text, pas juste du plaintext).
  - Nonce 96 bits aléatoire **unique par fichier** (généré via
    `os.urandom` = `/dev/urandom` sur Linux, `BCryptGenRandom` sur
    Windows). Stocké dans le header du fichier .enc.
  - Tag d'authentification 128 bits.
  - Pas de PBKDF2/Argon2 : on suppose que la clé est **gérée
    extérieurement** (KMS, Vault, env var) — c'est plus simple à
    raisonner et plus aligné avec les pratiques SOC. Si l'opérateur
    veut dériver d'une passphrase, il fait scrypt/argon2 lui-même
    en amont et passe la clé brute (32 bytes).

Format du fichier .enc :
    [4 octets  magic     "BCE1" ]
    [1 octet   version   = 1     ]
    [1 octet   alg id    = 1 (AES-256-GCM)]
    [12 octets nonce               ]
    [16 octets tag GCM              ]
    [N octets  ciphertext            ]

(Le tag est en fait à la fin chez la lib `cryptography.AESGCM`,
mais on le copie en header pour rendre le format auto-portant
et facile à parser. Voir code.)
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("biocybe.crypto")

KEY_ENV_VAR = "BIOCYBE_QUARANTINE_KEY"
MAGIC = b"BCE1"
VERSION = 1
ALG_AES_256_GCM = 1
NONCE_SIZE = 12  # 96 bits, recommandé pour GCM
KEY_SIZE = 32  # 256 bits


class CryptoError(Exception):
    """Erreur générique de chiffrement/déchiffrement."""


class KeyMissingError(CryptoError):
    """Aucune clé disponible (env, paramètre, fichier)."""


class TamperedError(CryptoError):
    """Le tag GCM ne vérifie pas — fichier modifié ou clé incorrecte."""


def generate_key() -> bytes:
    """Génère une clé AES-256 aléatoire (32 bytes)."""
    return os.urandom(KEY_SIZE)


def key_to_base64(key: bytes) -> str:
    """Encode une clé pour stockage / passage en env var."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Clé doit faire {KEY_SIZE} bytes, reçu {len(key)}")
    return base64.b64encode(key).decode("ascii")


def key_from_base64(s: str) -> bytes:
    """Décode une clé depuis base64."""
    try:
        k = base64.b64decode(s, validate=True)
    except Exception as exc:
        raise ValueError(f"Clé base64 invalide : {exc}") from exc
    if len(k) != KEY_SIZE:
        raise ValueError(f"Clé décodée doit faire {KEY_SIZE} bytes, reçu {len(k)}")
    return k


def load_key(key: bytes | str | None = None) -> bytes:
    """Récupère la clé depuis (par ordre) : argument bytes,
    argument base64 string, variable d'env `BIOCYBE_QUARANTINE_KEY`.
    """
    if isinstance(key, bytes):
        if len(key) != KEY_SIZE:
            raise ValueError(f"Clé bytes doit faire {KEY_SIZE} bytes")
        return key
    if isinstance(key, str):
        return key_from_base64(key)
    env_val = os.environ.get(KEY_ENV_VAR)
    if not env_val:
        raise KeyMissingError(
            f"Aucune clé de quarantaine disponible. "
            f"Définir env {KEY_ENV_VAR}=<base64> ou passer key=... ; "
            f"générer une nouvelle clé avec biocybe.crypto.generate_key()."
        )
    return key_from_base64(env_val)


# --------------------------------------------------------------------- #
# Format du fichier .enc
# --------------------------------------------------------------------- #


def _build_header(nonce: bytes, tag: bytes) -> bytes:
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce doit faire {NONCE_SIZE} bytes")
    if len(tag) != 16:
        raise ValueError("tag doit faire 16 bytes")
    return MAGIC + bytes([VERSION, ALG_AES_256_GCM]) + nonce + tag


def _parse_header(data: bytes) -> tuple[bytes, bytes, int]:
    """Retourne (nonce, tag, ciphertext_offset)."""
    header_len = 4 + 1 + 1 + NONCE_SIZE + 16
    if len(data) < header_len:
        raise CryptoError("Fichier .enc tronqué (header incomplet)")
    if data[:4] != MAGIC:
        raise CryptoError(f"Magic invalide : {data[:4]!r}, attendu {MAGIC!r}")
    if data[4] != VERSION:
        raise CryptoError(f"Version inconnue : {data[4]}")
    if data[5] != ALG_AES_256_GCM:
        raise CryptoError(f"Algorithme inconnu : {data[5]}")
    nonce = data[6 : 6 + NONCE_SIZE]
    tag = data[6 + NONCE_SIZE : 6 + NONCE_SIZE + 16]
    return nonce, tag, header_len


# --------------------------------------------------------------------- #
# Encrypt / Decrypt
# --------------------------------------------------------------------- #


def encrypt_file(
    src_path: str | os.PathLike,
    dest_path: str | os.PathLike,
    *,
    key: bytes | str | None = None,
    associated_data: bytes | None = None,
) -> None:
    """Chiffre `src_path` -> `dest_path` au format .enc BCE1.

    `associated_data` (optionnel) est lié cryptographiquement au
    chiffrement (n'est PAS chiffré mais ne peut pas être modifié sans
    invalider le tag). Typique : SHA-256 du clair, pour double sécurité.

    Le fichier source est lu en entier en mémoire — convient aux
    quarantaines (typiquement <100 Mo). Pour fichiers >1 Go, utiliser
    `encrypt_stream` (à venir si besoin réel).
    """
    src = Path(src_path)
    dest = Path(dest_path)
    k = load_key(key)

    plaintext = src.read_bytes()
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(k)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    # cryptography concatène ciphertext + tag (16 octets) ; on extrait
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as f:
        f.write(_build_header(nonce, tag))
        f.write(ciphertext)
    try:
        os.chmod(dest, 0o600)
    except OSError as exc:
        logger.debug("chmod sur %s impossible : %s", dest, exc)


def decrypt_file(
    src_path: str | os.PathLike,
    dest_path: str | os.PathLike,
    *,
    key: bytes | str | None = None,
    associated_data: bytes | None = None,
) -> None:
    """Déchiffre `src_path` (.enc BCE1) -> `dest_path`.

    Lève `TamperedError` si :
      - le tag GCM ne vérifie pas (clé incorrecte ou fichier modifié)
      - `associated_data` ne correspond pas
    """
    src = Path(src_path)
    dest = Path(dest_path)
    k = load_key(key)

    blob = src.read_bytes()
    nonce, tag, offset = _parse_header(blob)
    ciphertext = blob[offset:]

    aesgcm = AESGCM(k)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
    except InvalidTag as exc:
        raise TamperedError(
            "Tag GCM invalide : fichier modifié OU clé incorrecte OU associated_data divergent."
        ) from exc

    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as f:
        f.write(plaintext)


def is_encrypted(path: str | os.PathLike) -> bool:
    """Heuristique rapide : lit les 4 premiers octets pour le magic."""
    try:
        with Path(path).open("rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False
