"""Participant-authorized Zincha conversation protocol and client."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generator, Mapping, Optional, Sequence

import jcs
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
    crypto_scalarmult_base,
)
from nacl.exceptions import RuntimeError as NaClRuntimeError

from .crypto import Keypair, bytes_to_hex, hex_to_bytes, sha256_hex

DELEGATION_DOMAIN = "zincha-conversation-delegation-v1"
CHALLENGE_DOMAIN = "zincha-conversation-challenge-v1"
MESSAGE_DOMAIN = "zincha-conversation-message-v1"
E2E_CONTENT_DOMAIN = "zincha-conversation-e2e-content-v1"
E2E_WRAP_DOMAIN = "zincha-conversation-e2e-wrap-v1"
MAX_CONVERSATION_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 256 * 1024
MAX_OUTBOX_ERROR_CHARS = 1_024


def now_ms() -> int:
    return int(time.time() * 1000)


def canonical_json_bytes(value: Any) -> bytes:
    return jcs.canonicalize(value)


def delegation_signing_bytes(delegation: Mapping[str, Any]) -> bytes:
    subject = delegation["subject"]
    capabilities = ",".join(sorted(set(delegation["capabilities"])))
    return "\n".join(
        [
            DELEGATION_DOMAIN,
            str(delegation["version"]),
            str(delegation["delegation_id"]),
            delegation["participant_address"],
            delegation["participant_public_key"],
            subject["network"],
            subject["chain_id"],
            subject["kind"],
            subject["id"],
            delegation["home_service_id"],
            delegation["operational_signing_key"],
            delegation["encryption_key"],
            capabilities,
            str(delegation["not_before_ms"]),
            str(delegation["expires_at_ms"]),
            delegation["nonce"],
        ]
    ).encode("utf-8")


def create_conversation_delegation(
    *,
    account: Keypair,
    operational: Keypair,
    encryption_public_key: bytes,
    subject: Mapping[str, Any],
    home_service_id: str,
    not_before_ms: int,
    expires_at_ms: int,
    capabilities: Sequence[str] = ("read", "write"),
) -> Dict[str, Any]:
    _validate_x25519_public_key(encryption_public_key)
    validate_conversation_subject(subject)
    _validate_service_id(home_service_id)
    if (
        not isinstance(not_before_ms, int)
        or isinstance(not_before_ms, bool)
        or not isinstance(expires_at_ms, int)
        or isinstance(expires_at_ms, bool)
        or not_before_ms >= expires_at_ms
        or expires_at_ms - not_before_ms > 31 * 24 * 60 * 60 * 1000
    ):
        raise ValueError("delegation validity must be positive and no longer than 31 days")
    if (
        not capabilities
        or len(capabilities) != len(set(capabilities))
        or any(capability not in ("read", "write") for capability in capabilities)
    ):
        raise ValueError("delegation capabilities must be unique read/write values")
    delegation: Dict[str, Any] = {
        "version": 1,
        "delegation_id": str(uuid.uuid4()),
        "participant_address": account.address(),
        "participant_public_key": account.public_key_hex(),
        "subject": dict(subject),
        "home_service_id": home_service_id,
        "operational_signing_key": operational.public_key_hex(),
        "encryption_key": encryption_public_key.hex(),
        "capabilities": list(capabilities),
        "not_before_ms": not_before_ms,
        "expires_at_ms": expires_at_ms,
        "nonce": os.urandom(16).hex(),
        "signature": "",
    }
    delegation["signature"] = account.sign(delegation_signing_bytes(delegation)).hex()
    return delegation


def challenge_signing_bytes(challenge: Mapping[str, Any]) -> bytes:
    return (
        "%s\n%s\n%s"
        % (CHALLENGE_DOMAIN, challenge["challenge_id"], challenge["challenge"])
    ).encode("utf-8")


def conversation_payload_digest(payload: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(payload))


def message_signing_bytes(
    conversation_id: str,
    sender: str,
    request: Mapping[str, Any],
    digest: str,
) -> bytes:
    return "\n".join(
        [
            MESSAGE_DOMAIN,
            conversation_id,
            request["message_id"],
            sender,
            str(request["client_timestamp_ms"]),
            request.get("reply_to") or "",
            "" if request.get("key_epoch") is None else str(request["key_epoch"]),
            digest,
            request["signing_key_id"],
        ]
    ).encode("utf-8")


def sign_conversation_message(
    *,
    operational: Keypair,
    delegation_id: str,
    conversation_id: str,
    sender: str,
    payload: Mapping[str, Any],
    reply_to: Optional[str] = None,
    key_epoch: Optional[int] = None,
) -> Dict[str, Any]:
    _validate_conversation_id(conversation_id)
    _validate_conversation_address(sender)
    _validate_uuid(delegation_id, "delegation ID")
    if reply_to is not None:
        _validate_uuid(reply_to, "reply ID")
    if key_epoch is not None:
        _validate_epoch(key_epoch)
    request: Dict[str, Any] = {
        "message_id": str(uuid.uuid4()),
        "client_timestamp_ms": now_ms(),
        "reply_to": reply_to,
        "key_epoch": key_epoch,
        "payload": dict(payload),
        "signing_key_id": delegation_id,
        "signature": "",
    }
    digest = conversation_payload_digest(request["payload"])
    request["signature"] = operational.sign(
        message_signing_bytes(conversation_id, sender, request, digest)
    ).hex()
    return request


class ConversationAuthorizationRequiredError(RuntimeError):
    """The session or its chain-derived conversation authorization must be renewed."""


class ConversationClient:
    def __init__(
        self,
        base_url: str,
        *,
        access_token: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = _normalize_conversation_base_url(base_url)
        self.access_token = access_token
        self.timeout = timeout

    def set_access_token(self, token: str) -> None:
        self.access_token = token

    def profile(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/profile", authenticated=False)

    def issue_challenge(
        self, participant_address: str, subject: Mapping[str, Any]
    ) -> Dict[str, Any]:
        _validate_conversation_address(participant_address)
        validate_conversation_subject(subject)
        return self._request(
            "POST",
            "/v1/auth/challenges",
            {"participant_address": participant_address, "subject": dict(subject)},
            authenticated=False,
        )

    def create_session(
        self,
        challenge: Mapping[str, Any],
        delegation: Mapping[str, Any],
        operational: Keypair,
    ) -> Dict[str, Any]:
        _validate_uuid(challenge.get("challenge_id"), "challenge ID")
        challenge_value = challenge.get("challenge")
        if not isinstance(challenge_value, str) or not challenge_value or len(challenge_value) > 1024:
            raise ValueError("conversation challenge is invalid")
        _validate_uuid(delegation.get("delegation_id"), "delegation ID")
        validate_conversation_subject(delegation.get("subject", {}))
        _validate_conversation_address(delegation.get("participant_address"))
        _validate_service_id(delegation.get("home_service_id"))
        if delegation.get("operational_signing_key") != operational.public_key_hex():
            raise ValueError("operational key does not match delegation")
        return self._request(
            "POST",
            "/v1/auth/sessions",
            {
                "challenge_id": challenge["challenge_id"],
                "delegation": dict(delegation),
                "challenge_signature": operational.sign(
                    challenge_signing_bytes(challenge)
                ).hex(),
            },
            authenticated=False,
        )

    def resolve(
        self,
        subject: Mapping[str, Any],
        provider_address: str,
        privacy_mode: str,
    ) -> Dict[str, Any]:
        validate_conversation_subject(subject)
        _validate_conversation_address(provider_address)
        if privacy_mode not in ("platform_readable", "end_to_end"):
            raise ValueError("conversation privacy mode is invalid")
        return self._request(
            "POST",
            "/v1/conversations/resolve",
            {
                "subject": dict(subject),
                "provider_address": provider_address,
                "privacy_mode": privacy_mode,
            },
        )

    def conversation(self, conversation_id: str) -> Dict[str, Any]:
        _validate_conversation_id(conversation_id)
        return self._request("GET", "/v1/conversations/%s" % conversation_id)

    def submit(
        self, conversation_id: str, message: Mapping[str, Any]
    ) -> Dict[str, Any]:
        _validate_conversation_id(conversation_id)
        return self._request(
            "POST", "/v1/conversations/%s/messages" % conversation_id, dict(message)
        )

    def messages(
        self, conversation_id: str, *, after: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        _validate_conversation_id(conversation_id)
        if (
            not isinstance(after, int)
            or isinstance(after, bool)
            or after < 0
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > 500
        ):
            raise ValueError("message page cursor or limit is invalid")
        return self._request(
            "GET",
            "/v1/conversations/%s/messages?after=%d&limit=%d"
            % (conversation_id, after, limit),
        )

    def acknowledge(self, conversation_id: str, through_sequence: int) -> None:
        _validate_conversation_id(conversation_id)
        if (
            not isinstance(through_sequence, int)
            or isinstance(through_sequence, bool)
            or through_sequence < 0
        ):
            raise ValueError("acknowledgement sequence is invalid")
        self._request(
            "POST",
            "/v1/conversations/%s/acknowledgements" % conversation_id,
            {"through_sequence": through_sequence},
            allow_empty=True,
        )

    def revoke_delegation(self, delegation_id: str) -> None:
        _validate_uuid(delegation_id, "delegation ID")
        self._request(
            "DELETE",
            "/v1/auth/delegations/%s" % delegation_id,
            allow_empty=True,
        )

    def events(
        self,
        conversation_id: str,
        *,
        after: int = 0,
        stop: Optional[Callable[[], bool]] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        _validate_conversation_id(conversation_id)
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise ValueError("message cursor is invalid")
        cursor = after
        delay = 0.25
        while stop is None or not stop():
            request = urllib.request.Request(
                "%s/v1/conversations/%s/events?after=%d&limit=100"
                % (self.base_url, conversation_id, cursor),
                headers={**self._headers(), "accept": "text/event-stream"},
            )
            try:
                resync = False
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    event: Dict[str, str] = {}
                    event_bytes = 0
                    for raw in response:
                        event_bytes += len(raw)
                        if event_bytes > 256 * 1024:
                            raise ValueError("conversation SSE event exceeds 256 KiB")
                        line = raw.decode("utf-8").rstrip("\r\n")
                        if not line:
                            if event.get("event") == "message" and event.get("data"):
                                message = json.loads(event["data"])
                                if int(message["sequence"]) > cursor:
                                    cursor = int(message["sequence"])
                                    yield message
                            elif event.get("event") == "resync_required":
                                resync = True
                                break
                            elif event.get("event") == "authorization_required":
                                raise ConversationAuthorizationRequiredError(
                                    "conversation authorization must be renewed"
                                )
                            event = {}
                            event_bytes = 0
                            continue
                        name, _, value = line.partition(":")
                        if name == "event":
                            event[name] = value.lstrip()
                        elif name == "data":
                            data = value.lstrip()
                            event[name] = data if name not in event else event[name] + "\n" + data
                            if len(event[name]) > 256 * 1024:
                                raise ValueError("conversation SSE event exceeds 256 KiB")
                if resync:
                    while True:
                        previous_cursor = cursor
                        page = self.messages(conversation_id, after=cursor, limit=100)
                        for message in page["items"]:
                            sequence = int(message["sequence"])
                            if sequence > cursor:
                                cursor = sequence
                                yield message
                        next_cursor = page.get("next_cursor")
                        if next_cursor is None:
                            break
                        if cursor <= previous_cursor or next_cursor != cursor:
                            raise RuntimeError(
                                "conversation message pagination did not advance coherently"
                            )
                    delay = 0.25
                    continue
                raise OSError("conversation SSE connection closed")
            except ConversationAuthorizationRequiredError:
                raise
            except urllib.error.HTTPError as error:
                if error.code in (401, 403):
                    raise ConversationAuthorizationRequiredError(
                        "conversation authorization must be renewed"
                    ) from error
                if error.code not in (408, 429) and error.code < 500:
                    raise RuntimeError(
                        "conversation SSE HTTP %d" % error.code
                    ) from error
                if stop is not None and stop():
                    return
                time.sleep(delay)
                delay = min(delay * 2, 30.0)
            except (OSError, urllib.error.URLError):
                if stop is not None and stop():
                    return
                time.sleep(delay)
                delay = min(delay * 2, 30.0)

    def _headers(self) -> Dict[str, str]:
        headers = {"accept": "application/json"}
        if self.access_token:
            headers["authorization"] = "Bearer %s" % self.access_token
        return headers

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        *,
        authenticated: bool = True,
        allow_empty: bool = False,
    ) -> Any:
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"accept": "application/json"}
        if encoded is not None:
            headers["content-type"] = "application/json"
        if authenticated:
            headers.update(self._headers())
        request = urllib.request.Request(
            self.base_url + path, data=encoded, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = _read_bounded(response, MAX_CONVERSATION_RESPONSE_BYTES)
                if allow_empty and not raw:
                    return None
                parsed = json.loads(raw)
        except urllib.error.HTTPError as error:
            try:
                parsed = json.loads(_read_bounded(error, MAX_ERROR_RESPONSE_BYTES))
                message = parsed.get("error")
            except Exception:
                message = None
            raise RuntimeError(message or "conversation HTTP %d" % error.code) from error
        if not isinstance(parsed, dict) or parsed.get("success") is not True:
            raise RuntimeError(parsed.get("error") or "conversation request failed")
        return parsed.get("data")


def _read_bounded(response: Any, limit: int) -> bytes:
    length = response.headers.get("content-length")
    if length is not None:
        try:
            parsed_length = int(length)
        except (TypeError, ValueError):
            parsed_length = None
        if parsed_length is not None and parsed_length > limit:
            raise ValueError("conversation response exceeds bounded limit")
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("conversation response exceeds bounded limit")
    return raw


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output += previous
        counter += 1
    return output[:length]


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) % 4 == 1
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise ValueError("invalid URL-safe base64")
    return base64.b64decode(
        value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True
    )


def encrypt_conversation_e2e(
    conversation_id: str,
    epoch: int,
    plaintext: Mapping[str, Any],
    recipients: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    _validate_conversation_id(conversation_id)
    _validate_epoch(epoch)
    if plaintext.get("encoding") != "plaintext" or not (1 <= len(recipients) <= 256):
        raise ValueError("E2E encryption requires plaintext and 1-256 recipients")
    ephemeral_secret = os.urandom(32)
    ephemeral_public = crypto_scalarmult_base(ephemeral_secret)
    content_key = os.urandom(32)
    content_nonce = os.urandom(24)
    content_aad = (
        "%s\n%s\n%d" % (E2E_CONTENT_DOMAIN, conversation_id, epoch)
    ).encode()
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        canonical_json_bytes(plaintext), content_aad, content_nonce, content_key
    )
    wrapped = []
    seen = set()
    for recipient in recipients:
        key_id = str(recipient["key_id"])
        _validate_e2e_key_id(key_id)
        if key_id in seen:
            raise ValueError("duplicate E2E recipient key ID")
        seen.add(key_id)
        public_key = recipient["public_key"]
        if isinstance(public_key, str):
            public_key = bytes.fromhex(public_key)
        if len(public_key) != 32:
            raise ValueError("recipient public key must be 32 bytes")
        shared = crypto_scalarmult(ephemeral_secret, public_key)
        wrap_aad = (
            "%s\n%s\n%d\n%s" % (E2E_WRAP_DOMAIN, conversation_id, epoch, key_id)
        ).encode()
        wrap_key = _hkdf_sha256(shared, conversation_id.encode(), wrap_aad)
        nonce = os.urandom(24)
        wrapped.append(
            {
                "key_id": key_id,
                "nonce": _b64(nonce),
                "ciphertext": _b64(
                    crypto_aead_xchacha20poly1305_ietf_encrypt(
                        content_key, wrap_aad, nonce, wrap_key
                    )
                ),
            }
        )
    envelope = {
        "version": 1,
        "epoch": epoch,
        "ephemeral_public_key": ephemeral_public.hex(),
        "content_nonce": _b64(content_nonce),
        "ciphertext": _b64(ciphertext),
        "recipients": wrapped,
    }
    return {"encoding": "ciphertext", "ciphertext": _b64(canonical_json_bytes(envelope))}


def decrypt_conversation_e2e(
    conversation_id: str,
    epoch: int,
    payload: Mapping[str, Any],
    recipient_key_id: str,
    recipient_secret: bytes,
) -> Dict[str, Any]:
    _validate_conversation_id(conversation_id)
    _validate_epoch(epoch)
    _validate_e2e_key_id(recipient_key_id)
    if payload.get("encoding") != "ciphertext" or len(recipient_secret) != 32:
        raise ValueError("invalid E2E payload or recipient key")
    envelope = json.loads(_unb64(payload["ciphertext"]))
    if envelope.get("version") != 1 or envelope.get("epoch") != epoch:
        raise ValueError("E2E envelope version or epoch mismatch")
    recipients = envelope.get("recipients")
    if not isinstance(recipients, list) or not (1 <= len(recipients) <= 256):
        raise ValueError("E2E envelope recipient count is invalid")
    recipient_ids = set()
    for item in recipients:
        key_id = item.get("key_id") if isinstance(item, dict) else None
        _validate_e2e_key_id(key_id)
        if key_id in recipient_ids:
            raise ValueError("duplicate E2E recipient key ID")
        recipient_ids.add(key_id)
    recipient = next(
        (item for item in recipients if item["key_id"] == recipient_key_id),
        None,
    )
    if recipient is None:
        raise ValueError("recipient not in E2E envelope")
    shared = crypto_scalarmult(
        recipient_secret, bytes.fromhex(envelope["ephemeral_public_key"])
    )
    wrap_aad = (
        "%s\n%s\n%d\n%s"
        % (E2E_WRAP_DOMAIN, conversation_id, epoch, recipient_key_id)
    ).encode()
    wrap_key = _hkdf_sha256(shared, conversation_id.encode(), wrap_aad)
    content_key = crypto_aead_xchacha20poly1305_ietf_decrypt(
        _unb64(recipient["ciphertext"]),
        wrap_aad,
        _unb64(recipient["nonce"]),
        wrap_key,
    )
    content_aad = (
        "%s\n%s\n%d" % (E2E_CONTENT_DOMAIN, conversation_id, epoch)
    ).encode()
    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
        _unb64(envelope["ciphertext"]),
        content_aad,
        _unb64(envelope["content_nonce"]),
        content_key,
    )
    decoded = json.loads(plaintext)
    if (
        not isinstance(decoded, dict)
        or decoded.get("encoding") != "plaintext"
        or not isinstance(decoded.get("parts"), list)
    ):
        raise ValueError("E2E plaintext has an invalid payload encoding")
    return decoded


def _validate_x25519_public_key(public_key: bytes) -> None:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("encryption public key must be 32 bytes")
    try:
        crypto_scalarmult(bytes([0x42]) * 32, public_key)
    except NaClRuntimeError as error:
        raise ValueError("encryption public key is non-contributory") from error


class SQLiteConversationOutbox:
    """Crash-safe idempotent outbox using a caller-owned SQLite file."""

    def __init__(
        self,
        path: str,
        *,
        max_entries: int = 1_000,
        max_serialized_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        if (
            not isinstance(max_entries, int)
            or isinstance(max_entries, bool)
            or max_entries <= 0
            or not isinstance(max_serialized_bytes, int)
            or isinstance(max_serialized_bytes, bool)
            or max_serialized_bytes <= 0
        ):
            raise ValueError("outbox limits must be positive integers")
        self.path = path
        self.max_entries = max_entries
        self.max_serialized_bytes = max_serialized_bytes
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS conversation_outbox ("
                "message_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, request_json TEXT NOT NULL, "
                "attempts INTEGER NOT NULL, next_attempt_ms INTEGER NOT NULL, last_error TEXT)"
            )
            self._validate_bounds(db)
        self._secure_files()

    def enqueue(self, conversation_id: str, request: Mapping[str, Any]) -> None:
        encoded = canonical_json_bytes(request).decode("utf-8")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT conversation_id, request_json FROM conversation_outbox WHERE message_id = ?",
                (request["message_id"],),
            ).fetchone()
            if existing:
                if existing == (conversation_id, encoded):
                    return
                raise ValueError("outbox message ID conflict")
            count, logical_bytes = self._usage(db)
            added_bytes = len(conversation_id.encode("utf-8")) + len(encoded.encode("utf-8"))
            if count >= self.max_entries:
                raise ValueError("conversation outbox entry limit reached")
            if logical_bytes + added_bytes > self.max_serialized_bytes:
                raise ValueError("conversation outbox byte limit reached")
            db.execute(
                "INSERT INTO conversation_outbox VALUES (?, ?, ?, 0, ?, NULL)",
                (request["message_id"], conversation_id, encoded, now_ms()),
            )
        self._secure_files()

    def flush(self, client: ConversationClient, limit: int = 100) -> int:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("outbox flush limit must be a positive integer")
        current = now_ms()
        with self._connect() as db:
            self._validate_bounds(db)
            rows = db.execute(
                "SELECT message_id, conversation_id, request_json, attempts FROM conversation_outbox "
                "WHERE next_attempt_ms <= ? ORDER BY next_attempt_ms LIMIT ?",
                (current, limit),
            ).fetchall()
        sent = 0
        for message_id, conversation_id, encoded, attempts in rows:
            try:
                client.submit(conversation_id, json.loads(encoded))
            except Exception as error:
                attempts += 1
                delay = min(250 * (2 ** min(attempts, 8)), 60_000)
                with self._connect() as db:
                    db.execute(
                        "UPDATE conversation_outbox SET attempts=?, next_attempt_ms=?, last_error=? WHERE message_id=?",
                        (
                            attempts,
                            current + delay,
                            str(error)[:MAX_OUTBOX_ERROR_CHARS],
                            message_id,
                        ),
                    )
            else:
                with self._connect() as db:
                    db.execute(
                        "DELETE FROM conversation_outbox WHERE message_id=?", (message_id,)
                    )
                sent += 1
        self._secure_files()
        return sent

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _usage(self, db: sqlite3.Connection) -> tuple[int, int]:
        count, logical_bytes = db.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(conversation_id AS BLOB)) + "
            "LENGTH(CAST(request_json AS BLOB)) + "
            "COALESCE(LENGTH(CAST(last_error AS BLOB)), 0)), 0) FROM conversation_outbox"
        ).fetchone()
        return int(count), int(logical_bytes)

    def _validate_bounds(self, db: sqlite3.Connection) -> None:
        count, logical_bytes = self._usage(db)
        if count > self.max_entries:
            raise ValueError("conversation outbox entry limit exceeded")
        if logical_bytes > self.max_serialized_bytes:
            raise ValueError("conversation outbox byte limit exceeded")

    def _secure_files(self) -> None:
        if os.name != "posix":
            return
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(self.path + suffix, 0o600)
            except FileNotFoundError:
                pass


def validate_conversation_profile(profile: Mapping[str, Any]) -> None:
    _validate_exact_keys(
        profile,
        {
            "version",
            "service_id",
            "discovery_url",
            "privacy_modes",
            "protocol_versions",
            "service_signing_public_key",
        },
        "conversation profile",
    )
    if profile.get("version") != 1:
        raise ValueError("unsupported conversation profile")
    _validate_service_id(profile.get("service_id"))
    protocols = profile.get("protocol_versions")
    if (
        not isinstance(protocols, list)
        or 1 not in protocols
        or len(protocols) != len(set(protocols))
        or any(not isinstance(version, int) or isinstance(version, bool) or version <= 0 for version in protocols)
    ):
        raise ValueError("conversation profile protocol versions are invalid")
    privacy_modes = profile.get("privacy_modes")
    if (
        not isinstance(privacy_modes, list)
        or not privacy_modes
        or len(privacy_modes) != len(set(privacy_modes))
        or any(mode not in ("platform_readable", "end_to_end") for mode in privacy_modes)
    ):
        raise ValueError("conversation profile privacy modes are invalid")
    discovery_url = profile.get("discovery_url")
    if not isinstance(discovery_url, str):
        raise ValueError("conversation profile discovery URL is invalid")
    _normalize_conversation_base_url(discovery_url)
    public_key = profile.get("service_signing_public_key")
    if (
        not isinstance(public_key, str)
        or len(public_key) != 64
        or any(character not in "0123456789abcdef" for character in public_key)
    ):
        raise ValueError("conversation profile service signing key is invalid")


def validate_conversation_subject(subject: Mapping[str, Any]) -> None:
    _validate_exact_keys(
        subject, {"network", "chain_id", "kind", "id"}, "conversation subject"
    )
    network = subject.get("network")
    chain_id = subject.get("chain_id")
    if (
        not isinstance(network, str)
        or not network.strip()
        or len(network) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in network)
        or not isinstance(chain_id, str)
        or not chain_id.strip()
        or len(chain_id) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in chain_id)
        or subject.get("kind") not in ("task", "agreement", "tool_job", "tool_session")
    ):
        raise ValueError("conversation subject is invalid")
    _validate_conversation_id(subject.get("id"))


def _validate_exact_keys(value: Any, allowed: set, label: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} is invalid")
    if any(key not in allowed for key in value):
        raise ValueError(f"{label} contains unknown fields")


def _validate_service_id(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("conversation profile service ID is invalid")


def _validate_conversation_id(value: Any) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(
            "conversation identifier must be 32 bytes of lowercase hexadecimal"
        )


def _validate_conversation_address(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("zn1")
        or len(value) != 43
        or any(character not in "0123456789abcdef" for character in value[3:])
    ):
        raise ValueError("conversation address is invalid")


def _validate_uuid(value: Any, label: str) -> None:
    try:
        parsed = uuid.UUID(value) if isinstance(value, str) else None
    except (ValueError, AttributeError):
        parsed = None
    if parsed is None or str(parsed) != value.lower():
        raise ValueError(f"{label} is invalid")


def _validate_epoch(value: Any) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 2**63 - 1
    ):
        raise ValueError("conversation key epoch is invalid")


def _validate_e2e_key_id(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("E2E recipient key ID is invalid")


def _normalize_conversation_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname
    if host is None or parsed.username is not None or parsed.password is not None:
        raise ValueError("conversation service URL is invalid")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError(
            "conversation service URL must use HTTPS, except for loopback development"
        )
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
    )


def encode_conversation_profile(profile: Mapping[str, Any]) -> bytes:
    validate_conversation_profile(profile)
    encoded = canonical_json_bytes(profile)
    if len(encoded) > 4096:
        raise ValueError("conversation profile exceeds agent metadata limit")
    return encoded


def decode_conversation_profile(metadata: bytes) -> Dict[str, Any]:
    if len(metadata) > 4096:
        raise ValueError("conversation profile exceeds agent metadata limit")
    profile = json.loads(metadata)
    if not isinstance(profile, dict):
        raise ValueError("conversation profile must be a JSON object")
    validate_conversation_profile(profile)
    return profile


def verify_conversation_service_profile(
    advertised: Mapping[str, Any], live: Mapping[str, Any]
) -> None:
    validate_conversation_profile(advertised)
    validate_conversation_profile(live)
    if canonical_json_bytes(advertised) != canonical_json_bytes(live):
        raise ValueError(
            "live conversation profile does not match authenticated agent metadata"
        )
