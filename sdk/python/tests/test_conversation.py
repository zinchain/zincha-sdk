import base64
import json
import os
import socket
import ssl
import stat
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nacl.bindings import crypto_scalarmult_base
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from zincha import Keypair
from zincha.conversation import (
    SQLiteConversationOutbox,
    ConversationClient,
    create_conversation_delegation,
    decode_conversation_profile,
    decrypt_conversation_e2e,
    encrypt_conversation_e2e,
    encode_conversation_profile,
    sign_conversation_message,
    conversation_payload_digest,
    delegation_signing_bytes,
    message_signing_bytes,
    verify_conversation_service_profile,
)


class ConversationTests(unittest.TestCase):
    def test_delegation_and_message_use_separate_keys(self):
        account = Keypair.from_secret_bytes(bytes([7]) * 32)
        operational = Keypair.from_secret_bytes(bytes([9]) * 32)
        encryption_secret = bytes([11]) * 32
        subject = {
            "network": "testnet",
            "chain_id": "zincha-test",
            "kind": "task",
            "id": "ab" * 32,
        }
        delegation = create_conversation_delegation(
            account=account,
            operational=operational,
            encryption_public_key=crypto_scalarmult_base(encryption_secret),
            subject=subject,
            home_service_id="marketplace.example/conversations",
            not_before_ms=1,
            expires_at_ms=2,
        )
        self.assertEqual(delegation["participant_address"], account.address())
        with self.assertRaisesRegex(ValueError, "non-contributory"):
            create_conversation_delegation(
                account=account,
                operational=operational,
                encryption_public_key=bytes(32),
                subject=subject,
                home_service_id="marketplace.example/conversations",
                not_before_ms=1,
                expires_at_ms=2,
            )
        message = sign_conversation_message(
            operational=operational,
            delegation_id=delegation["delegation_id"],
            conversation_id="cd" * 32,
            sender=account.address(),
            payload={"encoding": "plaintext", "parts": [{"type": "text", "text": "hello"}]},
        )
        self.assertEqual(len(message["signature"]), 128)
        with self.assertRaisesRegex(ValueError, "key epoch"):
            sign_conversation_message(
                operational=operational,
                delegation_id=delegation["delegation_id"],
                conversation_id="cd" * 32,
                sender=account.address(),
                payload={
                    "encoding": "plaintext",
                    "parts": [{"type": "text", "text": "hello"}],
                },
                key_epoch=1,
            )
        with self.assertRaisesRegex(ValueError, "artifact ID"):
            sign_conversation_message(
                operational=operational,
                delegation_id=delegation["delegation_id"],
                conversation_id="cd" * 32,
                sender=account.address(),
                payload={
                    "encoding": "plaintext",
                    "parts": [
                        {
                            "type": "artifact_reference",
                            "artifact_id": "bad",
                            "digest": "00" * 32,
                            "media_type": "text/plain",
                            "size": 1,
                        }
                    ],
                },
            )

    def test_e2e_context_binding(self):
        secret = bytes([19]) * 32
        plaintext = {"encoding": "plaintext", "parts": [{"type": "text", "text": "hello"}]}
        encrypted = encrypt_conversation_e2e(
            "cd" * 32,
            7,
            plaintext,
            [{"key_id": "recipient", "public_key": crypto_scalarmult_base(secret)}],
        )
        with self.assertRaisesRegex(ValueError, "1-256"):
            encrypt_conversation_e2e(
                "cd" * 32,
                7,
                {"encoding": "plaintext", "parts": []},
                [{"key_id": "recipient", "public_key": crypto_scalarmult_base(secret)}],
            )
        self.assertEqual(
            decrypt_conversation_e2e("cd" * 32, 7, encrypted, "recipient", secret),
            plaintext,
        )
        with self.assertRaises(Exception):
            decrypt_conversation_e2e("ef" * 32, 7, encrypted, "recipient", secret)
        with self.assertRaisesRegex(ValueError, "epoch"):
            decrypt_conversation_e2e("cd" * 32, 8, encrypted, "recipient", secret)
        with self.assertRaisesRegex(ValueError, "recipient"):
            decrypt_conversation_e2e(
                "cd" * 32, 7, encrypted, "missing-recipient", secret
            )
        last = encrypted["ciphertext"][-1]
        tampered = {
            **encrypted,
            "ciphertext": encrypted["ciphertext"][:-1]
            + ("B" if last == "A" else "A"),
        }
        with self.assertRaises(Exception):
            decrypt_conversation_e2e("cd" * 32, 7, tampered, "recipient", secret)
        envelope_bytes = base64.urlsafe_b64decode(
            encrypted["ciphertext"] + "=" * (-len(encrypted["ciphertext"]) % 4)
        )
        non_contributory_envelope = json.loads(envelope_bytes)
        non_contributory_envelope["ephemeral_public_key"] = "00" * 32
        non_contributory_ephemeral = {
            **encrypted,
            "ciphertext": base64.urlsafe_b64encode(
                json.dumps(
                    non_contributory_envelope, separators=(",", ":")
                ).encode()
            )
            .rstrip(b"=")
            .decode(),
        }
        with self.assertRaises(Exception):
            decrypt_conversation_e2e(
                "cd" * 32, 7, non_contributory_ephemeral, "recipient", secret
            )
        with self.assertRaises(Exception):
            encrypt_conversation_e2e(
                "cd" * 32,
                7,
                plaintext,
                [{"key_id": "non-contributory", "public_key": bytes(32)}],
            )
        with self.assertRaisesRegex(ValueError, "epoch"):
            encrypt_conversation_e2e(
                "cd" * 32,
                2**63,
                plaintext,
                [{"key_id": "recipient", "public_key": crypto_scalarmult_base(secret)}],
            )

    def test_sqlite_outbox_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = SQLiteConversationOutbox(directory + "/outbox.sqlite")
            request = {
                "message_id": "11111111-1111-4111-8111-111111111111",
                "client_timestamp_ms": 1,
                "reply_to": None,
                "key_epoch": None,
                "payload": {"encoding": "plaintext", "parts": [{"type": "text", "text": "hello"}]},
                "signing_key_id": "22222222-2222-4222-8222-222222222222",
                "signature": "00" * 64,
            }
            outbox.enqueue("conversation", request)
            outbox.enqueue("conversation", request)
            with outbox._connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM conversation_outbox").fetchone()[0], 1)

    def test_sqlite_outbox_is_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory + "/outbox.sqlite"
            outbox = SQLiteConversationOutbox(path, max_entries=1)
            request = {
                "message_id": "11111111-1111-4111-8111-111111111111",
                "client_timestamp_ms": 1,
                "reply_to": None,
                "key_epoch": None,
                "payload": {"encoding": "plaintext", "parts": [{"type": "text", "text": "hello"}]},
                "signing_key_id": "22222222-2222-4222-8222-222222222222",
                "signature": "00" * 64,
            }
            outbox.enqueue("conversation", request)
            outbox.enqueue("conversation", request)
            with self.assertRaisesRegex(ValueError, "entry limit"):
                outbox.enqueue(
                    "conversation",
                    {**request, "message_id": "33333333-3333-4333-8333-333333333333"},
                )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_profiles_and_client_urls_are_strictly_validated(self):
        profile = {
            "version": 2,
            "service_id": "marketplace.example/conversations",
            "interfaces": [
                {
                    "type": "zincha_tls_v1",
                    "host": "203.0.113.25",
                    "port": 443,
                    "certificate_pins": [
                        {
                            "sha256": "ab" * 32,
                            "not_before_ms": 1791000000000,
                            "not_after_ms": 1822536000000,
                        }
                    ],
                },
                {"type": "https", "url": "https://conversations.example/v1"},
            ],
            "privacy_modes": ["platform_readable", "end_to_end"],
            "protocol_versions": [1],
        }
        self.assertEqual(decode_conversation_profile(encode_conversation_profile(profile)), profile)
        verify_conversation_service_profile(profile, profile)
        with self.assertRaisesRegex(ValueError, "does not match"):
            verify_conversation_service_profile(
                profile,
                {**profile, "service_id": "different.example/conversations"},
            )
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            encode_conversation_profile({**profile, "interfaces": [{"type": "https", "url": "http://conversations.example"}]})
        with self.assertRaises(ValueError):
            encode_conversation_profile(
                {**profile, "interfaces": [{"type": "https", "url": "https://user:secret@conversations.example"}]}
            )
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            encode_conversation_profile({**profile, "unexpected": True})
        duplicate_pin = profile["interfaces"][0]["certificate_pins"][0]
        with self.assertRaisesRegex(ValueError, "duplicated"):
            encode_conversation_profile(
                {
                    **profile,
                    "interfaces": [
                        {
                            **profile["interfaces"][0],
                            "certificate_pins": [duplicate_pin, duplicate_pin],
                        }
                    ],
                }
            )
        with self.assertRaisesRegex(ValueError, "URL exceeds"):
            encode_conversation_profile(
                {
                    **profile,
                    "interfaces": [
                        {
                            "type": "https",
                            "url": "https://conversations.example/" + "x" * 4096,
                        }
                    ],
                }
            )
        with self.assertRaisesRegex(ValueError, "protocol versions"):
            encode_conversation_profile(
                {**profile, "protocol_versions": list(range(1, 66))}
            )
        client = ConversationClient("http://127.0.0.1:8080/base")
        with self.assertRaisesRegex(ValueError, "identifier"):
            client.conversation("../profile")
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            ConversationClient("http://conversations.example")
        with self.assertRaisesRegex(ValueError, "metadata limit"):
            decode_conversation_profile(b"x" * 4097)

    def test_profile_v2_matches_cross_language_golden_vector(self):
        path = Path(__file__).parents[2] / "testdata" / "golden-conversation-profile-v2.json"
        vector = json.loads(path.read_text())
        encoded = encode_conversation_profile(vector["profile"])
        self.assertEqual(encoded.decode(), vector["canonical_json"])
        self.assertEqual(decode_conversation_profile(encoded), vector["profile"])

    def test_pinned_transport_enforces_complete_rotation_matrix(self):
        def create_identity(directory, name):
            key = ed25519.Ed25519PrivateKey.generate()
            current = datetime.now(timezone.utc).replace(microsecond=0)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name(
                        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
                    )
                )
                .issuer_name(
                    x509.Name(
                        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
                    )
                )
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(current - timedelta(minutes=1))
                .not_valid_after(current + timedelta(days=30))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.IPAddress(
                                __import__("ipaddress").ip_address("127.0.0.1")
                            )
                        ]
                    ),
                    critical=False,
                )
                .sign(key, algorithm=None)
            )
            certificate_path = os.path.join(directory, name + "-certificate.pem")
            key_path = os.path.join(directory, name + "-key.pem")
            with open(certificate_path, "wb") as output:
                output.write(certificate.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as output:
                output.write(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
            pin = {
                "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "not_before_ms": int(
                    certificate.not_valid_before_utc.timestamp() * 1000
                ),
                "not_after_ms": int(
                    certificate.not_valid_after_utc.timestamp() * 1000
                ),
            }
            return certificate_path, key_path, pin

        def start_server(certificate_path, key_path, profile_holder):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.2)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["http/1.1"])
            context.load_cert_chain(certificate_path, key_path)
            stopping = threading.Event()
            requests = []

            def handle(connection):
                try:
                    with context.wrap_socket(connection, server_side=True) as stream:
                        request = stream.recv(8192)
                        if not request:
                            return
                        requests.append(request)
                        encoded = json.dumps(
                            {"success": True, "data": profile_holder["value"]},
                            separators=(",", ":"),
                        ).encode()
                        stream.sendall(
                            (
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                "Content-Length: %d\r\nConnection: close\r\n\r\n"
                                % len(encoded)
                            ).encode()
                            + encoded
                        )
                except (OSError, ssl.SSLError):
                    connection.close()

            def serve():
                while not stopping.is_set():
                    try:
                        connection, _ = listener.accept()
                    except (socket.timeout, OSError):
                        continue
                    threading.Thread(
                        target=handle, args=(connection,), daemon=True
                    ).start()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            return listener, stopping, thread, requests

        def profile_for(port, pins, leading_unreachable=None, trailing_unreachable=None):
            interfaces = []
            if leading_unreachable is not None:
                interfaces.append(
                    {
                        "type": "https",
                        "url": "https://127.0.0.1:%d/before-pinned"
                        % leading_unreachable,
                    }
                )
            interfaces.append(
                {
                    "type": "zincha_tls_v1",
                    "host": "127.0.0.1",
                    "port": port,
                    "certificate_pins": pins,
                }
            )
            if trailing_unreachable is not None:
                interfaces.append(
                    {
                        "type": "https",
                        "url": "https://127.0.0.1:%d/after-pin-failure"
                        % trailing_unreachable,
                    }
                )
            return {
                "version": 2,
                "service_id": "provider/conversations",
                "interfaces": interfaces,
                "privacy_modes": ["platform_readable"],
                "protocol_versions": [1],
            }

        with tempfile.TemporaryDirectory() as directory:
            old_certificate, old_key, old_pin = create_identity(directory, "old")
            next_certificate, next_key, next_pin = create_identity(directory, "next")
            profile_holder = {"value": None}
            old_server = start_server(old_certificate, old_key, profile_holder)
            next_server = start_server(next_certificate, next_key, profile_holder)
            old_port = old_server[0].getsockname()[1]
            next_port = next_server[0].getsockname()[1]
            unavailable = socket.socket()
            unavailable.bind(("127.0.0.1", 0))
            unavailable_port = unavailable.getsockname()[1]
            unavailable.close()
            try:
                phases = [
                    profile_for(old_port, [old_pin]),
                    profile_for(
                        old_port,
                        [old_pin, next_pin],
                        leading_unreachable=unavailable_port,
                        trailing_unreachable=unavailable_port,
                    ),
                    profile_for(next_port, [old_pin, next_pin]),
                    profile_for(next_port, [next_pin]),
                ]
                for profile in phases:
                    profile_holder["value"] = profile
                    client = ConversationClient.from_profile(profile, policy="auto")
                    self.assertIsNone(client.access_token)
                    client.close()

                old_requests_before_removal = len(old_server[3])
                old_removed = profile_for(
                    old_port,
                    [next_pin],
                    trailing_unreachable=unavailable_port,
                )
                profile_holder["value"] = old_removed
                with self.assertRaisesRegex(ssl.SSLError, "pin mismatch"):
                    ConversationClient.from_profile(old_removed, policy="auto")
                self.assertEqual(
                    len(old_server[3]),
                    old_requests_before_removal,
                    "removed old pin must fail before HTTP data",
                )
                requests = old_server[3] + next_server[3]
                self.assertEqual(len(requests), 4)
                for request in requests:
                    self.assertNotIn(b"authorization:", request.lower())
            finally:
                for listener, stopping, thread, _ in (old_server, next_server):
                    stopping.set()
                    listener.close()
                    thread.join(timeout=2)

    def test_client_validates_session_and_resolution_inputs_before_io(self):
        class RecordingClient(ConversationClient):
            def _request(self, method, path, body=None, **kwargs):
                return {"method": method, "path": path, "body": body}

        account = Keypair.from_secret_bytes(bytes([7]) * 32)
        operational = Keypair.from_secret_bytes(bytes([9]) * 32)
        subject = {
            "network": "testnet",
            "chain_id": "zincha-test",
            "kind": "task",
            "id": "ab" * 32,
        }
        delegation = create_conversation_delegation(
            account=account,
            operational=operational,
            encryption_public_key=crypto_scalarmult_base(bytes([11]) * 32),
            subject=subject,
            home_service_id="marketplace.example/conversations",
            not_before_ms=1,
            expires_at_ms=2,
        )
        client = RecordingClient("http://127.0.0.1:8080")
        session = client.create_session(
            {
                "challenge_id": "11111111-1111-4111-8111-111111111111",
                "challenge": "challenge",
            },
            delegation,
            operational,
        )
        self.assertEqual(session["path"], "/v1/auth/sessions")
        resolved = client.resolve(subject, account.address(), "platform_readable")
        self.assertEqual(resolved["path"], "/v1/conversations/resolve")
        with self.assertRaisesRegex(ValueError, "privacy mode"):
            client.resolve(subject, account.address(), "unsupported")
        with self.assertRaisesRegex(ValueError, "delegation ID"):
            client.revoke_delegation("../sessions")

    def test_protocol_bytes_match_cross_language_golden(self):
        import json
        from pathlib import Path

        path = Path(__file__).parents[2] / "testdata" / "golden-conversation-v1.json"
        golden = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(delegation_signing_bytes(golden["delegation"]).hex(), golden["delegation_signing_hex"])
        digest = conversation_payload_digest(golden["payload"])
        self.assertEqual(digest, golden["payload_digest"])
        self.assertEqual(
            message_signing_bytes(golden["conversation_id"], golden["sender"], golden["message"], digest).hex(),
            golden["message_signing_hex"],
        )

    def test_e2e_decrypts_cross_language_golden(self):
        import json
        from pathlib import Path

        path = Path(__file__).parents[2] / "testdata" / "golden-conversation-e2e-v1.json"
        golden = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            decrypt_conversation_e2e(
                golden["conversation_id"],
                golden["epoch"],
                golden["payload"],
                golden["recipient_key_id"],
                bytes.fromhex(golden["recipient_secret_hex"]),
            ),
            golden["plaintext"],
        )


if __name__ == "__main__":
    unittest.main()
