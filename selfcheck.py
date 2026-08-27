#!/usr/bin/env python3
"""Runnable self-check for technocore_tools: identity, payload, signature, stats.

No test framework, no network. Run: python3 selfcheck.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import technocore_tools as tt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOOL = Path(__file__).resolve().parent / "technocore_tools.py"


def check_base58_roundtrip() -> None:
    for blob in (b"", b"\x00\x00\x01", os.urandom(34), b"\x00" * 5 + os.urandom(10)):
        assert tt.base58btc_decode(tt.base58btc_encode(blob)) == blob, blob.hex()


def check_did_roundtrip() -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    did = tt.did_from_private_key(key)
    assert did.startswith("did:key:z6Mk"), did
    assert len(did) == len("did:key:") + tt.MULTIBASE_LENGTH, did
    raw = key.public_key().public_bytes(
        tt.serialization.Encoding.Raw, tt.serialization.PublicFormat.Raw
    )
    assert tt.public_bytes_from_did(did) == raw
    assert tt.short_did(did) == did.removeprefix("did:key:z6Mk")[:12]
    return key


def check_payload_and_signature(key: Ed25519PrivateKey) -> dict[str, str]:
    did = tt.did_from_private_key(key)
    # A tab and a newline are invisible characters: the sweep turns them into spaces.
    normalized, payload = tt.message_payload("general", 42, "  hello\tthere\nagent  ")
    assert normalized == "hello there agent", normalized
    assert payload == b"general|42|hello there agent", payload
    signature = base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("=")
    assert len(signature) == tt.SIGNATURE_LENGTH, len(signature)
    tt.verify_signature(did, signature, payload)  # must not raise

    # Tampering with any signed field must fail.
    for bad_payload in (b"general|43|hello there agent", b"other|42|hello there agent",
                        b"general|42|hello there agents"):
        try:
            tt.verify_signature(did, signature, bad_payload)
        except tt.ToolError:
            pass
        else:
            raise AssertionError(f"accepted a tampered payload: {bad_payload!r}")
    return {"did": did, "room": "general", "nonce": "42",
            "text": normalized, "sig": signature}


def check_analytics() -> None:
    messages = [
        {"seq": 1, "ts": "2026-01-01T00:00:00Z", "from": "did:key:z6MkAAA", "text": "ping @peer"},
        {"seq": 2, "ts": "2026-01-01T00:30:00Z", "from": "did:key:z6MkAAA", "text": "ping @peer"},
        {"seq": 3, "ts": "2026-01-01T01:00:00Z", "from": "nick", "text": "unsigned line"},
    ]
    report = tt.analyze_room("general", messages)
    assert report["messages"] == 3
    assert report["unique_authors"] == 2
    assert report["duplicate_lines"] == 1, report["duplicate_lines"]
    assert report["spam_suspects"][0]["count"] == 2
    assert report["top_mentions"][0] == {"handle": "peer", "count": 2}
    assert [entry["messages"] for entry in report["timeline"]] == [2, 1]
    # Control and format characters become spaces, so an escape sequence cannot
    # reach the terminal; the outer whitespace is stripped.
    assert tt.safe_text("a\x1b[31mred\u200b") == "a [31mred", tt.safe_text("a\x1b[31mred\u200b")


def check_cli(record: dict[str, str]) -> None:
    with tempfile.TemporaryDirectory() as workdir:
        work = Path(workdir)
        message_file = work / "msg.json"
        message_file.write_text(json.dumps(record), encoding="utf-8")
        env = dict(os.environ, TECHNOCORE_PASSPHRASE="selfcheck-pass", NO_COLOR="1")

        def run(*argv: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, str(TOOL), *argv],
                capture_output=True, text=True, env=env, timeout=60,
            )

        result = run("verify", str(message_file), "--json")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["valid"] is True

        tampered = dict(record, text=record["text"] + " extra")
        (work / "bad.json").write_text(json.dumps(tampered), encoding="utf-8")
        result = run("verify", str(work / "bad.json"), "--json")
        assert result.returncode == 1, result.stdout
        assert json.loads(result.stdout)["valid"] is False

        result = run("batch-init", "2", "-d", str(work / "identities"))
        assert result.returncode == 0, result.stderr
        manifest = json.loads((work / "identities" / "manifest.json").read_text("utf-8"))
        assert manifest["count"] == 2 and manifest["encrypted"] is True
        first = manifest["identities"][0]
        key_path = work / "identities" / first["file"]
        assert oct(key_path.stat().st_mode)[-3:] == "600", key_path.stat().st_mode

        result = run("export-did", str(key_path), "--did-document")
        assert result.returncode == 0, result.stderr
        exported = json.loads(result.stdout)
        assert exported["did"] == first["did"]
        assert exported["multicodec_hex"] == "ed01"
        assert exported["did_document"]["id"] == first["did"]

        # Re-running batch-init over an existing manifest must refuse.
        result = run("batch-init", "1", "-d", str(work / "identities"))
        assert result.returncode == 2 and "already exists" in result.stderr


def check_llm_optional() -> None:
    # LLM assist is off by default: no url/model means no network call, so the
    # tool works for anyone with no account and no key.
    assert tt.llm_answer("what is 2+2", url="", model="") is None
    assert tt.llm_answer("q", url="https://x/y", model="") is None
    # Header spec parses into a dict, tolerating blanks and missing colons.
    assert tt.parse_header_pairs("X-Tag: a, Authorization: b") == {
        "X-Tag": "a", "Authorization": "b"}
    assert tt.parse_header_pairs(" , bogus , Z:1 ") == {"Z": "1"}
    assert tt.parse_header_pairs("") == {}


def check_quiz_board() -> None:
    # KV notes escape line breaks as literal backslash-n; rows must still parse
    # and rank by points regardless of the order they arrive in.
    raw = (
        "flop quiz board\\npoints 10 5 3\\n"
        "did:key:z6MkpJmwjiFyEW9Z5149x6nW2MHS17jYMiRpFoV7nvmhdaQ1    10 pts    1 firsts    1 rounds\\n"
        "did:key:z6MkonSW3879Eun51qMR3YGGKyWasaxiTghbuEXZ9dZUhYmN    95 pts    9 firsts   10 rounds"
    )
    rows = tt.parse_quiz_board(raw)
    assert [row["points"] for row in rows] == [95, 10], rows
    assert rows[0]["did"].endswith("dZUhYmN") and rows[0]["rounds"] == 10, rows
    assert rows[1]["firsts"] == 1, rows
    # A malformed line is ignored, not fatal.
    assert tt.parse_quiz_board("no rows here\\ngarbage 12 pts") == []


def main() -> int:
    check_base58_roundtrip()
    key = check_did_roundtrip()
    record = check_payload_and_signature(key)
    check_analytics()
    check_llm_optional()
    check_quiz_board()
    check_cli(record)
    print("selfcheck: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
