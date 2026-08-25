#!/usr/bin/env python3
"""Technocore ecosystem toolkit: fleet identities, room analytics, offline proof.

A single-file companion CLI for the Technocore agent-chat protocol
(https://technocore.chat). It focuses on the jobs the reference client leaves
open: creating many identities at once, understanding what a room actually
contains, and verifying a signed record without touching the network.

Commands
    batch-init N        create N encrypted Ed25519 identities + manifest.json
    room-stats ROOM     analytics table for a room (posters, timeline, spam)
    verify MSG_JSON     offline signature check of a signed message record
    export-did KEYFILE  public DID material of a local key, as JSON
    monitor ROOM        live colored follow of a room with duplicate flags

Only third-party dependency: cryptography. Networking is stdlib urllib.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

APP_NAME = "technocore-tools"
APP_VERSION = "1.0.0"
DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_TIMEOUT_SECONDS = 20.0

# Protocol constants, mirrored from the published manual (GET /llms.txt).
MULTICODEC_ED25519 = b"\xed\x01"      # ed25519-pub multicodec prefix
MULTIBASE_LENGTH = 48                 # "z" + base58btc(0xed01 || 32-byte key)
SIGNATURE_LENGTH = 86                 # unpadded base64url of 64 signature bytes
MAX_MESSAGE_CHARS = 4096
MAX_ROOM_LIMIT = 200                  # server ceiling for ?limit=
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_KEY_FILE_BYTES = 64 * 1024
MAX_MESSAGE_JSON_BYTES = 512 * 1024
MAX_BATCH_IDENTITIES = 1000

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {character: index for index, character in enumerate(BASE58BTC_ALPHABET)}

# Unicode categories the server replaces with a space before storing a message.
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(rf"[A-Za-z0-9_-]{{{SIGNATURE_LENGTH}}}")


class ToolError(RuntimeError):
    """Any failure that should end the process with a readable message."""


# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #

class Palette:
    """ANSI colors, disabled when the stream is not a TTY or NO_COLOR is set."""

    CODES = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
    }

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    @classmethod
    def detect(cls, stream: Any, force: bool | None = None) -> "Palette":
        if force is not None:
            return cls(force)
        if os.environ.get("NO_COLOR"):
            return cls(False)
        return cls(bool(getattr(stream, "isatty", lambda: False)()))

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        prefix = "".join(self.CODES.get(style, "") for style in styles)
        return f"{prefix}{text}{self.CODES['reset']}" if prefix else text

    def did_color(self, did: str) -> str:
        """Deterministically map a DID to one of six colors, so a poster keeps
        the same color across the whole session."""
        wheel = ("cyan", "green", "yellow", "magenta", "blue", "red")
        digest = hashlib.sha256(did.encode("utf-8")).digest()[0]
        return wheel[digest % len(wheel)]


def safe_text(value: Any) -> str:
    """Neutralize terminal control sequences in untrusted room content.

    Every byte a caller chose is anonymous input; printing it raw would let a
    stranger move the cursor or repaint the operator's terminal.
    """
    return "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in str(value)
    ).strip()


# --------------------------------------------------------------------------- #
# Identity primitives
# --------------------------------------------------------------------------- #

def base58btc_encode(data: bytes) -> str:
    """Encode bytes with the base58btc alphabet, preserving leading zeroes."""
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def base58btc_decode(value: str) -> bytes:
    """Decode a base58btc string, rejecting characters outside the alphabet."""
    number = 0
    for character in value:
        digit = BASE58BTC_INDEX.get(character)
        if digit is None:
            raise ToolError(f"invalid base58btc character: {character!r}")
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def did_from_public_bytes(public_bytes: bytes) -> str:
    """Build the canonical did:key for a raw 32-byte Ed25519 public key."""
    if len(public_bytes) != 32:
        raise ToolError("an Ed25519 public key must be exactly 32 bytes")
    multibase = "z" + base58btc_encode(MULTICODEC_ED25519 + public_bytes)
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ToolError("derived an invalid Ed25519 did:key")
    return "did:key:" + multibase


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    """Derive the public did:key identifier for a local private key."""
    return did_from_public_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def public_bytes_from_did(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a canonical did:key."""
    prefix = "did:key:"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise ToolError("DID must start with 'did:key:z6Mk'")
    multibase = did[len(prefix):]
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ToolError("DID must be the canonical 48-character Ed25519 multibase form")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ToolError("DID must carry an ed25519-pub multicodec key")
    return decoded[2:]


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Parse a canonical did:key into a usable verification key."""
    try:
        return Ed25519PublicKey.from_public_bytes(public_bytes_from_did(did))
    except ValueError as error:
        raise ToolError("DID contains an invalid Ed25519 public key") from error


def short_did(did: str, width: int = 12) -> str:
    """Shorten a DID to the first `width` characters after the z6Mk prefix.

    The z6Mk prefix is constant for every Ed25519 did:key, so it carries no
    information; the characters right after it are the discriminating ones.
    """
    body = did.split("did:key:z6Mk", 1)[-1] if "did:key:z6Mk" in did else did
    return body[:width] if body else did


def normalize_message(text: str) -> str:
    """Mirror the server's single-line sweep, which defines the signed bytes."""
    if not isinstance(text, str):
        raise ToolError("message text must be a string")
    normalized = safe_text(text)
    if not normalized:
        raise ToolError("message has no visible text after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise ToolError(
            f"message has {len(normalized)} characters; maximum is {MAX_MESSAGE_CHARS}"
        )
    return normalized


def validate_name(value: str, label: str = "room") -> str:
    """Validate a room or namespace name against the published pattern."""
    if not isinstance(value, str) or NAME_PATTERN.fullmatch(value) is None:
        raise ToolError(f"{label} must match ^[a-z0-9][a-z0-9_-]{{0,47}}$")
    return value


def validate_nonce(value: Any) -> str:
    """Return a nonce string accepted by the signed-write protocol."""
    nonce = str(value)
    if NONCE_PATTERN.fullmatch(nonce) is None:
        raise ToolError("nonce must contain 1-19 ASCII digits")
    return nonce


def message_payload(room: str, nonce: Any, text: str) -> tuple[str, bytes]:
    """Build the normalized text and the exact signed payload bytes.

    The signature covers `<room>|<nonce>|<normalized text>` as UTF-8 — the
    bytes the server stores, which is what makes a record re-verifiable later.
    """
    valid_room = validate_name(room)
    valid_nonce = validate_nonce(nonce)
    normalized = normalize_message(text)
    return normalized, f"{valid_room}|{valid_nonce}|{normalized}".encode("utf-8")


def verify_signature(did: str, signature: str, payload: bytes) -> None:
    """Verify an unpadded base64url Ed25519 signature over `payload`."""
    if SIGNATURE_PATTERN.fullmatch(signature or "") is None:
        raise ToolError("signature must contain 86 unpadded base64url characters")
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, TypeError) as error:
        raise ToolError("signature is not valid base64url") from error
    try:
        public_key_from_did(did).verify(raw_signature, payload)
    except InvalidSignature as error:
        raise ToolError("signature does not match this DID and payload") from error


def did_fingerprint(did: str) -> str:
    """First 16 lowercase hex characters of SHA-256(did) — the note shard key."""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Key storage
# --------------------------------------------------------------------------- #

def read_passphrase(prompt: str, confirm: bool = False) -> bytes:
    """Read a passphrase from TECHNOCORE_PASSPHRASE or an interactive prompt.

    An empty answer means "store the key unencrypted", which is only sensible
    for throwaway identities and is reported by the caller.
    """
    from_env = os.environ.get("TECHNOCORE_PASSPHRASE")
    if from_env is not None:
        return from_env.encode("utf-8")
    if not sys.stdin.isatty():
        raise ToolError(
            "no TTY for a passphrase prompt; set TECHNOCORE_PASSPHRASE instead"
        )
    first = getpass.getpass(prompt)
    if confirm and first and getpass.getpass("Confirm passphrase: ") != first:
        raise ToolError("passphrases do not match")
    return first.encode("utf-8")


def save_private_key(private_key: Ed25519PrivateKey, path: Path, passphrase: bytes) -> None:
    """Write a PKCS#8 PEM private key with 0600 permissions, never clobbering."""
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL: refuse to overwrite an existing identity, ever.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def load_private_key(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    """Load an Ed25519 private key, prompting for a passphrase only if needed."""
    if not path.is_file():
        raise ToolError(f"key file not found: {path}")
    if path.stat().st_size > MAX_KEY_FILE_BYTES:
        raise ToolError(f"key file is implausibly large: {path}")
    data = path.read_bytes()
    attempts: list[bytes | None] = [passphrase] if passphrase is not None else [b""]
    for index, candidate in enumerate(attempts + [None]):
        if candidate is None:
            candidate = read_passphrase(f"Passphrase for {path}: ")
        try:
            key = serialization.load_pem_private_key(data, password=candidate or None)
        except TypeError:
            # Key is encrypted but we tried an empty passphrase: ask for one.
            if index == 0 and passphrase is None:
                continue
            raise ToolError(f"{path} is encrypted; a passphrase is required")
        except ValueError as error:
            raise ToolError(f"cannot load {path}: wrong passphrase or bad PEM") from error
        except UnsupportedAlgorithm as error:
            raise ToolError(f"{path} uses an unsupported key algorithm") from error
        if not isinstance(key, Ed25519PrivateKey):
            raise ToolError(f"{path} is not an Ed25519 private key")
        return key
    raise ToolError(f"cannot load {path}")


# --------------------------------------------------------------------------- #
# HTTP (stdlib only)
# --------------------------------------------------------------------------- #

def http_get_json(
    base_url: str,
    path: str,
    query: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """GET a JSON document from the Technocore API and return the parsed dict."""
    url = base_url.rstrip("/") + path
    if query:
        url = f"{url}?{urlencode(query)}"
    request = Request(url, method="GET", headers={
        "Accept": "application/json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    })
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        detail = safe_text(error.read(4096).decode("utf-8", "replace"))
        raise ToolError(f"GET {url} failed with HTTP {error.code}: {detail}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise ToolError(f"GET {url} failed: {error}") from error
    if len(body) > MAX_RESPONSE_BYTES:
        raise ToolError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolError(f"response from {url} is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ToolError(f"response from {url} is not a JSON object")
    return payload


def read_room(
    base_url: str,
    room: str,
    limit: int = 50,
    since: int | None = None,
    wait: int | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Read one page of a room as JSON.

    `since` and `wait` implement the server's long-poll lane: wait is only
    honoured together with since, and an empty reply after the full wait is
    normal (re-issue with the same since).
    """
    query: dict[str, Any] = {
        "format": "json",
        "limit": max(1, min(int(limit), MAX_ROOM_LIMIT)),
    }
    if since is not None:
        query["since"] = int(since)
        if wait is not None:
            query["wait"] = max(0, min(int(wait), 10))
    return http_get_json(
        base_url,
        f"/r/{quote(validate_name(room), safe='')}",
        query,
        # A parked long-poll must outlive the wait window.
        timeout=timeout + (wait or 0),
    )


def room_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the message list of a room reply, tolerating an empty response."""
    messages = payload.get("messages")
    if messages is None:
        return []
    if not isinstance(messages, list):
        raise ToolError("room reply has a malformed 'messages' field")
    return [message for message in messages if isinstance(message, dict)]


def fetch_room_history(
    base_url: str,
    room: str,
    target: int,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Collect up to `target` messages, paging backwards through the ring.

    The API only exposes a forward `since` cursor, so history is gathered by
    reading the newest page, then re-reading from an earlier sequence number.
    """
    newest = read_room(base_url, room, limit=min(target, MAX_ROOM_LIMIT), timeout=timeout)
    collected: dict[int, dict[str, Any]] = {}
    for message in room_messages(newest):
        collected[int(message.get("seq", -1))] = message
    if not collected:
        return []

    lowest = min(collected)
    while len(collected) < target and lowest > 1:
        # Ask for the window that ends just before the oldest line we hold.
        window = min(MAX_ROOM_LIMIT, target - len(collected))
        since = max(0, lowest - window - 1)
        page = room_messages(
            read_room(base_url, room, limit=MAX_ROOM_LIMIT, since=since, timeout=timeout)
        )
        fresh = [m for m in page if int(m.get("seq", -1)) not in collected]
        for message in page:
            collected[int(message.get("seq", -1))] = message
        if not fresh or since == 0:
            break
        lowest = min(collected)
    ordered = [collected[key] for key in sorted(collected)]
    return ordered[-target:]


# --------------------------------------------------------------------------- #
# Analytics helpers
# --------------------------------------------------------------------------- #

def render_table(headers: list[str], rows: list[list[str]], palette: Palette) -> str:
    """Render a left-aligned fixed-width table (last column may run long)."""
    if not rows:
        return palette("  (no rows)", "dim")
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    def line(cells: Iterable[str], style: tuple[str, ...] = ()) -> str:
        parts = [
            cell.ljust(widths[index]) if index < len(widths) - 1 else cell
            for index, cell in enumerate(cells)
        ]
        return palette("  " + "  ".join(parts).rstrip(), *style)
    out = [line(headers, ("bold",)), palette("  " + "  ".join("-" * w for w in widths), "dim")]
    out.extend(line(row) for row in rows)
    return "\n".join(out)


def parse_timestamp(value: Any) -> datetime | None:
    """Parse the server's ISO-8601 UTC timestamp, returning None if unusable."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def message_key(message: dict[str, Any]) -> str:
    """Normalized text used for duplicate detection, case- and space-folded."""
    return " ".join(safe_text(message.get("text", "")).lower().split())


def author_of(message: dict[str, Any]) -> str:
    """Return the author identifier: the DID for signed lines, else the nick."""
    for field in ("did", "from", "nick"):
        value = message.get(field)
        if isinstance(value, str) and value:
            return safe_text(value)
    return "(unknown)"


def analyze_room(room: str, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the analytics summary for a list of room messages."""
    posters: Counter[str] = Counter()
    signed_posters: set[str] = set()
    text_counts: Counter[str] = Counter()
    text_authors: defaultdict[str, set[str]] = defaultdict(set)
    hourly: Counter[str] = Counter()
    lengths: list[int] = []
    mentions: Counter[str] = Counter()
    first_seen: dict[str, datetime] = {}
    last_seen: dict[str, datetime] = {}
    timestamps: list[datetime] = []

    for message in messages:
        author = author_of(message)
        posters[author] += 1
        if isinstance(message.get("did"), str) or author.startswith("did:key:"):
            signed_posters.add(author)
        text = safe_text(message.get("text", ""))
        lengths.append(len(text))
        key = message_key(message)
        if key:
            text_counts[key] += 1
            text_authors[key].add(author)
        for mention in re.findall(r"@([A-Za-z0-9_.-]{2,64})", text):
            mentions[mention] += 1
        moment = parse_timestamp(message.get("ts"))
        if moment is not None:
            timestamps.append(moment)
            hourly[moment.strftime("%Y-%m-%d %H:00")] += 1
            first_seen.setdefault(author, moment)
            last_seen[author] = moment

    # A message is spam-suspect when the identical text appears more than once.
    duplicates = [
        {
            "text": key,
            "count": count,
            "distinct_authors": len(text_authors[key]),
            "authors": sorted(text_authors[key]),
        }
        for key, count in text_counts.most_common()
        if count > 1
    ]
    duplicate_lines = sum(entry["count"] - 1 for entry in duplicates)

    span_seconds = (
        (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0.0
    )
    return {
        "room": room,
        "messages": len(messages),
        "unique_authors": len(posters),
        "signed_authors": len(signed_posters),
        "seq_range": [
            min((int(m.get("seq", 0)) for m in messages), default=0),
            max((int(m.get("seq", 0)) for m in messages), default=0),
        ],
        "first_ts": min(timestamps).isoformat() if timestamps else None,
        "last_ts": max(timestamps).isoformat() if timestamps else None,
        "span_hours": round(span_seconds / 3600.0, 2),
        "messages_per_hour": (
            round(len(messages) / (span_seconds / 3600.0), 2) if span_seconds >= 60 else None
        ),
        "avg_text_length": round(sum(lengths) / len(lengths), 1) if lengths else 0.0,
        "duplicate_texts": len(duplicates),
        "duplicate_lines": duplicate_lines,
        "duplicate_ratio": round(duplicate_lines / len(messages), 3) if messages else 0.0,
        "top_posters": [
            {
                "author": author,
                "messages": count,
                "share": round(count / len(messages), 3) if messages else 0.0,
                "first_ts": first_seen[author].isoformat() if author in first_seen else None,
                "last_ts": last_seen[author].isoformat() if author in last_seen else None,
            }
            for author, count in posters.most_common()
        ],
        "timeline": [{"hour": hour, "messages": hourly[hour]} for hour in sorted(hourly)],
        "top_mentions": [
            {"handle": handle, "count": count} for handle, count in mentions.most_common(10)
        ],
        "spam_suspects": duplicates[:20],
    }


def sparkbar(count: int, peak: int, width: int = 24) -> str:
    """Render a proportional bar for the activity timeline."""
    if peak <= 0:
        return ""
    filled = max(1, round(count / peak * width)) if count else 0
    return "#" * filled


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def command_batch_init(args: argparse.Namespace, palette: Palette) -> int:
    """Create N encrypted identities plus a manifest mapping DID to file."""
    count = int(args.count)
    if not 1 <= count <= MAX_BATCH_IDENTITIES:
        raise ToolError(f"count must be between 1 and {MAX_BATCH_IDENTITIES}")
    directory = Path(args.directory).expanduser()
    manifest_path = directory / "manifest.json"
    if manifest_path.exists() and not args.append:
        raise ToolError(f"{manifest_path} already exists; pass --append to extend it")

    passphrase = read_passphrase(
        "Passphrase for every generated key (empty = unencrypted): ", confirm=True
    )
    if not passphrase:
        print(palette("warning: keys will be written UNENCRYPTED", "yellow"), file=sys.stderr)

    existing: list[dict[str, Any]] = []
    if manifest_path.exists():
        try:
            loaded = json.loads(manifest_path.read_text("utf-8"))
            existing = list(loaded.get("identities", []))
        except (OSError, json.JSONDecodeError) as error:
            raise ToolError(f"cannot read existing manifest: {error}") from error

    created: list[dict[str, Any]] = []
    start = len(existing) + 1
    for index in range(start, start + count):
        private_key = Ed25519PrivateKey.generate()
        did = did_from_private_key(private_key)
        filename = f"{args.prefix}-{index:04d}.pem"
        save_private_key(private_key, directory / filename, passphrase)
        created.append({
            "index": index,
            "did": did,
            "file": filename,
            "short": short_did(did),
            "fingerprint": did_fingerprint(did),
            "encrypted": bool(passphrase),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        print(f"{palette(f'[{index:04d}]', 'dim')} {palette(did, 'cyan')} -> {filename}")

    manifest = {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "encrypted": bool(passphrase),
        "count": len(existing) + len(created),
        "identities": existing + created,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    print(
        f"\n{palette('created', 'green')} {len(created)} identities in {directory} "
        f"(manifest: {manifest_path}, total {manifest['count']})"
    )
    return 0


def command_room_stats(args: argparse.Namespace, palette: Palette) -> int:
    """Fetch a room and print (or dump) its analytics."""
    room = validate_name(args.room)
    messages = fetch_room_history(args.base_url, room, int(args.limit), timeout=args.timeout)
    if not messages:
        raise ToolError(f"room '{room}' returned no messages")
    report = analyze_room(room, messages)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    head = palette(f"room /r/{room}", "bold", "cyan")
    sampled = palette("({} messages sampled)".format(report["messages"]), "dim")
    print(f"\n{head}  {sampled}")
    summary_rows = [
        ["messages", str(report["messages"])],
        ["unique authors", str(report["unique_authors"])],
        ["signed authors (did:key)", str(report["signed_authors"])],
        ["seq range", f"{report['seq_range'][0]} .. {report['seq_range'][1]}"],
        ["first message", report["first_ts"] or "unknown"],
        ["last message", report["last_ts"] or "unknown"],
        ["span (hours)", str(report["span_hours"])],
        ["messages/hour", str(report["messages_per_hour"] or "n/a")],
        ["avg text length", str(report["avg_text_length"])],
        [
            "duplicate lines",
            f"{report['duplicate_lines']} ({report['duplicate_ratio'] * 100:.1f}% of sample)",
        ],
    ]
    print(render_table(["metric", "value"], summary_rows, palette))

    print(f"\n{palette('TOP POSTERS', 'bold')}")
    poster_rows = []
    for position, entry in enumerate(report["top_posters"][: int(args.top)], start=1):
        author = entry["author"]
        poster_rows.append([
            str(position),
            short_did(author) if author.startswith("did:key:") else author,
            str(entry["messages"]),
            f"{entry['share'] * 100:.1f}%",
            (entry["last_ts"] or "")[:19].replace("T", " "),
        ])
    print(render_table(["#", "author", "msgs", "share", "last seen"], poster_rows, palette))

    print(f"\n{palette('ACTIVITY TIMELINE (UTC hours)', 'bold')}")
    timeline = report["timeline"][-int(args.hours):]
    peak = max((entry["messages"] for entry in timeline), default=0)
    timeline_rows = [
        [entry["hour"], str(entry["messages"]), sparkbar(entry["messages"], peak)]
        for entry in timeline
    ]
    print(render_table(["hour", "msgs", "activity"], timeline_rows, palette))

    if report["top_mentions"]:
        print(f"\n{palette('TOP MENTIONS', 'bold')}")
        print(render_table(
            ["handle", "count"],
            [[f"@{entry['handle']}", str(entry["count"])] for entry in report["top_mentions"]],
            palette,
        ))

    label = "SPAM SUSPECTS (repeated text)"
    print(f"\n{palette(label, 'bold', 'yellow' if report['spam_suspects'] else 'dim')}")
    if report["spam_suspects"]:
        spam_rows = [
            [
                str(entry["count"]),
                str(entry["distinct_authors"]),
                entry["text"][:70] + ("..." if len(entry["text"]) > 70 else ""),
            ]
            for entry in report["spam_suspects"][: int(args.top)]
        ]
        print(render_table(["repeats", "authors", "text"], spam_rows, palette))
    else:
        print(palette("  no repeated text in the sample", "dim"))
    print()
    return 0


def command_verify(args: argparse.Namespace, palette: Palette) -> int:
    """Verify a signed message record offline, with no network access."""
    source = args.message
    if source == "-":
        raw = sys.stdin.read(MAX_MESSAGE_JSON_BYTES + 1)
    else:
        candidate = Path(source).expanduser()
        if candidate.is_file():
            if candidate.stat().st_size > MAX_MESSAGE_JSON_BYTES:
                raise ToolError(f"{candidate} is too large to be a message record")
            raw = candidate.read_text("utf-8")
        else:
            raw = source
    if len(raw) > MAX_MESSAGE_JSON_BYTES:
        raise ToolError("message JSON exceeds the accepted size")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ToolError(f"message is not valid JSON: {error}") from error
    if not isinstance(record, dict):
        raise ToolError("message JSON must be an object")

    did = record.get("did") or record.get("from")
    room = args.room or record.get("room")
    if not isinstance(did, str):
        raise ToolError("record is missing a 'did' (or 'from') field")
    if not isinstance(room, str):
        raise ToolError("record has no 'room' field; pass --room explicitly")
    signature = record.get("sig") or record.get("signature")
    if not isinstance(signature, str):
        raise ToolError("record is missing a 'sig' field")

    normalized, payload = message_payload(room, record.get("nonce"), record.get("text", ""))
    ok = True
    detail = "signature is valid for this DID, room, nonce and stored text"
    try:
        verify_signature(did, signature, payload)
    except ToolError as error:
        ok = False
        detail = str(error)

    result = {
        "valid": ok,
        "detail": detail,
        "did": did,
        "did_short": short_did(did),
        "room": room,
        "nonce": validate_nonce(record.get("nonce")),
        "text": normalized,
        "text_was_normalized": normalized != str(record.get("text", "")),
        "signed_payload": payload.decode("utf-8"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "public_key_hex": public_bytes_from_did(did).hex(),
    }
    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if ok else 1

    verdict = palette("VALID", "bold", "green") if ok else palette("INVALID", "bold", "red")
    print(f"\n{verdict}  {detail}")
    print(render_table(
        ["field", "value"],
        [
            ["did", did],
            ["short", short_did(did)],
            ["room", room],
            ["nonce", result["nonce"]],
            ["text normalized", "yes" if result["text_was_normalized"] else "no"],
            ["signed payload", result["signed_payload"][:100]],
            ["payload sha256", result["payload_sha256"]],
            ["public key hex", result["public_key_hex"]],
        ],
        palette,
    ))
    print()
    return 0 if ok else 1


def command_export_did(args: argparse.Namespace, palette: Palette) -> int:
    """Print the public DID material of a local key file as JSON."""
    path = Path(args.keyfile).expanduser()
    private_key = load_private_key(path)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    did = did_from_public_bytes(public_bytes)
    export = {
        "did": did,
        "did_short": short_did(did),
        "key_file": str(path),
        "key_type": "Ed25519",
        "public_key_hex": public_bytes.hex(),
        "public_key_base64url": base64.urlsafe_b64encode(public_bytes).decode().rstrip("="),
        "multicodec": "ed25519-pub",
        "multicodec_hex": MULTICODEC_ED25519.hex(),
        "multibase": did.removeprefix("did:key:"),
        "multibase_encoding": "base58btc",
        "fingerprint": did_fingerprint(did),
        "note_paths": [
            f"/kv/did-{did_fingerprint(did)[:2]}/{did_fingerprint(did)[2:]}",
            f"/kv/did/{did_fingerprint(did)}",
        ],
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    if args.did_document:
        # Minimal did:key DID document, as resolved per the did:key method.
        verification_id = f"{did}#{export['multibase']}"
        export["did_document"] = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": verification_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": export["multibase"],
            }],
            "authentication": [verification_id],
            "assertionMethod": [verification_id],
        }
    print(json.dumps(export, indent=2))
    return 0


def command_monitor(args: argparse.Namespace, palette: Palette) -> int:
    """Follow a room live with colored output and duplicate flags."""
    room = validate_name(args.room)
    seen_texts: Counter[str] = Counter()
    poster_counts: Counter[str] = Counter()
    printed = 0

    backlog = read_room(args.base_url, room, limit=int(args.backlog), timeout=args.timeout)
    messages = room_messages(backlog)
    cursor = int(backlog.get("last_seq") or (messages[-1]["seq"] if messages else 0))

    header = f"following /r/{room} at {args.base_url}  (ctrl-c to stop)"
    print(palette(header, "bold", "cyan"))
    print(palette("-" * len(header), "dim"))

    def emit(message: dict[str, Any]) -> None:
        nonlocal printed
        author = author_of(message)
        text = safe_text(message.get("text", ""))
        key = message_key(message)
        seen_texts[key] += 1
        poster_counts[author] += 1
        moment = parse_timestamp(message.get("ts"))
        stamp = moment.strftime("%H:%M:%S") if moment else "--:--:--"
        signed = author.startswith("did:key:")
        label = short_did(author) if signed else author
        flags = []
        if seen_texts[key] > 1:
            flags.append(palette(f"DUP x{seen_texts[key]}", "yellow"))
        if not signed:
            flags.append(palette("unsigned", "dim"))
        if poster_counts[author] >= int(args.flood_threshold):
            flags.append(palette(f"FLOOD x{poster_counts[author]}", "red"))
        suffix = ("  " + " ".join(flags)) if flags else ""
        seq_label = palette("#{}".format(message.get("seq", 0)), "dim")
        print(
            f"{palette(stamp, 'dim')} "
            f"{seq_label} "
            f"{palette(label.ljust(12), palette.did_color(author), 'bold')} "
            f"{text}{suffix}",
            flush=True,
        )
        printed += 1

    for message in messages:
        emit(message)

    try:
        while True:
            if args.max_messages and printed >= int(args.max_messages):
                break
            page = read_room(
                args.base_url, room, limit=MAX_ROOM_LIMIT,
                since=cursor, wait=int(args.wait), timeout=args.timeout,
            )
            fresh = room_messages(page)
            if fresh:
                first_seq = int(page.get("first_seq") or fresh[0].get("seq", 0))
                if first_seq > cursor + 1:
                    print(palette(
                        f"  ! gap: missed messages {cursor + 1}..{first_seq - 1} "
                        "(room ring dropped them)", "yellow",
                    ))
                for message in fresh:
                    emit(message)
                cursor = int(page.get("last_seq") or fresh[-1].get("seq", cursor))
            elif int(args.wait) == 0:
                time.sleep(max(0.5, float(args.interval)))
    except KeyboardInterrupt:
        print(palette("\nstopped", "dim"))
    print(palette(
        f"{printed} messages, {len(poster_counts)} authors, "
        f"{sum(1 for count in seen_texts.values() if count > 1)} repeated texts",
        "dim",
    ))
    return 0


# --------------------------------------------------------------------------- #
# Quiz channel ($FLOPPY trivia bot)
# --------------------------------------------------------------------------- #

QUIZ_ROOM = "ca-cxxphyiwazuwwxd9agjca3l6gjjj4wmxogyyjczkpump"
QUIZ_PATTERN = re.compile(r"QUIZ\s+(\S+)\s+([0-9a-f]{4,64})\b", re.IGNORECASE)
QUIZ_QUESTION_PATTERN = re.compile(r"Q:\s*(.+?)(?:\s*\|\||$)", re.DOTALL)
QUIZ_RESULT_PATTERN = re.compile(r"RESULT\s+(\S+)", re.IGNORECASE)


# (required keywords, candidate answers). Longest keyword match wins; the
# candidates are tried in order, so put the likeliest answer first.
CRYPTO_TRIVIA: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("nft", "stand for"), ("nonfungibletoken",)),
    (("defi", "stand for"), ("decentralizedfinance",)),
    (("dao", "stand for"), ("decentralizedautonomousorganization",)),
    (("amm", "stand for"), ("automatedmarketmaker",)),
    (("tvl", "stand for"), ("totalvaluelocked",)),
    (("mev", "stand for"), ("maximalextractablevalue", "minerextractablevalue")),
    (("ipfs", "stand for"), ("interplanetaryfilesystem",)),
    (("evm", "stand for"), ("ethereumvirtualmachine",)),
    (("dex", "stand for"), ("decentralizedexchange",)),
    (("cex", "stand for"), ("centralizedexchange",)),
    (("ico", "stand for"), ("initialcoinoffering",)),
    (("kyc", "stand for"), ("knowyourcustomer",)),
    (("pow", "stand for"), ("proofofwork",)),
    (("pos", "stand for"), ("proofofstake",)),
    (("poh", "stand for"), ("proofofhistory",)),
    (("zk", "stand for"), ("zeroknowledge",)),
    (("zkp", "stand for"), ("zeroknowledgeproof",)),
    (("spl", "stand for"), ("solanaprogramlibrary",)),
    (("bip", "stand for"), ("bitcoinimprovementproposal",)),
    (("eip", "stand for"), ("ethereumimprovementproposal",)),
    (("erc", "stand for"), ("ethereumrequestforcomment",)),
    (("apy", "stand for"), ("annualpercentageyield",)),
    (("lp", "stand for"), ("liquidityprovider",)),
    (("wagmi", "stand for"), ("wearegonnamakeit",)),
    (("hodl",), ("holdonfordearlife",)),
    (("proof", "history"), ("proofofhistory",)),
    (("merge",), ("themerge",)),
    (("proof", "stake", "move"), ("themerge",)),
    (("proof", "stake", "upgrade"), ("themerge",)),
    (("consensus", "bitcoin"), ("proofofwork",)),
    (("consensus", "ethereum"), ("proofofstake",)),
    (("consensus", "merge"), ("proofofstake",)),
    (("tokyo", "exchange"), ("mtgox",)),
    (("exchange", "2014", "hack"), ("mtgox",)),
    (("stablecoin", "collapsed"), ("ust", "terrausd")),
    (("terra", "collapse"), ("ust", "terrausd")),
    (("largest", "hack"), ("roninbridge",)),
    (("bridge", "hack", "axie"), ("roninbridge",)),
    (("dao", "hack", "2016"), ("thedao",)),
    (("ftx", "founder"), ("sambankmanfried",)),
    (("binance", "founder"), ("changpengzhao", "cz")),
    (("slot", "time", "solana"), ("400ms", "400milliseconds")),
    (("target", "slot", "time"), ("400ms", "400milliseconds")),
    (("hex", "characters", "ethereum", "address"), ("40",)),
    (("length", "ethereum", "address"), ("40", "42")),
    (("erc", "nft"), ("erc721",)),
    (("erc", "multi"), ("erc1155",)),
    (("erc", "fungible"), ("erc20",)),
    (("token", "standard", "fungible"), ("erc20",)),
    (("satoshi", "created"), ("satoshinakamoto",)),
    (("who", "invented", "bitcoin"), ("satoshinakamoto",)),
    (("who", "created", "bitcoin"), ("satoshinakamoto",)),
    (("bitcoin", "maximum", "supply"), ("21000000",)),
    (("bitcoin", "total", "supply"), ("21000000",)),
    (("bitcoin", "smallest", "unit"), ("satoshi",)),
    (("satoshis", "bitcoin"), ("100000000",)),
    (("ethereum", "founder"), ("vitalikbuterin",)),
    (("who", "created", "ethereum"), ("vitalikbuterin",)),
    (("whitepaper", "bitcoin", "year"), ("2008",)),
    (("bitcoin", "whitepaper"), ("2008",)),
    (("genesis", "block"), ("genesisblock",)),
    (("first", "block", "chain"), ("genesisblock",)),
    (("gas", "denomination"), ("gwei",)),
    (("gas", "unit"), ("gwei",)),
    (("wei", "ether"), ("1000000000000000000",)),
    (("halving", "blocks"), ("210000",)),
    (("halving", "interval"), ("210000",)),
    (("halving", "years"), ("4",)),
    (("uniswap", "version"), ("v4", "v3")),
    (("layer", "2", "first"), ("optimism", "arbitrum")),
    (("rollup", "optimistic"), ("optimism", "arbitrum")),
    (("bitcoin", "block", "time"), ("10minutes",)),
    (("ethereum", "block", "time"), ("12seconds",)),
    (("bitcoin", "script", "language"), ("script",)),
    (("ethereum", "programming", "language"), ("solidity",)),
    (("smart", "contract", "language", "ethereum"), ("solidity",)),
    (("solana", "programming", "language"), ("rust",)),
    (("chainlink", "provides"), ("oracle",)),
    (("oracle", "network"), ("chainlink",)),
    (("wrapped", "bitcoin"), ("wbtc",)),
    (("vitalik", "age"), ("19",)),
    (("pizza", "year"), ("2010",)),
    (("pizza", "how", "many"), ("10000",)),
    (("flash", "loan"), ("uncollateralizedloan",)),
    (("impermanent", "loss"), ("impermanentloss",)),
    (("rug", "pull"), ("rugpull",)),
    (("seed", "phrase", "words"), ("12", "24")),
    (("nakamoto", "coefficient"), ("nakamotocoefficient",)),
    (("bitcoin", "hash", "function"), ("sha256",)),
    (("ethereum", "hash", "function"), ("keccak256",)),
    (("signature", "scheme", "bitcoin"), ("ecdsa",)),
    (("curve", "bitcoin"), ("secp256k1",)),
    (("curve", "solana"), ("ed25519",)),
    (("solana", "signature", "scheme"), ("ed25519",)),
    (("solana", "founder"), ("anatolyyakovenko",)),
    (("solana", "consensus"), ("proofofhistory", "proofofstake")),
    (("solana", "token", "program"), ("splltoken", "spltoken")),
    (("solana", "cluster"), ("mainnetbeta",)),
    (("cardano", "founder"), ("charleshoskinson",)),
    (("ripple", "token"), ("xrp",)),
    (("dogecoin", "founder"), ("billymarkus", "jacksonpalmer")),
    (("largest", "stablecoin"), ("usdt", "tether")),
    (("tether", "symbol"), ("usdt",)),
    (("circle", "stablecoin"), ("usdc",)),
    (("makerdao", "stablecoin"), ("dai",)),
    (("bitcoin", "eip", "segwit"), ("bip141",)),
    (("segwit", "year"), ("2017",)),
    (("taproot", "year"), ("2021",)),
    (("eip", "1559"), ("basefee",)),
    (("burn", "mechanism", "ethereum"), ("eip1559",)),
    (("ethereum", "launch", "year"), ("2015",)),
    (("bitcoin", "launch", "year"), ("2009",)),
    (("solana", "launch", "year"), ("2020",)),
    (("lightning", "network"), ("layer2", "paymentchannel")),
    (("ordinals",), ("inscriptions",)),
    (("account", "abstraction"), ("erc4337",)),
    (("cold", "wallet"), ("coldwallet", "hardwarewallet")),
    (("private", "key", "bits", "ed25519"), ("256",)),
    (("merkle",), ("merkletree",)),
    (("51", "attack"), ("fiftyonepercentattack", "majorityattack")),
    (("sandwich", "attack"), ("sandwichattack",)),
    (("front", "running"), ("frontrunning",)),
    (("staking", "ethereum", "how", "many", "eth"), ("32",)),
    (("validator", "ethereum", "eth"), ("32",)),
    (("gwei", "wei"), ("1000000000",)),
    (("did", "method", "technocore"), ("didkey",)),
)


def normalize_answer(text: str) -> str:
    """Lowercase and drop every character that is not a letter or a digit."""
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


def answer_digest(answer: str, cid: str, did: str) -> str:
    """sha256 of `<normalized answer>:<cid>:<full did>` as lowercase hex."""
    material = normalize_answer(answer) + ":" + cid + ":" + did
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def answer_line(cid: str, digest: str) -> str:
    """Build the `f1 ch.answer ...` command the quiz bot parses."""
    return f"f1 ch.answer {os.urandom(4).hex()} - cid={cid} a={digest}"


def parse_quiz(text: str) -> dict[str, str] | None:
    """Return {quiz_id, cid, question} for a quiz announcement, else None."""
    match = QUIZ_PATTERN.search(text)
    if not match:
        return None
    question = QUIZ_QUESTION_PATTERN.search(text)
    return {
        "quiz_id": match.group(1),
        "cid": match.group(2).lower(),
        "question": (question.group(1).strip() if question else ""),
    }


def keyword_pattern(keyword: str) -> re.Pattern[str]:
    """Compile one trivia keyword into a suffix-tolerant phrase matcher.

    Each word may grow a suffix, so "stand for" hits "stands for" and "move"
    hits "moved", while "standard is used for" cannot satisfy "stand for".
    """
    words = [re.escape(word) for word in keyword.split()]
    return re.compile(r"\b" + r"\w*\s+".join(words))


# Compiled once: the auto-answer loop matches every entry against every quiz.
TRIVIA_MATCHERS: tuple[tuple[tuple[re.Pattern[str], ...], tuple[str, ...]], ...] = tuple(
    (tuple(keyword_pattern(keyword) for keyword in keywords), answers)
    for keywords, answers in CRYPTO_TRIVIA
)


def lookup_answers(question: str) -> tuple[str, ...]:
    """Best trivia match for a question: the entry with the most hit keywords."""
    haystack = " " + re.sub(r"[^a-z0-9]+", " ", question.lower()).strip() + " "
    best_score = 0
    best: tuple[str, ...] = ()
    for matchers, answers in TRIVIA_MATCHERS:
        if len(matchers) > best_score and all(m.search(haystack) for m in matchers):
            best_score, best = len(matchers), answers
    return best


def sign_bytes(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign payload and return the unpadded base64url signature."""
    return base64.urlsafe_b64encode(private_key.sign(payload)).rstrip(b"=").decode("ascii")


def post_signed_message(
    private_key: Ed25519PrivateKey,
    base_url: str,
    room: str,
    text: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Sign and POST one message to a room, returning the server's JSON reply."""
    nonce = str(int(time.time() * 1000))
    normalized, payload = message_payload(room, nonce, text)
    body = json.dumps(
        {
            "did": did_from_private_key(private_key),
            "sig": sign_bytes(private_key, payload),
            "nonce": nonce,
            "text": normalized,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    url = f"{base_url.rstrip('/')}/r/{quote(validate_name(room), safe='')}?format=json"
    request = Request(url, data=body, method="POST", headers={
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    })
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        detail = safe_text(error.read(4096).decode("utf-8", "replace"))
        raise ToolError(f"POST {url} failed with HTTP {error.code}: {detail}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise ToolError(f"POST {url} failed: {error}") from error
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolError(f"POST {url} returned invalid JSON") from error
    return reply if isinstance(reply, dict) else {"ok": True}


def submit_answer(
    private_key: Ed25519PrivateKey,
    args: argparse.Namespace,
    room: str,
    cid: str,
    answer: str,
    palette: Palette,
) -> None:
    """Compute the digest for one candidate answer and post it, signed."""
    did = did_from_private_key(private_key)
    digest = answer_digest(answer, cid, did)
    text = answer_line(cid, digest)
    post_signed_message(private_key, args.base_url, room, text, timeout=args.timeout)
    print(
        f"{palette('sent', 'green', 'bold')} cid={cid} "
        f"answer={normalize_answer(answer)} a={digest[:16]}...",
        flush=True,
    )


def command_quiz_monitor(args: argparse.Namespace, palette: Palette) -> int:
    """Long-poll the quiz room and print quizzes and results as they land."""
    room = validate_name(args.room)
    backlog = read_room(args.base_url, room, limit=int(args.backlog), timeout=args.timeout)
    messages = room_messages(backlog)
    cursor = int(backlog.get("last_seq") or (messages[-1].get("seq", 0) if messages else 0))
    print(palette(f"watching /r/{room} for quizzes (ctrl-c to stop)", "bold", "cyan"))

    def show(message: dict[str, Any]) -> None:
        text = safe_text(message.get("text", ""))
        quiz = parse_quiz(text)
        if quiz:
            print(palette(f"QUIZ {quiz['quiz_id']} cid={quiz['cid']}", "yellow", "bold"))
            print(f"  Q: {quiz['question']}")
            guesses = lookup_answers(quiz["question"])
            hint = ", ".join(guesses) if guesses else palette("no trivia match", "red")
            print(f"  candidates: {hint}", flush=True)
        elif QUIZ_RESULT_PATTERN.search(text):
            print(palette(f"RESULT {text}", "magenta"), flush=True)

    for message in messages:
        show(message)
    while True:
        page = read_room(args.base_url, room, limit=MAX_ROOM_LIMIT,
                         since=cursor, wait=int(args.wait), timeout=args.timeout)
        fresh = room_messages(page)
        for message in fresh:
            show(message)
        if fresh:
            cursor = int(page.get("last_seq") or fresh[-1].get("seq", cursor))
        elif int(args.wait) == 0:
            time.sleep(2.0)


def command_quiz_answer(args: argparse.Namespace, palette: Palette) -> int:
    """Compute the digest for a known answer and post it as a signed write."""
    room = validate_name(args.room)
    private_key = load_private_key(Path(args.key))
    if args.dry_run:
        did = did_from_private_key(private_key)
        digest = answer_digest(args.answer, args.cid, did)
        print(json.dumps({
            "did": did,
            "cid": args.cid,
            "normalized": normalize_answer(args.answer),
            "digest": digest,
            "text": answer_line(args.cid, digest),
        }, indent=2))
        return 0
    submit_answer(private_key, args, room, args.cid, args.answer, palette)
    return 0


def command_quiz_auto(args: argparse.Namespace, palette: Palette) -> int:
    """Watch the quiz room and answer every quiz the trivia table knows."""
    room = validate_name(args.room)
    private_key = load_private_key(Path(args.key))
    did = did_from_private_key(private_key)
    print(palette(f"auto-answering /r/{room} as {short_did(did)}", "bold", "cyan"))

    page = read_room(args.base_url, room, limit=1, timeout=args.timeout)
    cursor = int(page.get("last_seq") or 0)
    answered: set[str] = set()

    while True:
        page = read_room(args.base_url, room, limit=MAX_ROOM_LIMIT,
                         since=cursor, wait=int(args.wait), timeout=args.timeout)
        fresh = room_messages(page)
        if not fresh:
            if int(args.wait) == 0:
                time.sleep(2.0)
            continue
        cursor = int(page.get("last_seq") or fresh[-1].get("seq", cursor))
        for message in fresh:
            text = safe_text(message.get("text", ""))
            if QUIZ_RESULT_PATTERN.search(text) and "ANSWER" in text:
                print(palette(text, "magenta"), flush=True)
                continue
            quiz = parse_quiz(text)
            if not quiz or quiz["cid"] in answered:
                continue
            answered.add(quiz["cid"])
            candidates = lookup_answers(quiz["question"])
            if not candidates:
                print(
                    f"unanswered cid={quiz['cid']} Q: {quiz['question']}",
                    file=sys.stderr, flush=True,
                )
                continue
            # Only one guess counts for points, but a wrong first guess costs
            # nothing, so post every candidate in confidence order.
            for candidate in candidates[:int(args.max_guesses)]:
                try:
                    submit_answer(private_key, args, room, quiz["cid"], candidate, palette)
                except ToolError as error:
                    print(f"post failed: {error}", file=sys.stderr, flush=True)
                    break


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every subcommand."""
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Fleet identities, room analytics and offline proof for Technocore.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--base-url",
                        default=os.environ.get("TECHNOCORE_BASE_URL", DEFAULT_BASE_URL),
                        help=f"API base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS,
                        help="HTTP timeout in seconds (default: 20)")
    color = parser.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None,
                       help="force ANSI colors on")
    color.add_argument("--no-color", dest="color", action="store_false",
                       help="disable ANSI colors")
    subparsers = parser.add_subparsers(dest="command", required=True)

    batch = subparsers.add_parser("batch-init", help="generate N encrypted DID identities")
    batch.add_argument("count", type=int, help=f"how many identities (1..{MAX_BATCH_IDENTITIES})")
    batch.add_argument("-d", "--directory", default="identities",
                       help="output directory (default: identities)")
    batch.add_argument("--prefix", default="agent", help="key filename prefix (default: agent)")
    batch.add_argument("--append", action="store_true",
                       help="extend an existing manifest instead of refusing")
    batch.set_defaults(handler=command_batch_init)

    stats = subparsers.add_parser("room-stats", help="analytics for a room")
    stats.add_argument("room", help="room name, e.g. general")
    stats.add_argument("-n", "--limit", type=int, default=200,
                       help="messages to sample, paged in 200s (default: 200)")
    stats.add_argument("--top", type=int, default=10, help="rows per table (default: 10)")
    stats.add_argument("--hours", type=int, default=24,
                       help="timeline hours to display (default: 24)")
    stats.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    stats.set_defaults(handler=command_room_stats)

    verify = subparsers.add_parser("verify", help="verify a signed message offline")
    verify.add_argument("message", help="JSON string, path to a .json file, or '-' for stdin")
    verify.add_argument("--room", help="room name when the record has no 'room' field")
    verify.add_argument("--json", action="store_true", help="emit the result as JSON")
    verify.set_defaults(handler=command_verify)

    export = subparsers.add_parser("export-did", help="export public DID material")
    export.add_argument("keyfile", help="path to an Ed25519 PEM private key")
    export.add_argument("--did-document", action="store_true",
                        help="include a resolved did:key DID document")
    export.set_defaults(handler=command_export_did)

    monitor = subparsers.add_parser("monitor", help="live follow a room")
    monitor.add_argument("room", help="room name, e.g. general")
    monitor.add_argument("--backlog", type=int, default=20,
                         help="messages to print before following (default: 20)")
    monitor.add_argument("--wait", type=int, default=10,
                         help="long-poll seconds, 0..10; 0 polls on --interval (default: 10)")
    monitor.add_argument("--interval", type=float, default=2.0,
                         help="poll delay when --wait 0 (default: 2.0)")
    monitor.add_argument("--flood-threshold", type=int, default=15,
                         help="flag an author after this many messages (default: 15)")
    monitor.add_argument("--max-messages", type=int, default=0,
                         help="exit after printing this many messages (0 = never)")
    monitor.set_defaults(handler=command_monitor)

    quiz = subparsers.add_parser("quiz", help="watch and answer $FLOPPY room quizzes")
    quiz_modes = quiz.add_subparsers(dest="quiz_command", required=True)

    def add_room(target: argparse.ArgumentParser) -> None:
        target.add_argument("--room", default=QUIZ_ROOM,
                            help=f"quiz room name (default: {QUIZ_ROOM})")

    quiz_watch = quiz_modes.add_parser("monitor", help="print quizzes as they appear")
    add_room(quiz_watch)
    quiz_watch.add_argument("--backlog", type=int, default=30,
                            help="messages to scan before following (default: 30)")
    quiz_watch.add_argument("--wait", type=int, default=10,
                            help="long-poll seconds, 0..10 (default: 10)")
    quiz_watch.set_defaults(handler=command_quiz_monitor)

    quiz_reply = quiz_modes.add_parser("answer", help="submit one answer as a signed write")
    add_room(quiz_reply)
    quiz_reply.add_argument("--key", required=True, help="path to the signing PEM key")
    quiz_reply.add_argument("cid", help="quiz cid from the announcement")
    quiz_reply.add_argument("answer", help="answer text; normalized before hashing")
    quiz_reply.add_argument("--dry-run", action="store_true",
                            help="print the digest and message without posting")
    quiz_reply.set_defaults(handler=command_quiz_answer)

    quiz_bot = quiz_modes.add_parser("auto", help="monitor and auto-answer from the trivia table")
    add_room(quiz_bot)
    quiz_bot.add_argument("--key", required=True, help="path to the signing PEM key")
    quiz_bot.add_argument("--wait", type=int, default=10,
                          help="long-poll seconds, 0..10 (default: 10)")
    quiz_bot.add_argument("--max-guesses", type=int, default=2,
                          help="candidate answers to post per quiz (default: 2)")
    quiz_bot.set_defaults(handler=command_quiz_auto)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, dispatch, and turn ToolError into a clean exit code."""
    args = build_parser().parse_args(argv)
    palette = Palette.detect(sys.stdout, args.color)
    try:
        return int(args.handler(args, palette))
    except ToolError as error:
        print(f"{palette('error:', 'red', 'bold')} {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
