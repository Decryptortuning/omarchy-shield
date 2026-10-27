"""SNCP1: pure authenticated observations and fixed host control messages.

There is no I/O, clock, random source, device access or execution dispatch here.
A MAC authenticates possession of a private attempt key; it is not measured-boot
attestation, writer eligibility, a recovery receipt or a deadline extension.

API:
  Context(session_id, phase, candidate, config_sha256, version=1) is frozen;
  phase is packages/layer/systemd and implies role 1/1/2 respectively.
  Session(context, key, side="host"|"native", boot_id=None) holds sequences.
  Native sessions require their actual boot UUID. A host may omit it and adopt
  ONLY an authenticated, context-matching native HELLO with sequence 1 bound to
  its previously sent PROBE challenge.
  send(kind, payload) returns one complete ASCII line and consumes a TX sequence
  only after validation. receive(line) verifies then commits RX state and returns
  a frozen Record, including body_sha256 for ACK binding. Rejected operations do
  not change session state. Instances are single-owner, not thread-safe.
  send() commits before transport delivery. A known positive write count may
  advance a byte cursor through ONLY the unsent suffix of that same immutable
  encoded line, in the same live transfer before the caller's deadline. This is
  one frame, not a new send() or a replay. An exception, uncertain count,
  transport loss or deadline with an incomplete frame discards the attempt and
  session. Never rewind, regenerate, restart a prefix or resend its frames.

Envelope fields are EXACTLY context, boot_id, direction, seq, kind, payload.
Context fields are EXACTLY version, session_id, phase, role, candidate,
config_sha256. The ONLY bootstrap is host PROBE sequence 1 using the reserved
zero UUID, native HELLO sequence 1 with its actual nonzero UUID, then host ACK
sequence 2 with that actual UUID. All later messages use the actual UUID.
Normal next messages are host PING sequence 3 and native PONG sequence 2;
callers require that round trip before any workload. Payloads are EXACTLY:
  host PROBE:   {challenge: lowercase 64-hex value}
  native HELLO: {kernel_release: "7.1.0-shield-bringup", boottime_ns: positive int,
                 probe_challenge: the verified PROBE challenge}
  host ACK:     {hello_body_sha256: lowercase 64-hex digest}
  host PING:    {challenge: lowercase 64-hex value, utc_ns: supported UTC int}
  native PONG: {challenge: the outstanding PING, boottime_ns: positive int}
  host ABORT:   {reason: one member of ABORT_REASONS}
  native EVIDENCE and RESULT: {observations: JSON object}
Only one PING may be outstanding. Observations have no protocol-level authority;
the consumer must apply its own allowlist, eligibility and deadline checks.

Canonical JSON uses sorted keys, no whitespace and ensure_ascii=True. Integers
have magnitude <= 2**63-1; floats, duplicate keys and surrogate code points are
forbidden. MAX_DEPTH counts the envelope as depth 1. MAX_ITEMS counts values
AND object keys across the envelope. Strings, including keys, are bounded.
Decoded objects become mapping proxies and arrays become tuples.

Wire: b"SNCP1 " + canonical standard base64(JSON) + b" " + lowercase HMAC
hex + b"\n". HMAC-SHA256 covers MAC_DOMAIN + the exact JSON bytes. Authentication
precedes JSON decoding. There is one current format, with no negotiation/fallback.

Transport callers must retain a key outside command lines/public receipts, cap
framing before buffering and transmit each returned immutable line exactly once.
Known positive short writes may continue only at the remaining-byte cursor;
reject incomplete final or uncertain transmission and discard the attempt and
session. Do not rewind/replay after transport loss. An API that throws after an
unknown transmitted prefix cannot resume that frame. This streaming rule does
not relax a separate caller contract requiring one atomic PIPE_BUF-sized write.
Encoding an ACK does not prove delivery; a matching authenticated PONG can prove
a round trip, but still grants no effects. Records may contain private evidence;
this module never logs them. Complete records alone never replace owned peer,
capsule/source binding, process status, health or caller-owned time checks.
The MAC does not encrypt observations; private evidence stays out of public logs.
An approved early-RAM to real-root transition must use two distinct externally
sealed contexts, session IDs and keys, with the root host session pinned to the
already verified boot UUID. This module exports no session resume/restore API;
it neither approves that transition nor renews a deadline.
"""

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from types import MappingProxyType


MAX_JSON_BYTES = 32 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_DEPTH = 12
MAX_ITEMS = 2048
MAX_STRING_CHARS = 4096
MAX_INTEGER = (1 << 63) - 1
MAC_DOMAIN = b"shield-native-control/SNCP1/v1\x00"
# Calendar policy, not an assertion that an authenticated HOST clock is correct.
UTC_MIN_NS = 1_577_836_800_000_000_000  # 2020-01-01 inclusive.
UTC_MAX_NS = 4_102_444_800_000_000_000  # 2100-01-01 exclusive.


def valid_utc_ns(value):
  return type(value) is int and UTC_MIN_NS <= value < UTC_MAX_NS
KERNEL_RELEASE = "7.1.0-shield-bringup"
ABORT_REASONS = frozenset({"operator", "deadline", "health", "protocol", "transport", "evidence"})

_ROLES = MappingProxyType({"packages": 1, "layer": 1, "systemd": 2})
_KINDS = MappingProxyType({
  "native": frozenset({"HELLO", "EVIDENCE", "PONG", "RESULT"}),
  "host": frozenset({"PROBE", "ACK", "PING", "ABORT"}),
})
_CONTEXT_FIELDS = frozenset({"version", "session_id", "phase", "role", "candidate", "config_sha256"})
_ENVELOPE_FIELDS = frozenset({"context", "boot_id", "direction", "seq", "kind", "payload"})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_FRAME = re.compile(rb"SNCP1 ([A-Za-z0-9+/]+={0,2}) ([0-9a-f]{64})\n\Z")
BOOTSTRAP_BOOT_ID = "00000000-0000-0000-0000-000000000000"


class ProtocolError(ValueError):
  """Invalid/unexpected current protocol input; no session state committed."""


def _need(condition, message):
  if not condition:
    raise ProtocolError(message)


def _hex(value):
  return type(value) is str and _HEX.fullmatch(value) is not None


def _positive(value):
  return type(value) is int and 1 <= value <= MAX_INTEGER


def _key(value):
  _need(type(value) is bytes and len(value) == 32 and any(value), "Expected a nonzero 32-byte key")
  return value


def _boot(value):
  _need(type(value) is str and _UUID.fullmatch(value) is not None and
    value != BOOTSTRAP_BOOT_ID, "Expected canonical nonzero boot UUID")
  return value


@dataclass(frozen=True, slots=True)
class Context:
  session_id: str
  phase: str
  candidate: str
  config_sha256: str
  version: int = 1

  def __post_init__(self):
    _need(type(self.version) is int and self.version == 1, "Wrong protocol version")
    _need(type(self.phase) is str and self.phase in _ROLES, "Wrong phase")
    _need(all(_hex(v) for v in [self.session_id, self.candidate, self.config_sha256]), "Wrong context digest")

  @property
  def role(self):
    return _ROLES[self.phase]

  def as_dict(self):
    return {"version": self.version, "session_id": self.session_id,
      "phase": self.phase, "role": self.role, "candidate": self.candidate,
      "config_sha256": self.config_sha256}


@dataclass(frozen=True, slots=True)
class Record:
  context: Context
  boot_id: str
  direction: str
  seq: int
  kind: str
  payload: MappingProxyType
  body_sha256: str


def _json_limits(value):
  pending = [(value, 1)]
  items = 0
  while pending:
    current, depth = pending.pop()
    items += 1
    _need(depth <= MAX_DEPTH and items <= MAX_ITEMS, "JSON complexity exceeds limit")
    kind = type(current)
    if current is None or kind is bool:
      continue
    if kind is int:
      _need(-MAX_INTEGER <= current <= MAX_INTEGER, "JSON integer exceeds limit")
    elif kind is str:
      _need(len(current) <= MAX_STRING_CHARS and
        not any(0xd800 <= ord(c) <= 0xdfff for c in current), "Invalid JSON string")
    elif kind is dict:
      _need(len(current) <= MAX_ITEMS, "JSON object exceeds limit")
      for key, child in current.items():
        _need(type(key) is str, "JSON keys must be strings")
        pending.append((key, depth + 1))
        pending.append((child, depth + 1))
    elif kind is list:
      _need(len(current) <= MAX_ITEMS, "JSON array exceeds limit")
      pending.extend((child, depth + 1) for child in current)
    else:
      raise ProtocolError("Unsupported JSON value")


def _canonical(value):
  _json_limits(value)
  try:
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"),
      ensure_ascii=True, allow_nan=False)
    parts, total = [], 0
    for chunk in encoder.iterencode(value):
      data = chunk.encode("ascii")
      total += len(data)
      _need(total <= MAX_JSON_BYTES, "JSON bytes exceed limit")
      parts.append(data)
    return b"".join(parts)
  except ProtocolError:
    raise
  except (ValueError, TypeError, RecursionError, UnicodeError):
    raise ProtocolError("Cannot encode bounded JSON") from None


def _pairs(pairs):
  result = {}
  for key, value in pairs:
    _need(key not in result, "Duplicate JSON key")
    result[key] = value
  return result


def _integer(text):
  _need(len(text.lstrip("-")) <= 19, "JSON integer exceeds limit")
  value = int(text)
  _need(-MAX_INTEGER <= value <= MAX_INTEGER, "JSON integer exceeds limit")
  return value


def _not_numeric(text):
  raise ProtocolError("Noninteger JSON number forbidden")


def _freeze(value):
  if type(value) is dict:
    return MappingProxyType({key: _freeze(child) for key, child in value.items()})
  if type(value) is list:
    return tuple(_freeze(child) for child in value)
  return value


def _payload(direction, kind, value):
  _need(type(direction) is str and direction in _KINDS and
    type(kind) is str and kind in _KINDS[direction], "Kind is not allowed for direction")
  _need(type(value) is dict, "Payload must be an object")
  fields = {
    "PROBE": {"challenge"},
    "HELLO": {"kernel_release", "boottime_ns", "probe_challenge"},
    "ACK": {"hello_body_sha256"}, "PING": {"challenge", "utc_ns"},
    "PONG": {"challenge", "boottime_ns"}, "ABORT": {"reason"},
    "EVIDENCE": {"observations"}, "RESULT": {"observations"},
  }
  _need(set(value) == fields[kind], "Wrong payload fields")
  if kind == "HELLO":
    _need(type(value["kernel_release"]) is str and
      value["kernel_release"] == KERNEL_RELEASE, "Wrong kernel release")
    _need(_hex(value["probe_challenge"]), "Wrong PROBE challenge")
  if kind in {"HELLO", "PONG"}:
    _need(_positive(value["boottime_ns"]), "Wrong boot timestamp")
  if kind == "PING":
    _need(valid_utc_ns(value["utc_ns"]), "Unsupported UTC timestamp")
  if kind == "ACK":
    _need(_hex(value["hello_body_sha256"]), "Wrong HELLO digest")
  if kind in {"PROBE", "PING", "PONG"}:
    _need(_hex(value["challenge"]), "Wrong challenge")
  if kind == "ABORT":
    _need(type(value["reason"]) is str and value["reason"] in ABORT_REASONS, "Wrong abort reason")
  if kind in {"EVIDENCE", "RESULT"}:
    _need(type(value["observations"]) is dict, "Observations must be an object")


def _record(value, body):
  _need(type(value) is dict and set(value) == _ENVELOPE_FIELDS, "Wrong envelope fields")
  context = value["context"]
  _need(type(context) is dict and set(context) == _CONTEXT_FIELDS, "Wrong context fields")
  _need(type(context["role"]) is int, "Wrong context role type")
  frozen = Context(context["session_id"], context["phase"], context["candidate"],
    context["config_sha256"], context["version"])
  _need(context["role"] == frozen.role, "Phase and role differ")
  _need(_positive(value["seq"]), "Wrong sequence")
  _payload(value["direction"], value["kind"], value["payload"])
  if value["kind"] == "PROBE":
    _need(value["direction"] == "host" and value["seq"] == 1 and
      value["boot_id"] == BOOTSTRAP_BOOT_ID, "Wrong bootstrap UUID or sequence")
  else:
    _boot(value["boot_id"])
  return Record(frozen, value["boot_id"], value["direction"], value["seq"],
    value["kind"], _freeze(value["payload"]), hashlib.sha256(body).hexdigest())


def _encode(key, envelope):
  body = _canonical(envelope)
  record = _record(envelope, body)
  tag = hmac.digest(key, MAC_DOMAIN + body, "sha256").hex().encode("ascii")
  line = b"SNCP1 " + base64.b64encode(body) + b" " + tag + b"\n"
  _need(len(line) <= MAX_LINE_BYTES, "Frame exceeds limit")
  return line, record


def _decode(key, line):
  _need(type(line) is bytes and 0 < len(line) <= MAX_LINE_BYTES, "Wrong frame bytes or length")
  match = _FRAME.fullmatch(line)
  _need(match is not None, "Wrong ASCII frame")
  encoded, tag = match.groups()
  try:
    body = base64.b64decode(encoded, validate=True)
  except (ValueError, binascii.Error):
    raise ProtocolError("Wrong base64 body") from None
  _need(base64.b64encode(body) == encoded and len(body) <= MAX_JSON_BYTES, "Noncanonical or oversized body")
  expected = hmac.digest(key, MAC_DOMAIN + body, "sha256")
  _need(hmac.compare_digest(expected, bytes.fromhex(tag.decode("ascii"))), "Authentication failed")
  # No JSON decoding happens before the constant-time MAC comparison above.
  try:
    value = json.loads(body.decode("ascii"), object_pairs_hook=_pairs,
      parse_int=_integer, parse_float=_not_numeric, parse_constant=_not_numeric)
  except ProtocolError:
    raise
  except (ValueError, TypeError, RecursionError, UnicodeError):
    raise ProtocolError("Invalid JSON") from None
  _need(_canonical(value) == body, "Noncanonical JSON")
  return _record(value, body)


class Session:
  """Single-owner protocol state; never an effect or transport authority."""

  __slots__ = ("_context", "_key", "_side", "_boot_id", "_sent", "_received",
    "_hello_hash", "_ack_sent", "_ack_received", "_challenge", "_probe")

  def __init__(self, context, key, *, side, boot_id=None):
    _need(type(context) is Context, "Expected frozen Context")
    _need(type(side) is str and side in _KINDS, "Wrong session side")
    _key(key)
    if boot_id is not None:
      _boot(boot_id)
    _need(side != "native" or boot_id is not None, "Native boot identity required")
    self._context, self._key, self._side = context, key, side
    self._boot_id = boot_id
    self._sent = self._received = 0
    self._hello_hash = self._challenge = self._probe = None
    self._ack_sent = self._ack_received = False

  def __repr__(self):
    return "<SNCP1 Session side=" + repr(self._side) + " key=<redacted>>"

  @property
  def context(self):
    return self._context

  @property
  def boot_id(self):
    return self._boot_id

  @property
  def sent_sequence(self):
    return self._sent

  @property
  def received_sequence(self):
    return self._received

  @property
  def hello_body_sha256(self):
    return self._hello_hash

  @property
  def probe_challenge(self):
    return self._probe

  def send(self, kind, payload):
    _need(type(kind) is str, "Kind must be a string")
    sequence = self._sent + 1
    boot_id = BOOTSTRAP_BOOT_ID if self._side == "host" and kind == "PROBE" else self._boot_id
    _need(boot_id is not None, "Boot identity is not established")
    line, record = _encode(self._key, {"context": self._context.as_dict(),
      "boot_id": boot_id, "direction": self._side, "seq": sequence,
      "kind": kind, "payload": payload})
    if self._side == "native":
      if sequence == 1:
        _need(kind == "HELLO" and self._probe is not None and
          payload["probe_challenge"] == self._probe, "HELLO must bind verified PROBE")
      else:
        _need(kind != "HELLO" and self._ack_received, "Verified ACK required")
      if kind == "PONG":
        _need(self._challenge is not None and payload["challenge"] == self._challenge, "PONG challenge differs")
    else:
      if sequence == 1:
        _need(kind == "PROBE", "Host must start with PROBE")
      elif sequence == 2:
        _need(kind == "ACK" and self._hello_hash is not None and
          payload["hello_body_sha256"] == self._hello_hash, "ACK must bind verified HELLO")
      else:
        _need(kind not in {"PROBE", "ACK"} and self._ack_sent, "Verified HELLO/ACK required")
      if kind == "PING":
        _need(self._challenge is None, "PING is already outstanding")
    # Commit only after the complete frame/schema/handshake has validated.
    self._sent = sequence
    if kind == "PROBE": self._probe = payload["challenge"]
    if kind == "HELLO": self._hello_hash = record.body_sha256
    if kind == "ACK": self._ack_sent = True
    if kind == "PING": self._challenge = payload["challenge"]
    if kind == "PONG": self._challenge = None
    return line

  def receive(self, line):
    record = _decode(self._key, line)
    _need(record.context == self._context, "Context differs")
    _need(record.direction != self._side, "Reflected direction")
    _need(record.seq == self._received + 1, "Sequence gap or replay")
    bootstrap = self._side == "native" and record.kind == "PROBE" and record.seq == 1
    if bootstrap:
      _need(record.boot_id == BOOTSTRAP_BOOT_ID, "Wrong bootstrap UUID")
    elif self._boot_id is None:
      _need(self._side == "host" and record.kind == "HELLO" and record.seq == 1,
        "Only first native HELLO may establish boot identity")
    else:
      _need(record.boot_id == self._boot_id, "Boot identity differs")
    if self._side == "host":
      if record.seq == 1:
        _need(record.kind == "HELLO" and self._probe is not None and
          record.payload["probe_challenge"] == self._probe, "HELLO does not bind sent PROBE")
      else:
        _need(record.kind != "HELLO" and self._ack_sent, "ACK must precede native observations")
      if record.kind == "PONG":
        _need(self._challenge is not None and record.payload["challenge"] == self._challenge,
          "Unexpected PONG challenge")
    else:
      if record.seq == 1:
        _need(record.kind == "PROBE", "First host message must be PROBE")
      elif record.seq == 2:
        _need(record.kind == "ACK" and self._hello_hash is not None and
          record.payload["hello_body_sha256"] == self._hello_hash, "ACK does not bind HELLO")
      else:
        _need(record.kind not in {"PROBE", "ACK"} and self._ack_received, "Verified ACK required")
      if record.kind == "PING":
        _need(self._challenge is None, "PING is already outstanding")
    self._received = record.seq
    if self._boot_id is None: self._boot_id = record.boot_id
    if record.kind == "PROBE": self._probe = record.payload["challenge"]
    if record.kind == "HELLO": self._hello_hash = record.body_sha256
    if record.kind == "ACK": self._ack_received = True
    if record.kind == "PING": self._challenge = record.payload["challenge"]
    if record.kind == "PONG": self._challenge = None
    return record
