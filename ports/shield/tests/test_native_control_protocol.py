"""Pure SNCP1 adversarial fixtures; no device, process or transport actions.

All keys, digests and UUIDs here are synthetic test constants. Run only after
the complete native208 producer/consumer source review gate has settled.
"""
import base64
from dataclasses import FrozenInstanceError, replace
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import native_control_protocol as protocol


KEY = b"\x01" * 32
BOOT = "11111111-2222-4333-8444-555555555555"
OTHER_BOOT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CHALLENGE = "c" * 64
PROBE_CHALLENGE = "e" * 64


def context():
  return protocol.Context("a" * 64, "packages", "b" * 64, "d" * 64)


def envelope(*, direction="native", seq=1, kind="HELLO", payload=None,
             boot=BOOT, ctx=None):
  if payload is None:
    payload = {"kernel_release": protocol.KERNEL_RELEASE, "boottime_ns": 1,
      "probe_challenge": PROBE_CHALLENGE}
  return {"context": (ctx or context()).as_dict(), "boot_id": boot,
    "direction": direction, "seq": seq, "kind": kind, "payload": payload}


def signed_bytes(body, key=KEY):
  """Deliberately forge authenticated malformed input without the producer API."""
  tag = hmac.digest(key, protocol.MAC_DOMAIN + body, "sha256").hex().encode()
  return b"SNCP1 " + base64.b64encode(body) + b" " + tag + b"\n"


def signed(value):
  return signed_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"),
    ensure_ascii=True).encode("ascii"))


def probing_host():
  host = protocol.Session(context(), KEY, side="host")
  host.send("PROBE", {"challenge": PROBE_CHALLENGE})
  return host


def pair():
  native = protocol.Session(context(), KEY, side="native", boot_id=BOOT)
  host = protocol.Session(context(), KEY, side="host")
  native.receive(host.send("PROBE", {"challenge": PROBE_CHALLENGE}))
  hello = native.send("HELLO", {"kernel_release": protocol.KERNEL_RELEASE,
    "boottime_ns": 1, "probe_challenge": PROBE_CHALLENGE})
  observed = host.receive(hello)
  native.receive(host.send("ACK", {"hello_body_sha256": observed.body_sha256}))
  return native, host


class NativeControlProtocolTests(unittest.TestCase):
  def test_handshake_derives_role_and_binds_hello_body(self):
    native, host = pair()
    self.assertEqual(host.boot_id, BOOT)
    self.assertEqual(host.hello_body_sha256, native.hello_body_sha256)
    body = json.dumps(envelope(), sort_keys=True, separators=(",", ":")).encode()
    self.assertEqual(host.hello_body_sha256, hashlib.sha256(body).hexdigest())
    self.assertEqual((host.sent_sequence, host.received_sequence), (2, 1))
    self.assertEqual((native.sent_sequence, native.received_sequence), (1, 2))
    for phase, role in [("packages", 1), ("layer", 1), ("systemd", 2)]:
      self.assertEqual(replace(context(), phase=phase).role, role)
    with self.assertRaises(FrozenInstanceError):
      host.context.phase = "systemd"

  def test_records_and_all_nested_observations_are_immutable(self):
    native, host = pair()
    record = host.receive(native.send("EVIDENCE", {"observations": {
      "array": [{"health": True}, None, 3], "text": "\U0001f600"}}))
    with self.assertRaises(FrozenInstanceError): record.kind = "RESULT"
    with self.assertRaises(TypeError): record.payload["other"] = True
    observations = record.payload["observations"]
    self.assertIsInstance(observations["array"], tuple)
    with self.assertRaises(TypeError): observations["array"][0]["health"] = False
    self.assertEqual(observations["text"], "\U0001f600")

  def test_bad_mac_is_rejected_before_json_decoding_or_boot_adoption(self):
    host = probing_host()
    frame = signed(envelope())
    bad = frame[:-65] + (b"0" if frame[-65:-64] != b"0" else b"1") + frame[-64:]
    with patch.object(protocol.json, "loads", side_effect=AssertionError("JSON parsed before MAC")) as loads:
      with self.assertRaises(protocol.ProtocolError): host.receive(bad)
      loads.assert_not_called()
    self.assertIsNone(host.boot_id)
    self.assertEqual(host.received_sequence, 0)

  def test_body_tampering_and_wrong_key_fail(self):
    host = probing_host()
    frame = signed(envelope())
    fields = frame.split(b" ")
    body = base64.b64decode(fields[1]).replace(b'"boottime_ns":1', b'"boottime_ns":2')
    bad = fields[0] + b" " + base64.b64encode(body) + b" " + fields[2]
    with self.assertRaises(protocol.ProtocolError): host.receive(bad)
    with self.assertRaises(protocol.ProtocolError):
      host.receive(signed_bytes(json.dumps(envelope(), sort_keys=True,
        separators=(",", ":")).encode(), b"\x02" * 32))
    self.assertEqual(host.received_sequence, 0)

  def test_reflection_replay_and_sequence_gaps_do_not_commit(self):
    native, host = pair()
    abort = host.send("ABORT", {"reason": "operator"})
    with self.assertRaises(protocol.ProtocolError): host.receive(abort)
    self.assertEqual(host.received_sequence, 1)
    message = native.send("EVIDENCE", {"observations": {"counter": 1}})
    with self.assertRaises(protocol.ProtocolError): native.receive(message)
    host.receive(message)
    with self.assertRaises(protocol.ProtocolError): host.receive(message)
    with self.assertRaises(protocol.ProtocolError):
      host.receive(signed(envelope(seq=4, kind="RESULT", payload={"observations": {}})))
    self.assertEqual(host.received_sequence, 2)

  def test_wrong_boot_and_context_leave_same_sequence_available(self):
    native, host = pair()
    good = envelope(seq=2, kind="EVIDENCE", payload={"observations": {}})
    for field, value in [("phase", "layer"), ("session_id", "e" * 64),
                         ("candidate", "e" * 64), ("config_sha256", "e" * 64)]:
      wrong = envelope(seq=2, kind="EVIDENCE", payload={"observations": {}},
        ctx=replace(context(), **{field: value}))
      with self.assertRaises(protocol.ProtocolError): host.receive(signed(wrong))
    wrong = {**good, "boot_id": OTHER_BOOT}
    with self.assertRaises(protocol.ProtocolError): host.receive(signed(wrong))
    self.assertEqual(host.received_sequence, 1)
    host.receive(signed(good))
    self.assertEqual(host.received_sequence, 2)

  def test_unknown_boot_only_adopts_a_valid_first_native_hello(self):
    host = probing_host()
    for value in [envelope(seq=2), envelope(kind="EVIDENCE", payload={"observations": {}}),
                  envelope(boot=OTHER_BOOT.upper()),
                  envelope(payload={"kernel_release": "wrong", "boottime_ns": 1,
                    "probe_challenge": PROBE_CHALLENGE}),
                  envelope(payload={"kernel_release": protocol.KERNEL_RELEASE, "boottime_ns": 0,
                    "probe_challenge": PROBE_CHALLENGE}),
                  envelope(payload={"kernel_release": protocol.KERNEL_RELEASE, "boottime_ns": True,
                    "probe_challenge": PROBE_CHALLENGE})]:
      with self.assertRaises(protocol.ProtocolError): host.receive(signed(value))
      self.assertIsNone(host.boot_id)
      self.assertEqual(host.received_sequence, 0)
    host.receive(signed(envelope()))
    self.assertEqual(host.boot_id, BOOT)

  def test_hello_ack_order_and_hash_are_mandatory(self):
    native = protocol.Session(context(), KEY, side="native", boot_id=BOOT)
    host = protocol.Session(context(), KEY, side="host")
    with self.assertRaises(protocol.ProtocolError): native.send("RESULT", {"observations": {}})
    self.assertEqual(native.sent_sequence, 0)
    with self.assertRaises(protocol.ProtocolError): native.send("HELLO", envelope()["payload"])
    native.receive(host.send("PROBE", {"challenge": PROBE_CHALLENGE}))
    hello = native.send("HELLO", envelope()["payload"])
    with self.assertRaises(protocol.ProtocolError): native.send("EVIDENCE", {"observations": {}})
    host.receive(hello)
    with self.assertRaises(protocol.ProtocolError): host.send("PING", {"challenge": CHALLENGE})
    with self.assertRaises(protocol.ProtocolError):
      native.receive(signed(envelope(direction="host", seq=2, kind="ACK", payload={"hello_body_sha256": "f" * 64})))
    self.assertEqual(native.received_sequence, 1)
    native.receive(host.send("ACK", {"hello_body_sha256": host.hello_body_sha256}))
    self.assertEqual(native.received_sequence, 2)

  def test_ping_pong_matches_outstanding_challenge(self):
    native, host = pair()
    native.receive(host.send("PING", {"challenge": CHALLENGE}))
    self.assertEqual(host.sent_sequence, 3)
    with self.assertRaises(protocol.ProtocolError): host.send("PING", {"challenge": "e" * 64})
    with self.assertRaises(protocol.ProtocolError): native.send("PONG", {"challenge": "e" * 64, "boottime_ns": 2})
    wrong = envelope(seq=2, kind="PONG", payload={"challenge": "e" * 64, "boottime_ns": 2})
    with self.assertRaises(protocol.ProtocolError): host.receive(signed(wrong))
    self.assertEqual(host.received_sequence, 1)
    host.receive(native.send("PONG", {"challenge": CHALLENGE, "boottime_ns": 2}))
    self.assertEqual(native.sent_sequence, 2)
    native.receive(host.send("PING", {"challenge": "e" * 64}))
    host.receive(native.send("PONG", {"challenge": "e" * 64, "boottime_ns": 3}))
    self.assertEqual(host.received_sequence, 3)

  def test_unsolicited_pong_and_unqualified_ack_do_not_commit(self):
    native, host = pair()
    with self.assertRaises(protocol.ProtocolError):
      host.receive(signed(envelope(seq=2, kind="PONG", payload={"challenge": CHALLENGE, "boottime_ns": 2})))
    with self.assertRaises(protocol.ProtocolError):
      native.receive(signed(envelope(direction="host", seq=3, kind="ACK", payload={"hello_body_sha256": native.hello_body_sha256})))
    self.assertEqual((host.received_sequence, native.received_sequence), (1, 2))

  def test_duplicate_and_noncanonical_authenticated_json_are_rejected(self):
    host = probing_host()
    raw = json.dumps(envelope(), sort_keys=True, separators=(",", ":")).encode()
    duplicate = raw.replace(b'"seq":1', b'"seq":1,"seq":1')
    for body in [duplicate, json.dumps(envelope()).encode(), raw + b"\n",
                 raw.replace(b'"kind":"HELLO"', b'"kind":"H\\u0045LLO"')]:
      with self.assertRaises(protocol.ProtocolError): host.receive(signed_bytes(body))
    self.assertIsNone(host.boot_id)

  def test_floats_nonfinite_surrogates_and_bool_identifiers_are_rejected(self):
    host = probing_host()
    cases = [envelope(seq=True), envelope(seq=1.0)]
    for field, value in [("version", True), ("role", True), ("role", 2)]:
      item = envelope()
      item["context"][field] = value
      cases.append(item)
    for item in cases:
      with self.assertRaises(protocol.ProtocolError): host.receive(signed(item))
    native, host = pair()
    for value in [float("nan"), float("inf"), 1.25, "\ud800", "\udfff"]:
      item = envelope(seq=2, kind="EVIDENCE", payload={"observations": {"value": value}})
      with self.assertRaises(protocol.ProtocolError): host.receive(signed(item))
      with self.assertRaises(protocol.ProtocolError): native.send("EVIDENCE", item["payload"])
    self.assertEqual((host.received_sequence, native.sent_sequence), (1, 1))

  def test_host_cannot_send_effect_selectors_or_native_message_kinds(self):
    native, host = pair()
    for kind, payload in [("RUN", {"exec": "anything"}), ("RESULT", {"observations": {}}),
                          ("PING", {"challenge": CHALLENGE, "duration": 20}),
                          ("ABORT", {"reason": "operator", "path": "/anywhere"}),
                          ("ABORT", {"reason": "arbitrary text"})]:
      with self.assertRaises(protocol.ProtocolError): host.send(kind, payload)
      with self.assertRaises(protocol.ProtocolError):
        native.receive(signed(envelope(direction="host", seq=3, kind=kind, payload=payload)))
    self.assertEqual((host.sent_sequence, native.received_sequence), (2, 2))
    record = native.receive(host.send("ABORT", {"reason": "operator"}))
    self.assertEqual(record.payload["reason"], "operator")

  def test_unknown_fields_and_payload_types_are_rejected(self):
    host = probing_host()
    items = [{**envelope(), "extra": 0}, envelope(payload=[])]
    extra = envelope()
    extra["context"]["extra"] = 0
    items.append(extra)
    for item in items:
      with self.assertRaises(protocol.ProtocolError): host.receive(signed(item))
    native, host = pair()
    with self.assertRaises(protocol.ProtocolError): native.send("EVIDENCE", {"observations": []})

  def test_json_depth_item_string_and_integer_limits(self):
    native, host = pair()
    deep = "value"
    for _ in range(protocol.MAX_DEPTH): deep = [deep]
    bad_values = [deep, [0] * protocol.MAX_ITEMS,
      "x" * (protocol.MAX_STRING_CHARS + 1), protocol.MAX_INTEGER + 1,
      -protocol.MAX_INTEGER - 1, b"bytes", ("tuple",)]
    for value in bad_values:
      with self.assertRaises(protocol.ProtocolError):
        native.send("EVIDENCE", {"observations": {"value": value}})
    for value in bad_values[:5]:
      with self.assertRaises(protocol.ProtocolError):
        host.receive(signed(envelope(seq=2, kind="EVIDENCE",
          payload={"observations": {"value": value}})))
    self.assertEqual((native.sent_sequence, host.received_sequence), (1, 1))
    for value in [protocol.MAX_INTEGER, -protocol.MAX_INTEGER]:
      record = host.receive(native.send("EVIDENCE", {"observations": {"value": value}}))
      self.assertEqual(record.payload["observations"]["value"], value)

  def test_wire_limits_and_noncanonical_framing(self):
    host = probing_host()
    frame = signed(envelope())
    fields = frame.split(b" ")
    cases = [frame.replace(b"SNCP1 ", b"SNCP2 "), frame + b"\n",
      frame.replace(b"\n", b"\r\n"), b" " + frame,
      fields[0] + b" " + fields[1] + b"= " + fields[2],
      b"x" * (protocol.MAX_LINE_BYTES + 1),
      signed_bytes(b" " * (protocol.MAX_JSON_BYTES + 1))]
    for value in cases:
      with self.assertRaises(protocol.ProtocolError): host.receive(value)
    self.assertIsNone(host.boot_id)

  def test_raw_json_byte_limit_is_independent_of_individual_string_limit(self):
    native, host = pair()
    observations = {str(i): "x" * 4000 for i in range(9)}
    with self.assertRaises(protocol.ProtocolError): native.send("EVIDENCE", {"observations": observations})
    self.assertEqual(native.sent_sequence, 1)

  def test_context_key_boot_and_sequence_boundaries(self):
    for key in [b"\0" * 32, b"x" * 31, bytearray(KEY), "not bytes"]:
      with self.assertRaises(protocol.ProtocolError): protocol.Session(context(), key, side="host")
    with self.assertRaises(protocol.ProtocolError): protocol.Session(context(), KEY, side="native")
    for side in ["native", "host"]:
      with self.assertRaises(protocol.ProtocolError):
        protocol.Session(context(), KEY, side=side, boot_id=protocol.BOOTSTRAP_BOOT_ID)
    with self.assertRaises(protocol.ProtocolError): protocol.Session(context(), KEY, side="host", boot_id="not a UUID")
    with self.assertRaises(protocol.ProtocolError): replace(context(), version=True)
    with self.assertRaises(protocol.ProtocolError): replace(context(), phase="recovery")
    native, host = pair()
    for seq in [False, 0, -1, protocol.MAX_INTEGER + 1]:
      with self.assertRaises(protocol.ProtocolError):
        host.receive(signed(envelope(seq=seq, kind="RESULT", payload={"observations": {}})))
    self.assertNotIn(KEY.hex(), repr(native))

  def test_probe_is_host_first_zero_boot_only_and_cannot_be_reissued(self):
    host = protocol.Session(context(), KEY, side="host")
    native = protocol.Session(context(), KEY, side="native", boot_id=BOOT)
    with self.assertRaises(protocol.ProtocolError): host.receive(signed(envelope()))
    self.assertIsNone(host.boot_id)
    probe = host.send("PROBE", {"challenge": PROBE_CHALLENGE})
    self.assertIsNone(host.boot_id)
    record = native.receive(probe)
    self.assertEqual(record.boot_id, protocol.BOOTSTRAP_BOOT_ID)
    self.assertEqual(native.boot_id, BOOT)
    with self.assertRaises(protocol.ProtocolError): native.receive(probe)
    with self.assertRaises(protocol.ProtocolError): host.send("PROBE", {"challenge": PROBE_CHALLENGE})
    with self.assertRaises(protocol.ProtocolError): host.send("ABORT", {"reason": "operator"})
    self.assertEqual((host.sent_sequence, native.received_sequence), (1, 1))

  def test_probe_challenge_and_prebound_real_boot_must_match(self):
    host = probing_host()
    wrong = envelope(payload={**envelope()["payload"], "probe_challenge": "f" * 64})
    with self.assertRaises(protocol.ProtocolError): host.receive(signed(wrong))
    self.assertIsNone(host.boot_id)
    self.assertEqual(host.received_sequence, 0)
    host.receive(signed(envelope()))
    pinned = protocol.Session(context(), KEY, side="host", boot_id=OTHER_BOOT)
    pinned.send("PROBE", {"challenge": PROBE_CHALLENGE})
    with self.assertRaises(protocol.ProtocolError): pinned.receive(signed(envelope()))
    self.assertEqual(pinned.boot_id, OTHER_BOOT)
    self.assertEqual(pinned.received_sequence, 0)
    pinned.receive(signed(envelope(boot=OTHER_BOOT)))

  def test_zero_boot_is_forbidden_except_first_host_probe(self):
    native, host = pair()
    bad = [envelope(boot=protocol.BOOTSTRAP_BOOT_ID),
      envelope(seq=2, kind="RESULT", payload={"observations": {}}, boot=protocol.BOOTSTRAP_BOOT_ID)]
    for value in bad:
      with self.assertRaises(protocol.ProtocolError): host.receive(signed(value))
    for value in [envelope(direction="host", kind="PROBE", payload={"challenge": CHALLENGE}),
                  envelope(direction="host", seq=3, kind="PING", payload={"challenge": CHALLENGE},
                    boot=protocol.BOOTSTRAP_BOOT_ID)]:
      with self.assertRaises(protocol.ProtocolError): native.receive(signed(value))
    self.assertEqual((native.received_sequence, host.received_sequence), (2, 1))

  def test_probe_cannot_carry_effect_selectors(self):
    host = protocol.Session(context(), KEY, side="host")
    native = protocol.Session(context(), KEY, side="native", boot_id=BOOT)
    for selector in ["path", "exec", "duration", "phase"]:
      payload = {"challenge": PROBE_CHALLENGE, selector: "forbidden"}
      with self.assertRaises(protocol.ProtocolError): host.send("PROBE", payload)
      with self.assertRaises(protocol.ProtocolError):
        native.receive(signed(envelope(direction="host", kind="PROBE",
          boot=protocol.BOOTSTRAP_BOOT_ID, payload=payload)))
    self.assertEqual((host.sent_sequence, native.received_sequence), (0, 0))


if __name__ == "__main__":
  unittest.main()
