"""Unrun native208 stream tests using owned Unix socketpairs, never a gadget.

These exercise actual stream fragmentation and protocol state, rather than
mocking the MAC/handshake. Execute after the combined source gate settles.
"""
import errno
import hashlib
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_control_protocol import Context, Session
from native_serial_link import (BYTE_BUDGET, CLEANUP_DOMAIN, Framer, NativeLink,
  SECOND, cleanup_challenge)

KEY = b'\x01' * 32
BOOT = '11111111-2222-4333-8444-555555555555'
CONTEXT = Context('a' * 64, 'systemd', 'b' * 64, 'c' * 64)


class NativeSerialLinkTests(unittest.TestCase):
  def setUp(self):
    self.device, self.host = socket.socketpair()
    for endpoint in [self.device, self.host]:
      endpoint.setblocking(False)
      self.addCleanup(endpoint.close)
    self.timestamp = SECOND
    self.link = NativeLink(self.device.fileno(), CONTEXT, KEY, BOOT, 60 * SECOND,
                           clock=lambda: self.timestamp)
    self.peer = Session(CONTEXT, KEY, side='host')

  def flush(self):
    for _step in range(10000):
      if not self.link.wants_write: return
      self.link.drive_write()
    self.fail('Owned small frame failed to drain')

  def probe(self):
    self.host.sendall(self.peer.send('PROBE', {'challenge': 'd' * 64}))
    self.link.drive_read()

  def prepare_pong(self):
    self.probe()
    self.flush()
    hello = self.peer.receive(self.host.recv(8192))
    self.host.sendall(self.peer.send('ACK', {'hello_body_sha256': hello.body_sha256})
                     + self.peer.send('PING', {'challenge': 'e' * 64}))
    self.link.drive_read()

  def handshake(self):
    self.prepare_pong()
    self.flush()
    pong = self.peer.receive(self.host.recv(8192))
    self.assertEqual(pong.kind, 'PONG')
    self.assertTrue(self.link.ready)
    self.link.take_events()

  def test_unsigned_hints_do_not_consume_authenticated_sequences(self):
    self.link.tick(); self.flush()
    self.assertEqual(self.host.recv(8192), b'SNCR1 ' + b'a' * 64 + b'\n')
    self.assertEqual(self.link.session.sent_sequence, 0)
    self.timestamp += SECOND
    self.link.tick(); self.flush()
    self.assertEqual(self.host.recv(8192), b'SNCR1 ' + b'a' * 64 + b'\n')
    self.assertFalse(self.link.ready)
    self.probe(); self.flush()
    self.assertEqual(self.peer.receive(self.host.recv(8192)).kind, 'HELLO')
    self.timestamp += SECOND
    self.link.tick()
    self.assertFalse(self.link.wants_write)

  def test_actual_handshake_waits_for_complete_pong_transfer(self):
    self.prepare_pong()
    self.assertFalse(self.link.ready)
    self.assertEqual(self.link.take_events(), ())
    self.flush()
    self.assertEqual(self.peer.receive(self.host.recv(8192)).payload['challenge'], 'e' * 64)
    events = self.link.take_events()
    self.assertEqual([event.kind for event in events], ['ready', 'pong-transferred'])

  def test_streaming_probe_fragments_do_not_generate_partial_hello(self):
    frame = self.peer.send('PROBE', {'challenge': 'd' * 64})
    for start in range(0, len(frame) - 1, 7):
      stop = min(start + 7, len(frame) - 1)
      self.host.sendall(frame[start:stop])
      self.link.drive_read()
      self.assertFalse(self.link.wants_write)
    self.host.sendall(frame[-1:])
    self.link.drive_read()
    self.flush()
    self.assertEqual(self.peer.receive(self.host.recv(8192)).kind, 'HELLO')

  def test_positive_short_writes_only_advance_same_mac_frame_suffix(self):
    self.probe()
    frame = self.link.pending[0][0]
    write = os.write
    with patch('native_serial_link.os.write', side_effect=lambda fd, data: write(fd, data[:7])):
      self.link.drive_write()
      self.assertEqual(self.link.pending[0][1], 7)
      self.assertEqual(self.link.session.sent_sequence, 1)
      self.flush()
    received = self.host.recv(8192)
    self.assertEqual(received, frame)
    self.assertEqual(self.peer.receive(received).kind, 'HELLO')

  def test_unknown_partial_write_poisons_session_and_never_resends_prefix(self):
    self.probe()
    frame = self.link.pending[0][0]
    write = os.write
    def uncertain(fd, data):
      write(fd, data[:3])
      raise OSError(errno.EIO, 'uncertain prefix')
    with patch('native_serial_link.os.write', side_effect=uncertain):
      with self.assertRaises(OSError): self.link.drive_write()
    self.assertTrue(self.link.failed)
    self.assertEqual(self.host.recv(8192), frame[:3])
    with self.assertRaises(ValueError): self.link.drive_write()
    with self.assertRaises(BlockingIOError): self.host.recv(8192)

  def test_known_eagain_keeps_byte_cursor_and_original_sequence(self):
    self.probe()
    with patch('native_serial_link.os.write', side_effect=BlockingIOError(errno.EAGAIN, 'full')):
      self.link.drive_write()
    self.assertFalse(self.link.failed)
    self.assertEqual(self.link.pending[0][1], 0)
    self.assertEqual(self.link.session.sent_sequence, 1)
    self.flush()
    self.assertEqual(self.peer.receive(self.host.recv(8192)).kind, 'HELLO')

  def test_expiry_after_successful_write_does_not_mark_native_ready(self):
    self.prepare_pong()
    write = os.write
    def late(fd, data):
      count = write(fd, data)
      self.timestamp = 60 * SECOND
      return count
    with patch('native_serial_link.os.write', side_effect=late):
      with self.assertRaises(ValueError): self.link.drive_write()
    self.assertFalse(self.link.ready)
    self.assertTrue(self.link.failed)

  def test_signed_evidence_binds_exact_retained_frame_challenge(self):
    self.handshake()
    challenge = self.link.evidence({'kind': 'synthetic-no-effect'}, purpose='cleanup')
    self.flush()
    frame = self.host.recv(8192)
    self.assertEqual(self.peer.receive(frame).kind, 'EVIDENCE')
    self.assertEqual(challenge, hashlib.sha256(CLEANUP_DOMAIN + frame).hexdigest())
    self.assertEqual(challenge, cleanup_challenge(frame))
    self.assertEqual(self.link.take_events()[0].kind, 'evidence-transferred')
    self.host.sendall(self.peer.send('PING', {'challenge': challenge}))
    self.link.drive_read(); self.flush()
    self.assertEqual(self.peer.receive(self.host.recv(8192)).payload['challenge'], challenge)
    self.assertEqual(self.link.take_events()[0].challenge, challenge)

  def test_evidence_before_roundtrip_is_not_a_work_admission(self):
    with self.assertRaises(ValueError): self.link.evidence({'unsafe': True}, purpose='cleanup')
    self.assertTrue(self.link.failed)

  def test_bad_mac_cannot_generate_response_or_native_readiness(self):
    frame = self.peer.send('PROBE', {'challenge': 'd' * 64})
    tag = frame[-65:-1]
    replacement = b'0' if tag[:1] != b'0' else b'1'
    self.host.sendall(frame[:-65] + replacement + tag[1:] + b'\n')
    with self.assertRaises(ValueError): self.link.drive_read()
    self.assertTrue(self.link.failed)
    self.assertFalse(self.link.wants_write)

  def test_disconnect_and_partial_frame_deadline_discard_attempt(self):
    self.host.sendall(b'SNCP1 partial')
    self.link.drive_read()
    self.timestamp += 5 * SECOND
    with self.assertRaises(ValueError): self.link.tick()
    self.assertTrue(self.link.failed)

  def test_framer_rejects_bad_bytes_long_lines_and_receive_budget(self):
    for data in [b'\r', b'\x00', b'\xff']:
      with self.assertRaises(ValueError): Framer().feed(data, SECOND)
    framer = Framer()
    framer.bytes = BYTE_BUDGET
    with self.assertRaises(ValueError): framer.feed(b'x', SECOND)
    framer = Framer()
    for _chunk in range(8): framer.feed(b'x' * 8192, SECOND)
    with self.assertRaises(ValueError): framer.feed(b'x', SECOND)


if __name__ == '__main__':
  unittest.main()
