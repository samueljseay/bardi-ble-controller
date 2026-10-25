"""Offline behavioral checks of reference-derived semantics, not bulb behavior.

All key material and reports are synthetic. The reserve callback is an in-memory
stand-in, not evidence of durable storage. No device or account is accessed.
"""
import hashlib
import struct
import unittest

from activation_verification import aes_cbc
from info_probe_codec import reassemble
from legacy_demo_study import DemoError, DemoSession, write_payload


KEY = 'SYNTHk9q2w7e4r8t'
NONCE = bytes.fromhex('9351a706c82d')
SESSION_KEY = hashlib.md5(b'SYNTHk' + NONCE).digest()
IV = bytes.fromhex('714b09c6e8235afd048db26790ce31a5')
BASELINE = {
    20: bytes.fromhex('1401000101'),
    21: bytes.fromhex('1504000100'),
    22: bytes.fromhex('160200040000015b'),
    23: bytes.fromhex('170200040000032c'),
    24: bytes.fromhex('1803000c') + b'0035026902dd',
}
VALUES = {20: True, 21: 0, 22: 347, 23: 812, 24: '0035026902dd'}
GREEN = bytes.fromhex('1803000c') + b'007803e80064'
COLOR_MODE = bytes.fromhex('1504000101')
DEMO_PAYLOAD = bytes.fromhex('00000000011803000c') + b'007803e80064' + bytes.fromhex('1504000101')
RESTORE_PAYLOAD = bytes.fromhex('00000000021803000c') + b'0035026902dd'
RESTORE_MODE_PAYLOAD = bytes.fromhex('00000000031504000100')


def wire_crc(data):
    """Independent CRC-16/MODBUS, without the codec's CRC helper."""
    value = 0xffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xa001 if value & 1 else 0)
    return value


def envelope(payload, *, serial, ack=0, opcode=0x8006):
    # Literal wire layout: serial:u32, ack:u32, opcode:u16, length:u16,
    # payload, CRC:u16, zero padding. Mode 5 precedes the IV and ciphertext.
    body = struct.pack('>IIHH', serial, ack, opcode, len(payload)) + payload
    body += wire_crc(body).to_bytes(2, 'big')
    body += bytes(-len(body) % 16)
    return b'\x05' + IV + aes_cbc(body, SESSION_KEY, IV, encrypt=True)


def report(*, serial=71, sequence=0x10203040, points=None, needs_ack=True):
    points = BASELINE if points is None else points
    header = b'\x00' + sequence.to_bytes(4, 'big') + bytes([0 if needs_ack else 128, 0])
    return envelope(header + b''.join(points.values()), serial=serial)


def command_ack(*, serial=72, outer=20, inner=1, status=0, opcode=0x27, prefix=0):
    payload = bytes([prefix]) + inner.to_bytes(4, 'big') + bytes([status])
    return envelope(payload, serial=serial, ack=outer, opcode=opcode)


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.time = 100.0
        self.intents = []

    def session(self, reserve=None):
        if reserve is None:
            def reserve(kind, digest):
                self.intents.append((kind, digest))
                return True
        return DemoSession(KEY, NONCE, reserve, clock=lambda: self.time, next_serial=19)

    def ready(self, *, points=None, reserve=None):
        session = self.session(reserve)
        session.receive_report(report(points=points))
        return session

    def changed(self):
        points = dict(BASELINE)
        points.update({21: COLOR_MODE, 24: GREEN})
        return points

    def assert_wire(self, command, serial, opcode, ack, payload):
        self.assertEqual((command.serial, command.opcode, command.acknowledgement, command.payload),
                         (serial, opcode, ack, payload))
        packed = reassemble(command.packets(KEY, NONCE, IV))
        self.assertEqual(packed[:17], b'\x05' + IV)
        body = aes_cbc(packed[17:], SESSION_KEY, IV, encrypt=False)
        expected = struct.pack('>IIHH', serial, ack, opcode, len(payload)) + payload
        expected += wire_crc(expected).to_bytes(2, 'big')
        self.assertEqual(body, expected + bytes(-len(expected) % 16))

    def test_complete_observed_baseline_demo_and_restoration_on_the_wire(self):
        session = self.session()
        baseline_ack = session.receive_report(report())
        self.assert_wire(baseline_ack, 19, 0x8006, 71, bytes.fromhex('0010203040000000'))
        self.assertEqual(session.fresh_snapshot(), VALUES)
        demo = session.start_demo(reference_semantics_approved=True)
        self.assert_wire(demo, 20, 0x27, 0, DEMO_PAYLOAD)
        self.assertEqual(self.intents, [('demo', hashlib.sha256(DEMO_PAYLOAD).hexdigest())])
        session.receive_command_ack(command_ack())
        self.assertEqual(session.phase, 'demo_pending')
        self.time = 101.25
        session.receive_report(report(serial=73, sequence=0x10203041, points=self.changed()))
        self.assertEqual(session.phase, 'demo_confirmed')
        restore = session.start_restore()
        self.assert_wire(restore, 22, 0x27, 0, RESTORE_PAYLOAD)
        self.assertEqual(self.intents[-1], ('restore_color', hashlib.sha256(RESTORE_PAYLOAD).hexdigest()))
        # State arriving before its matching ACK must not confirm restoration.
        session.receive_report(report(serial=74, sequence=0x10203042, points=BASELINE | {21: COLOR_MODE}))
        self.assertEqual(session.phase, 'restore_color_pending')
        with self.assertRaises(DemoError):session.finish_restore()
        session.receive_command_ack(command_ack(serial=75, outer=22, inner=2))
        self.assertEqual(session.phase, 'restore_color_confirmed')
        mode=session.finish_restore()
        self.assert_wire(mode,24,0x27,0,RESTORE_MODE_PAYLOAD)
        with self.assertRaises(DemoError):session.finish_restore()
        session.receive_command_ack(command_ack(serial=76,outer=24,inner=3))
        self.assertEqual(session.phase,'restore_pending')
        session.receive_report(report(serial=77,sequence=0x10203043))
        self.assertEqual(session.phase, 'restore_confirmed')
        self.assertEqual(session.fresh_snapshot(), VALUES)
        with self.assertRaises(DemoError):
            session.start_demo(reference_semantics_approved=True)
        with self.assertRaises(DemoError):
            session.start_restore()

    def test_baseline_requires_all_five_fresh_observed_points_and_approval(self):
        session = self.session()
        with self.assertRaises(DemoError):
            session.start_demo(reference_semantics_approved=True)
        session.receive_report(report(points={k: v for k, v in BASELINE.items() if k != 23}))
        with self.assertRaises(DemoError):
            session.start_demo(reference_semantics_approved=True)
        session.receive_report(report(serial=72, sequence=0x10203041, points={23: BASELINE[23]}))
        self.assertEqual(session.fresh_snapshot(), VALUES)
        with self.assertRaises(DemoError):
            session.start_demo()
        self.time = 105.001
        with self.assertRaises(DemoError):
            session.start_demo(reference_semantics_approved=True)
        session.receive_report(report(serial=73, sequence=0x10203042))
        self.assertEqual(session.start_demo(reference_semantics_approved=True).payload, DEMO_PAYLOAD)
        for identifier, raw in ((20, bytes.fromhex('1401000100')),
                                (21, bytes.fromhex('1504000102')),
                                (21, bytes.fromhex('1504000103'))):
            with self.subTest(unsafe_baseline=raw.hex()):
                points = dict(BASELINE)
                points[identifier] = raw
                session = self.ready(points=points)
                with self.assertRaises(DemoError):
                    session.start_demo(reference_semantics_approved=True)

    def test_color_is_bounded_distinct_and_does_not_write_power_or_white_settings(self):
        cases = [
            (0, b'0035026902dd', b'007803e80064', True),
            (1, b'007803e8000a', b'00f003e8000a', False),
            (1, b'012c007b0039', b'007803e80039', False),
        ]
        for mode, old, expected, switches_mode in cases:
            with self.subTest(mode=mode, color=old):
                points = dict(BASELINE)
                points[21] = bytes.fromhex('1504000100')[:-1] + bytes([mode])
                points[24] = bytes.fromhex('1803000c') + old
                session = self.ready(points=points)
                command = session.start_demo(reference_semantics_approved=True)
                payload = bytes.fromhex('00000000011803000c') + expected
                if switches_mode:
                    payload += bytes.fromhex('1504000101')
                self.assertEqual(command.payload, payload)
                restored = bytes.fromhex('00000000021803000c') + old
                self.assertEqual(session.start_restore().payload, restored)
        for updates in ({20: False}, {22: 50}, {23: 0}, {21: 2}, {21: 3},
                        {24: '016903e80064'}, {24: '007803e90064'}, {24: '007803e80009'}):
            with self.subTest(updates=updates), self.assertRaises(DemoError):
                write_payload(1, updates)

    def test_wrong_ack_fields_are_rejected_without_confirming_reported_state(self):
        cases = [dict(outer=19), dict(inner=2), dict(opcode=0x8006), dict(prefix=1)]
        for fields in cases:
            with self.subTest(fields=fields):
                session = self.ready()
                session.start_demo(reference_semantics_approved=True)
                session.receive_report(report(serial=72, sequence=0x10203041, points=self.changed()))
                with self.assertRaises(DemoError):
                    session.receive_command_ack(command_ack(serial=73, **fields))
                self.assertEqual(session.phase, 'demo_pending')
                session.receive_command_ack(command_ack(serial=74))
                self.assertEqual(session.phase, 'demo_confirmed')

    def test_error_ack_cannot_be_overridden_by_later_success_and_report(self):
        session = self.ready()
        session.start_demo(reference_semantics_approved=True)
        with self.assertRaises(DemoError):
            session.receive_command_ack(command_ack(status=7))
        self.assertEqual(session.phase, 'blocked')
        # Another response serial is not permission to reinterpret a rejected write.
        try:
            session.receive_command_ack(command_ack(serial=73))
        except DemoError:
            pass
        try:
            session.receive_report(report(serial=74, sequence=0x10203041, points=self.changed()))
        except DemoError:
            pass
        self.assertEqual(session.phase, 'blocked')

    def test_changed_field_confirmation_does_not_claim_a_full_snapshot_recheck(self):
        # Firmware can report only written fields. Unwritten fields remain baseline evidence.
        baseline = dict(BASELINE)
        baseline[21] = COLOR_MODE
        for omitted in (20, 21, 22, 23):
            with self.subTest(omitted=omitted):
                session = self.ready(points=baseline)
                session.start_demo(reference_semantics_approved=True)
                session.receive_command_ack(command_ack())
                partial = {k: v for k, v in self.changed().items() if k != omitted}
                session.receive_report(report(serial=73, sequence=0x10203041, points=partial))
                self.assertEqual(session.phase, 'demo_confirmed')
                self.assertFalse(session.full_snapshot_rechecked())
                session.receive_report(report(serial=74, sequence=0x10203042, points=self.changed()))
                self.assertEqual(session.phase, 'demo_confirmed')
                self.assertTrue(session.full_snapshot_rechecked())

    def test_late_demo_ack_during_restoration_cannot_confirm_the_restore(self):
        session=self.ready()
        demo=session.start_demo(reference_semantics_approved=True)
        restore=session.start_restore()
        session.receive_command_ack(command_ack(outer=demo.serial))
        self.assertEqual(session.phase,'restore_color_pending')
        session.receive_report(report(serial=73,sequence=0x10203041,points=BASELINE | {21:COLOR_MODE}))
        self.assertEqual(session.phase,'restore_color_pending')
        session.receive_command_ack(command_ack(serial=74,outer=restore.serial,inner=2))
        self.assertEqual(session.phase,'restore_color_confirmed')

    def test_matching_write_state_with_changed_power_or_white_settings_is_not_confirmation(self):
        for identifier, raw in ((20, bytes.fromhex('1401000100')),
                                (22, bytes.fromhex('160200040000015c')),
                                (23, bytes.fromhex('170200040000032b'))):
            with self.subTest(identifier=identifier):
                session = self.ready()
                session.start_demo(reference_semantics_approved=True)
                session.receive_command_ack(command_ack())
                points = self.changed()
                points[identifier] = raw
                session.receive_report(report(serial=73, sequence=0x10203041, points=points))
                self.assertEqual(session.phase, 'demo_pending')
                session.receive_report(report(serial=74, sequence=0x10203042, points=self.changed()))
                self.assertEqual(session.phase, 'demo_confirmed')

    def test_replayed_reports_do_not_refresh_baseline_or_confirm_a_command(self):
        session = self.ready()
        self.time = 105.01
        session.receive_report(report())
        session.receive_report(report(serial=72))  # Same inner report, new outer serial.
        with self.assertRaises(DemoError):
            session.fresh_snapshot()
        session.receive_report(report(serial=73, sequence=0x10203041))
        command = session.start_demo(reference_semantics_approved=True)
        session.receive_command_ack(command_ack(serial=74, outer=command.serial))
        session.receive_report(report(serial=75, sequence=0x10203041))
        self.assertEqual(session.phase, 'demo_pending')
        session.receive_report(report(serial=76, sequence=0x10203042, points=self.changed()))
        self.assertEqual(session.phase, 'demo_confirmed')

    def test_old_and_conflicting_report_sequences_do_not_replace_observed_state(self):
        cases = [report(serial=70, sequence=0x10203041, points=self.changed()),
                 report(serial=72, sequence=0x1020303f, points=self.changed()),
                 report(serial=72, points=self.changed()),
                 report(serial=71, sequence=0x10203041, points=self.changed())]
        for bad in cases:
            with self.subTest(frame=bad.hex()):
                session = self.ready()
                with self.assertRaises(DemoError):
                    session.receive_report(bad)
                self.assertEqual(session.fresh_snapshot(), VALUES)

    def test_durable_intent_requires_literal_true_and_failure_cannot_retry_demo(self):
        for result in (False, None, 1, 'persisted'):
            with self.subTest(result=result):
                recorded = []

                def reserve(kind, digest):
                    recorded.append((kind, digest))
                    return result

                session = self.ready(reserve=reserve)
                with self.assertRaises(DemoError):
                    session.start_demo(reference_semantics_approved=True)
                self.assertEqual(recorded, [('demo', hashlib.sha256(DEMO_PAYLOAD).hexdigest())])
                self.assertEqual(session.phase, 'blocked')
                with self.assertRaises(DemoError):
                    session.start_demo(reference_semantics_approved=True)
        session = self.ready()
        session.start_demo(reference_semantics_approved=True)

        def failed_restore(kind, digest):
            raise OSError('synthetic storage failure')

        session.reserve = failed_restore
        with self.assertRaisesRegex(OSError, 'synthetic storage failure'):
            session.start_restore()
        self.assertEqual(session.phase, 'blocked')
        with self.assertRaises(DemoError):
            session.start_restore()

    def test_clock_rollback_rejects_confirmation_and_late_reports_do_not_confirm(self):
        session = self.ready()
        session.start_demo(reference_semantics_approved=True)
        self.time = 99.9
        with self.assertRaises(DemoError):
            session.receive_command_ack(command_ack())
        self.assertEqual(session.phase, 'demo_pending')
        self.time = 100
        session.receive_command_ack(command_ack())
        self.time = 108.001
        session.receive_report(report(serial=73, sequence=0x10203041, points=self.changed()))
        self.assertEqual(session.phase, 'demo_pending')
        # A restoration command remains available when demo state is uncertain.
        self.assertEqual(session.start_restore().payload, RESTORE_PAYLOAD)

    def test_report_budgets_bound_ack_generation_and_unique_outer_frames(self):
        session = self.session()
        for index in range(32):
            ack = session.receive_report(report())
            self.assertEqual((ack.serial, ack.opcode, ack.acknowledgement), (19 + index, 0x8006, 71))
        with self.assertRaisesRegex(DemoError, 'acknowledgement budget'):
            session.receive_report(report())
        # No-ACK reports do not spend that budget, but unique responses are bounded.
        session = self.session()
        for index in range(64):
            self.assertIsNone(session.receive_report(report(serial=71 + index,
                                                          sequence=0x10203040 + index,
                                                          needs_ack=False)))
        self.assertEqual(session.fresh_snapshot(), VALUES)
        with self.assertRaisesRegex(DemoError, 'session budget'):
            session.receive_report(report(serial=135, sequence=0x10203080, needs_ack=False))


if __name__ == '__main__':
    unittest.main()
