"""Typed controls through synthetic reports and literal expected wire payloads."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from activation_store import create_trial, load_private, load_trial, write_exclusive
from activation_transport import BleSession, _decode
from lighting_control import (Color, ControlSession, Countdown, DoNotDisturb, Power,
                              PowerOnMemory, Scene, Status, White, control_payload)
from lighting_state import LightingError
from lighting_test_support import (TARGET, FakeClient, TRANSPORT_NONCE, information,
                                   BASELINE, COLOR_MODE, KEY, NONCE, command_ack, report)


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.time = 100.0
        self.intents = []

    def ready(self, timer=0):
        def reserve(kind, digest):
            self.intents.append((kind, digest))
            return True
        session = ControlSession(KEY, NONCE, reserve, clock=lambda: self.time, next_serial=19)
        points = dict(BASELINE)
        if timer is not None:
            points[26] = bytes.fromhex('1a020004') + timer.to_bytes(4, 'big')
        session.receive_report(report(points=points))
        return session

    def test_typed_controls_encode_literal_asymmetric_values_and_stage_mode_last(self):
        self.assertEqual(control_payload(0x1020304, Power(False)),
                         bytes.fromhex('00010203041401000100'))
        self.assertEqual(control_payload(7, White(347, 812)),
                         bytes.fromhex('0000000007160200040000015b170200040000032c1504000100'))
        self.assertEqual(control_payload(9, Color(53, 617, 733)),
                         bytes.fromhex('00000000091803000c') + b'0035026902dd' + bytes.fromhex('1504000101'))
        for construct in (lambda: Power(1), lambda: White(True, 812), lambda: White(9, 0),
                          lambda: White(100, 1001), lambda: Color(361, 0, 100),
                          lambda: Color(120, 1001, 100), lambda: Color(120, 1000, 9)):
            with self.subTest(construct=construct), self.assertRaises(LightingError):
                construct()

    def test_matching_changed_fields_require_both_ack_and_new_reports(self):
        session = self.ready()
        command = session.apply(Color(120, 1000, 57))
        self.assertEqual(command.serial, 20)
        session.receive_command_ack(command_ack())
        self.assertEqual(session.outcome().status, Status.PENDING)
        session.receive_report(report(serial=73, sequence=0x10203041,
                                      points={21: COLOR_MODE, 24: bytes.fromhex('1803000c') + b'007803e80039'}))
        outcome = session.outcome()
        self.assertEqual(outcome.status, Status.CONFIRMED)
        self.assertTrue(outcome.command_acknowledged)
        self.assertEqual(outcome.fresh_written_fields, frozenset({21, 24}))
        self.assertFalse(outcome.full_snapshot_rechecked)
        # The real peer reports changed color but does not echo unchanged mode.
        next_command = session.apply(Color(240, 789, 83))
        self.assertEqual(next_command.payload, bytes.fromhex('00000000021803000c') + b'00f003150053')
        session.receive_report(report(serial=74, sequence=0x10203042,
                                      points={24: bytes.fromhex('1803000c') + b'00f003150053'}))
        session.receive_command_ack(command_ack(serial=75, outer=next_command.serial, inner=2))
        self.assertEqual(session.outcome().status, Status.CONFIRMED)

    def test_report_before_ack_confirms_white_and_full_snapshot_independently(self):
        session = self.ready()
        command = session.apply(White(123, 789))
        session.receive_report(report(serial=72, sequence=0x10203041, points={
            **BASELINE, 22: bytes.fromhex('160200040000007b'), 23: bytes.fromhex('1702000400000315')}))
        self.assertEqual(session.outcome().status, Status.PENDING)
        session.receive_command_ack(command_ack(serial=73, outer=command.serial))
        self.assertEqual(session.outcome().status, Status.CONFIRMED)
        self.assertTrue(session.outcome().full_snapshot_rechecked)

    def test_off_baseline_permits_power_but_not_implicit_on_or_timer_cancellation(self):
        for timer in (None, 123):
            session = self.ready(timer=timer)
            with self.subTest(timer=timer), self.assertRaisesRegex(LightingError, 'countdown'):
                session.apply(Power(False))
            self.assertEqual(self.intents, [])
        session = self.ready()
        session.receive_report(report(serial=72, sequence=0x10203041,
                                      points={20: bytes.fromhex('1401000100')}))
        with self.assertRaisesRegex(LightingError, 'power on separately'):
            session.apply(White(100, 500))
        command = session.apply(Power(True))
        self.assertEqual(command.payload, bytes.fromhex('00000000011401000101'))

    def test_uncertain_delivery_and_rejection_are_terminal_even_after_late_success(self):
        for rejected in (False, True):
            with self.subTest(rejected=rejected):
                session = self.ready()
                command = session.apply(Power(False))
                if rejected:
                    with self.assertRaises(LightingError):
                        session.receive_command_ack(command_ack(status=7))
                    self.assertEqual(session.outcome().status, Status.REJECTED)
                    self.assertEqual(session.outcome().rejection_status, 7)
                else:
                    self.time += 8.001
                    self.assertEqual(session.outcome().status, Status.UNCERTAIN)
                session.receive_command_ack(command_ack(serial=73, outer=command.serial))
                session.receive_report(report(serial=74, sequence=0x10203041,
                                              points={20: bytes.fromhex('1401000100')}))
                self.assertEqual(session.outcome().status, Status.REJECTED if rejected else Status.UNCERTAIN)
                with self.assertRaises(LightingError):
                    session.apply(Power(True))
                self.time = 100


    def test_optional_controls_have_literal_encodings_and_require_fresh_reports(self):
        self.assertEqual(control_payload(7, Countdown(86400)), bytes.fromhex('00000000071a02000400015180'))
        default_scene = Scene((White(200, 0),), 'static', 14, 13)
        self.assertEqual(default_scene.text(), '000e0d0000000000000000c80000')
        asymmetric = Scene((Color(53, 617, 733), White(123, 789)), 'fade', 37, 61)
        self.assertEqual(asymmetric.text(), '00253d020035026902dd00000000253d02000000000000007b0315')
        for invalid in (lambda: Countdown(True), lambda: Countdown(-1), lambda: Countdown(86401),
                        lambda: Scene((White(200, 0),)), lambda: Scene((Power(True),), 'static'),
                        lambda: Scene((White(200, 0),), 'static', 101)):
            with self.assertRaises(LightingError):
                invalid()
        session = self.ready()
        with self.assertRaisesRegex(LightingError, 'capability'):
            session.apply(default_scene)
        command = session.apply(Countdown(73))
        self.assertEqual(command.payload, bytes.fromhex('00000000011a02000400000049'))
        session.receive_command_ack(command_ack(outer=command.serial))
        self.assertEqual(session.outcome().status, Status.PENDING)
        session.receive_report(report(serial=73, sequence=0x10203041,
                                      points={26: bytes.fromhex('1a02000400000049')}))
        self.assertEqual(session.outcome().status, Status.CONFIRMED)
        self.assertEqual(session.outcome().fresh_written_fields, frozenset({26}))
        with self.assertRaisesRegex(LightingError, 'Cancel'):
            session.apply(Countdown(27))
        self.assertEqual(session.apply(Countdown(0)).payload, bytes.fromhex('00000000021a02000400000000'))

    def test_persistent_settings_encode_binary_memory_and_preserve_existing_parameters(self):
        self.assertEqual(control_payload(7, DoNotDisturb(True)), bytes.fromhex('00000000072201000101'))
        self.assertEqual(control_payload(9, PowerOnMemory('custom', White(123, 789))),
                         bytes.fromhex('00000000092100000c0002000000000000007b0315'))
        self.assertEqual(control_payload(9, PowerOnMemory('custom', Color(53, 617, 733))),
                         bytes.fromhex('00000000092100000c00020035026902dd00000000'))
        for invalid in (lambda: DoNotDisturb(1), lambda: PowerOnMemory('custom'),
                        lambda: PowerOnMemory('remember', White(123, 789))):
            with self.assertRaises(LightingError):
                invalid()
        session = self.ready()
        with self.assertRaisesRegex(LightingError, 'observed'):
            session.apply(PowerOnMemory('initial'))
        session.receive_report(report(serial=72, sequence=0x10203041, points={
            33: bytes.fromhex('2100000c00020035026902dd00000000')}))
        command = session.apply(PowerOnMemory('remember'))
        self.assertEqual(command.payload, bytes.fromhex('00000000012100000c00010035026902dd00000000'))
        session.receive_report(report(serial=73, sequence=0x10203042, points={
            33: bytes.fromhex('2100000c00010035026902dd00000000')}))
        self.assertEqual(session.outcome().status, Status.PENDING)
        session.receive_command_ack(command_ack(serial=74, outer=command.serial))
        self.assertEqual(session.outcome().status, Status.CONFIRMED)


class ControlLamp(FakeClient):
    """Synthetic peer that accepts only the basic lighting wire contract."""

    def __init__(self, *args, uncertain=False, boot_default=False, control_directory=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.boot_default = boot_default
        self.control_directory = control_directory or self.directory
        self.points = dict(BASELINE) | {26: bytes.fromhex('1a02000400000000')}
        self.report_sequence = 0
        self.uncertain = uncertain
        self.control_payloads = []

    def report(self, points):
        self.report_sequence += 1
        payload = b'\0' + self.report_sequence.to_bytes(4, 'big') + b'\0\0' + b''.join(points.values())
        self.reply(0x8006, 0, payload, 5, self.key)

    async def write_gatt_char(self, uuid, packet, response):
        self.written.append(packet)
        frame = self.assembler.add(packet)
        if frame is None:
            return
        temporary = hashlib.md5(bytes(16) + TRANSPORT_NONCE).digest()
        prefix = bytes(6) if self.boot_default else self.profile['localKey'].encode()[:6]
        self.key = hashlib.md5(prefix + TRANSPORT_NONCE).digest()
        information_key = hashlib.md5(prefix).digest()
        serial, ack, opcode, payload = _decode(frame, {0: None, 12: temporary, 5: self.key, 4: information_key})
        self.commands.append(opcode)
        if opcode == 0:
            info = bytearray(information(self.profile) if frame[0] == 4 else information())
            info[55:77] = bytes(22)  # Actual bulb retains zero ID despite working prefix-key access.
            self.reply(0, serial, bytes(info),
                       frame[0], information_key if frame[0] == 4 else None)
        elif opcode == 1:
            self.reply(1, serial, b'\0', frame[0], self.key if frame[0] == 5 else temporary)
        elif opcode == 27:
            assert (self.directory / 'write-intent.json').exists()
            self.reply(27, serial, b'\0', 2, bytes(16))
            self.report(self.points)
        elif opcode == 3:
            self.reply(3, serial, b'\0', 5, self.key)
            self.report(self.points)
        elif opcode == 0x8006:
            assert ack != 0 and len(payload) == 8
        elif opcode == 0x27:
            sequence = int.from_bytes(payload[1:5], 'big')
            assert (self.control_directory / f'control-{sequence:04d}-intent.json').exists()
            self.control_payloads.append(payload)
            offset = 5
            changed = {}
            while offset < len(payload):
                identifier = payload[offset]
                size = int.from_bytes(payload[offset + 2:offset + 4], 'big')
                changed[identifier] = payload[offset:offset + 4 + size]
                offset += 4 + size
            self.points.update(changed)
            if self.uncertain:
                raise OSError('synthetic uncertain delivery after updating peer state')
            self.reply(0x27, serial, b'\0' + payload[1:5] + b'\0', 5, self.key)
            self.report(changed)
        else:
            raise AssertionError(f'Unexpected opcode {opcode}')


class ControlTransportTests(unittest.IsolatedAsyncioTestCase):
    def prepare(self, **kwargs):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        directory = create_trial(root, approved=True, target_reference=TARGET)
        fake = ControlLamp(SimpleNamespace(address=TARGET['peripheral_identifier']),
                           profile=load_trial(directory)['profile'], directory=directory, **kwargs)
        session = BleSession(fake.device, TARGET, client_factory=lambda *args, **kw: fake)
        return directory, fake, session

    async def test_basic_demo_and_refresh_use_one_serial_allocator_and_durable_intents(self):
        directory, fake, session = self.prepare()
        async with session:
            await session.temporary_session()
            baseline = await session.lighting_start(directory, activation_directory=directory)
            self.assertEqual(baseline[22], 347)
            for control in (Color(120, 1000, 57), White(123, 789), Power(False), Power(True)):
                await session.lighting_read()
                outcome = await session.lighting_apply(control)
                self.assertEqual(outcome.status, Status.CONFIRMED)
                self.assertFalse(outcome.full_snapshot_rechecked)
            snapshot = await session.lighting_read()
            self.assertEqual(snapshot, {20: True, 21: 0, 22: 123, 23: 789, 24: '007803e80039'})
        self.assertTrue(session.disconnect_confirmed)
        self.assertEqual(fake.control_payloads, [
            bytes.fromhex('00000000011803000c') + b'007803e80039' + bytes.fromhex('1504000101'),
            bytes.fromhex('0000000002160200040000007b17020004000003151504000100'),
            bytes.fromhex('00000000031401000100'), bytes.fromhex('00000000041401000101'),
        ])
        self.assertEqual(len(list(directory.glob('control-*-intent.json'))), 4)

    async def test_fixed_recipe_restores_actual_baseline_without_claiming_optical_proof(self):
        from lighting_demo import run_demo
        directory, fake, session = self.prepare()
        original = dict(fake.points)
        async with session:
            await session.temporary_session()
            await session.lighting_start(directory, activation_directory=directory)
            result = await run_demo(session, directory, dwell_seconds=0)
        self.assertTrue(result['demo_reported_confirmed'])
        self.assertTrue(result['restore_reported_confirmed'])
        self.assertTrue(result['restore_full_snapshot_rechecked'])
        self.assertFalse(result['optical_output_verified'])
        self.assertEqual([step['step'] for step in result['steps']], [
            'green', 'blue', 'red', 'dim_red', 'warm_white', 'cool_white',
            'logical_off', 'logical_on', 'restore_saved_color', 'restore_white'])
        self.assertEqual(fake.points, original)
        self.assertLessEqual(session.writes, 512)

    async def test_partial_delivery_never_retries_or_issues_a_second_control(self):
        directory, fake, session = self.prepare(uncertain=True)
        async with session:
            await session.temporary_session()
            await session.lighting_start(directory, activation_directory=directory)
            with self.assertRaises(OSError):
                await session.lighting_apply(Color(120, 1000, 57))
            self.assertEqual(session.lighting.outcome().status, Status.UNCERTAIN)
            with self.assertRaises(LightingError):
                await session.lighting_apply(White(100, 500))
        self.assertEqual(len(fake.control_payloads), 1)
        self.assertTrue(session.disconnect_confirmed)

    async def test_already_observed_state_and_expired_connection_send_no_control(self):
        from activation_transport import TransportError
        directory, fake, session = self.prepare()
        async with session:
            await session.temporary_session()
            await session.lighting_start(directory, activation_directory=directory)
            outcome = await session.lighting_apply(White(347, 812))
            self.assertEqual(outcome.status, Status.UNCHANGED)
            self.assertFalse(outcome.command_acknowledged)
            with self.assertRaisesRegex(TransportError, 'approval'):
                await session.lighting_apply(DoNotDisturb(True))
            session.lighting_started -= 181
            before = len(fake.written)
            with self.assertRaises(TransportError):
                await session.lighting_apply(Color(120, 1000, 57))
            self.assertEqual(len(fake.written), before)
        self.assertEqual(fake.control_payloads, [])


class StandaloneTests(unittest.IsolatedAsyncioTestCase):
    def prepare(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        selected = {'target': TARGET, 'service': '4304' + '00' * 18,
                    'manufacturer': 'd00700000468' + '00' * 16}
        write_exclusive(root / 'target.json', selected)
        return root, SimpleNamespace(address=TARGET['peripheral_identifier'])

    async def test_standalone_setup_then_fresh_connection_status_without_reactivation(self):
        from bardi import execute, confirm_setup_access
        root, device = self.prepare()
        peers = []

        def factory(*args, **kwargs):
            enrollment = root / 'enrollment'
            plan = enrollment / load_private(enrollment / 'reservation.json')['trial_id']
            peer = ControlLamp(device, profile=load_trial(plan)['profile'], directory=plan)
            peers.append(peer)
            return peer

        with patch('bardi.find_target', AsyncMock(return_value=device)), patch('bardi.cached_device', AsyncMock(return_value=device)):
            setup = await execute(root, 'setup', client_factory=factory)
            self.assertTrue(setup['ok'], setup)
            self.assertTrue(setup['disconnect_confirmed'])
            self.assertIn(27, peers[0].commands)
            status = await execute(root, 'status', client_factory=factory)
            # Model a crash after setup delivery, not a new configuration attempt.
            write_exclusive(root / 'pending-write.json', {'action': 'setup', 'run': 'synthetic'})
            reconciled = await confirm_setup_access(root, client_factory=factory)
        self.assertTrue(status['ok'], status)
        self.assertFalse(status['authentication']['assigned_trial_id_matches'])
        self.assertFalse(status['authentication']['complete_local_key_verified'])
        self.assertEqual(status['state'], {20: True, 21: 0, 22: 347, 23: 812, 24: '0035026902dd'})
        self.assertNotIn(27, peers[1].commands)
        self.assertNotIn(27, peers[2].commands)
        self.assertTrue(reconciled['setup_access_confirmed'])
        self.assertFalse((root / 'pending-write.json').exists())

    async def test_boot_default_reconnect_controls_without_reconfiguring_or_replacing_saved_credentials(self):
        from bardi import execute
        root, device = self.prepare()
        peers = []
        booted = False

        def factory(*args, **kwargs):
            enrollment = root / 'enrollment'
            plan = enrollment / load_private(enrollment / 'reservation.json')['trial_id']
            active = next(run for run in (root / 'runs').iterdir() if not (run / 'result.json').exists())
            peer = ControlLamp(device, profile=load_trial(plan)['profile'], directory=plan,
                               control_directory=active, boot_default=booted)
            peers.append(peer)
            return peer

        with patch('bardi.find_target', AsyncMock(return_value=device)), patch('bardi.cached_device', AsyncMock(return_value=device)):
            self.assertTrue((await execute(root, 'setup', client_factory=factory))['ok'])
            saved = dict(peers[0].profile)
            booted = True
            result = await execute(root, 'color', control=Color(120, 1000, 57), boot_default=True, client_factory=factory)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['authentication']['reset_default_key_verified'])
        self.assertFalse(result['authentication']['local_key_prefix_verified'])
        self.assertEqual(result['authentication']['key_source'], 'boot-default')
        self.assertEqual(result['outcome']['status'], 'reported_confirmed')
        self.assertEqual(result['observed_points'][24]['value'], '007803e80039')
        self.assertEqual(peers[1].profile, saved)
        self.assertNotIn(27, peers[1].commands)

    async def test_failed_setup_blocks_new_writes_without_reconnecting(self):
        from bardi import execute
        root, _ = self.prepare()
        with patch('bardi.find_target', AsyncMock(side_effect=TimeoutError)) as find:
            result = await execute(root, 'setup')
            self.assertFalse(result['ok'])
            self.assertFalse(result['configuration_may_have_committed'])
            with self.assertRaisesRegex(ValueError, 'earlier operation'):
                await execute(root, 'demo')
        self.assertEqual(find.await_count, 1)

    async def test_discovery_decodes_synthetic_identity_and_rejects_bound_profile(self):
        from bardi import candidate
        from activation_verification import aes_cbc
        root, device = self.prepare()
        service = bytes.fromhex('4304') + bytes(range(18))
        key = hashlib.md5(service).digest()
        advertisement = SimpleNamespace(service_data={'fd50': service}, manufacturer_data={
            0x07d0: bytes.fromhex('00000468') + aes_cbc(TARGET['factory_uuid'].encode(), key, key, encrypt=True)})
        self.assertEqual(candidate(device, advertisement)['target'], TARGET)
        advertisement.service_data['fd50'] = bytes.fromhex('4b04') + service[2:]
        self.assertIsNone(candidate(device, advertisement))


if __name__ == '__main__':
    unittest.main()
