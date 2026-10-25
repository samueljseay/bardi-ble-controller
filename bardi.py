"""Direct BLE controller for the verified Bardi P4.8 profile on macOS.

No app, account, Wi-Fi enrollment, supply control, or vendor network requests.
State is private and local. Setup is explicit and never retried automatically.
"""
import argparse
import asyncio
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import uuid

from activation_store import (check_private, create_trial, load_private, load_trial,
                              operator_lock, sync_directory, write_exclusive)
from activation_transport import BleSession, SERVICE, find_target
from activation_verification import aes_cbc
from cached_information import cached_device
from lighting_control import Color, Countdown, DoNotDisturb, Power, PowerOnMemory, Scene, White
from lighting_demo import run_demo


def candidate(device, advertisement):
    """Decode only the observed unbound profile, not arbitrary Tuya devices."""
    service = next((bytes(data) for name, data in advertisement.service_data.items()
                    if name.lower() in (SERVICE, 'fd50', '0000fd50')), b'')
    manufacturer = b'\xd0\x07' + bytes(advertisement.manufacturer_data.get(0x07d0, b''))
    if (len(service) != 20 or service[:2] != b'\x43\x04' or
            len(manufacturer) != 22 or manufacturer[:6] != bytes.fromhex('d00700000468')):
        return None
    key = hashlib.md5(service).digest()
    try:
        identity = aes_cbc(manufacturer[6:], key, key, encrypt=False).decode('ascii')
        uuid.UUID(device.address)
    except (UnicodeError, ValueError):
        return None
    if len(identity) != 16 or not identity.isalnum():
        return None
    return {'target': {'peripheral_identifier': device.address, 'factory_uuid': identity},
            'service': service.hex(), 'manufacturer': manufacturer.hex()}


async def discover(root):
    from bleak import BleakScanner
    candidates = {}

    def observe(device, advertisement):
        row = candidate(device, advertisement)
        if row is not None:
            candidates[device.address] = row

    async with BleakScanner(detection_callback=observe):
        await asyncio.sleep(15)
    rows = [candidates[address] for address in sorted(candidates)]
    write_exclusive(root / 'discovery.json', rows)
    return {'candidates': len(rows), 'connections': 0,
            'next': 'Select the known bulb with select --candidate NUMBER, starting at 1.'}


async def execute(root, action, *, control=None, persistent_approved=False, boot_default=False, client_factory=None):
    """Run a fresh recorded connection. Injected clients are for offline tests."""
    check_private(root, directory=True)
    if action == 'setup' and boot_default:
        raise ValueError('Boot-default selection is for reconnect, not setup')
    pending = root / 'pending-write.json'
    if action != 'status' and os.path.lexists(pending):
        raise ValueError('An earlier operation may have written. Inspect state before further controls.')
    if action == 'setup' and (root / 'enrollment').exists():
        raise ValueError('Setup is one-shot. Use status to check saved credentials, not another setup.')
    selected = load_private(root / 'target.json')
    target = selected['target']
    golden = {name: bytes.fromhex(selected[name]) for name in ('manufacturer', 'service')}
    run_root = root / 'runs'
    run_root.mkdir(mode=0o700, exist_ok=True)
    check_private(run_root, directory=True)
    directory = run_root / str(uuid.uuid4())
    directory.mkdir(mode=0o700)
    sync_directory(run_root)
    plan = None
    result = {'action': action, 'ok': False, 'optical_output_verified': False}
    session = None
    try:
        if action != 'status':
            write_exclusive(pending, {'action': action, 'run': directory.name,
                                      'automatic_retry_permitted': False})
        if action == 'setup':
            enrollment = root / 'enrollment'
            enrollment.mkdir(mode=0o700)
            plan = create_trial(enrollment, approved=True, target_reference=target)
            device = await find_target(target, golden, bound=False)
        else:
            enrollment = root / 'enrollment'
            reservation = load_private(enrollment / 'reservation.json')
            plan = enrollment / str(uuid.UUID(reservation['trial_id']))
            if load_trial(plan)['target'] != target:
                raise ValueError('Saved enrollment target does not match selected bulb')
            device = await cached_device(target)
        session = BleSession(device, target, client_factory=client_factory)
        async with session:
            if action == 'setup':
                await session.temporary_session()
                await session.lighting_start(directory, activation_directory=plan)
            else:
                profile = load_trial(plan)['profile']
                result['authentication'] = await session.legacy_reconnect(profile, boot_default=boot_default)
                await session.lighting_start(directory, reconnect_profile=profile)
            result['state'] = await session.lighting_read()
            if action == 'demo':
                result.update(await run_demo(session, directory))
                result['ok'] = bool(result.get('demo_reported_confirmed') and
                                    result.get('restore_reported_confirmed'))
            elif control is not None:
                outcome = await session.lighting_apply(control, persistent_approved=persistent_approved)
                result['outcome'] = asdict(outcome)
                result['outcome']['fresh_written_fields'] = sorted(outcome.fresh_written_fields)
                result['ok'] = outcome.status.value in ('reported_confirmed', 'already_observed')
            else:
                result['ok'] = True
            result['observed_points'] = {identifier: sample[0] for identifier, sample in session.lighting.observed.items()}
    except Exception as error:
        # Do not print arbitrary backend messages, which can contain identities.
        write_exclusive(directory / 'private-error.json', {'type': type(error).__name__, 'message': str(error)})
        result['error_type'] = type(error).__name__
        result['next'] = 'Inspect private state. Do not retry an uncertain write or rerun setup.'
    finally:
        if session is not None:
            await session.close()
            write_exclusive(directory / 'private-radio.json', {
                'stage': session.stage, 'writes': session.writes, 'write_acks': session.write_acks,
                'notifications': [packet.hex() for packet in session.raw],
                'disconnect_confirmed': session.disconnect_confirmed})
            result['disconnect_confirmed'] = session.disconnect_confirmed
            if not session.disconnect_confirmed:
                result['ok'] = False
        if plan is not None:
            result['configuration_may_have_committed'] = (plan / 'write-intent.json').exists()
        write_exclusive(directory / 'result.json', result)
        if result['ok'] and action != 'status':
            pending.unlink()
            sync_directory(root)
    return result


async def confirm_setup_access(root, *, boot_default=False, client_factory=None):
    """Reconcile only setup, using a new read-only credential/session check.

    This never retries configuration or clears an uncertain lighting command.
    It proves prefix-key access, not full-key acceptance or power persistence.
    """
    pending = load_private(root / 'pending-write.json')
    if pending.get('action') != 'setup':
        raise ValueError('Only a pending setup can be reconciled by this command')
    result = await execute(root, 'status', boot_default=boot_default, client_factory=client_factory)
    if result['ok']:
        write_exclusive(root / 'setup-access-confirmed.json', {
            'original_intent': pending, 'fresh_state': result['state'],
            'authentication': result['authentication'], 'configuration_repeated': False})
        (root / 'pending-write.json').unlink()
        sync_directory(root)
        result['setup_access_confirmed'] = True
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--state', type=Path, required=True, help='Private per-bulb directory, outside source')
    result.add_argument('--boot-default', action='store_true',
                        help='Explicitly use the verified post-power-restoration default login prefix, never reconfigure')
    commands = result.add_subparsers(dest='command', required=True)
    commands.add_parser('discover', help='Record unbound advertisements only, once per state directory')
    select = commands.add_parser('select', help='Select a known bulb from the saved discovery')
    select.add_argument('--candidate', type=int, required=True)
    setup = commands.add_parser('setup', help='Configure generated local credentials once, without cloud')
    setup.add_argument('--accept-local-configuration', action='store_true', required=True)
    for name in ('status', 'confirm-setup-access', 'demo', 'on', 'off'):
        commands.add_parser(name)
    white = commands.add_parser('white')
    white.add_argument('--brightness', type=int, required=True)
    white.add_argument('--temperature', type=int, required=True)
    color = commands.add_parser('color')
    color.add_argument('--hue', type=int, required=True)
    color.add_argument('--saturation', type=int, required=True)
    color.add_argument('--value', type=int, required=True)
    scene = commands.add_parser('scene', help='Bounded scene in the observed slot zero')
    scene.add_argument('--preset', choices=('cycle', 'default-white'), required=True)
    countdown = commands.add_parser('countdown', help='Toggle current power after a delay, or cancel with zero')
    countdown.add_argument('--seconds', type=int, required=True)
    memory = commands.add_parser('memory', help='Persistent power-on preference, not immediate output')
    modes = memory.add_mutually_exclusive_group(required=True)
    modes.add_argument('--initial', action='store_true')
    modes.add_argument('--remember', action='store_true')
    modes.add_argument('--white', nargs=2, type=int, metavar=('BRIGHTNESS', 'TEMPERATURE'))
    modes.add_argument('--color', nargs=3, type=int, metavar=('HUE', 'SATURATION', 'VALUE'))
    memory.add_argument('--accept-persistent-setting', action='store_true', required=True)
    dnd = commands.add_parser('dnd', help='Persistent do-not-disturb preference; changes power-return behavior')
    dnd.add_argument('--enabled', choices=('yes', 'no'), required=True)
    dnd.add_argument('--accept-persistent-setting', action='store_true', required=True)
    return result


def main():
    arguments = parser().parse_args()
    # Validate controls before opening a connection or allocating device state.
    control = None
    if arguments.command in ('on', 'off'):
        control = Power(arguments.command == 'on')
    elif arguments.command == 'white':
        control = White(arguments.brightness, arguments.temperature)
    elif arguments.command == 'color':
        control = Color(arguments.hue, arguments.saturation, arguments.value)
    elif arguments.command == 'scene':
        control = (Scene((Color(120, 1000, 100), Color(240, 1000, 100), Color(0, 1000, 100)))
                   if arguments.preset == 'cycle' else Scene((White(200, 0),), 'static', 14, 13))
    elif arguments.command == 'countdown':
        control = Countdown(arguments.seconds)
    elif arguments.command == 'memory':
        control = (PowerOnMemory('initial') if arguments.initial else PowerOnMemory('remember') if arguments.remember
                   else PowerOnMemory('custom', White(*arguments.white)) if arguments.white
                   else PowerOnMemory('custom', Color(*arguments.color)))
    elif arguments.command == 'dnd':
        control = DoNotDisturb(arguments.enabled == 'yes')
    root = arguments.state.expanduser().absolute()
    if arguments.command == 'discover':
        root.mkdir(mode=0o700)
    check_private(root, directory=True)
    if root.resolve() != root:
        raise ValueError('Private state path must not contain symlinks')
    with operator_lock(root):
        if arguments.command == 'select':
            rows = load_private(root / 'discovery.json')
            if not 1 <= arguments.candidate <= len(rows):
                raise ValueError('Candidate number is outside the saved discovery')
            write_exclusive(root / 'target.json', rows[arguments.candidate - 1])
            outcome = {'selected': arguments.candidate, 'device_writes': 0}
        elif arguments.command == 'discover':
            outcome = asyncio.run(discover(root))
        elif arguments.command == 'confirm-setup-access':
            outcome = asyncio.run(confirm_setup_access(root, boot_default=arguments.boot_default))
        else:
            outcome = asyncio.run(execute(root, arguments.command, control=control,
                                           boot_default=arguments.boot_default,
                                           persistent_approved=getattr(arguments, 'accept_persistent_setting', False)))
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome.get('ok', True) else 1


if __name__ == '__main__':
    raise SystemExit(main())
