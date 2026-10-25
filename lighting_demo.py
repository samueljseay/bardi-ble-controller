"""Fixed basic-control demo, without app, cloud, activation or supply operations.

An initialized BleSession is the only device dependency. Optical observations
must be supplied separately; matching reports never set optical verification.
"""
import asyncio
from dataclasses import asdict

from activation_store import write_exclusive
from lighting_control import Color, Power, Status, White
from lighting_state import LightingError, hsv


RECIPE_VERSION = 1
RECIPE = (
    ('green', Color(120, 1000, 100)),
    ('blue', Color(240, 1000, 100)),
    ('red', Color(0, 1000, 100)),
    ('dim_red', Color(0, 1000, 30)),
    ('warm_white', White(100, 0)),
    ('cool_white', White(100, 1000)),
    ('logical_off', Power(False)),
    ('logical_on', Power(True)),
)


async def run_demo(session, directory, *, dwell_seconds=2):
    if type(dwell_seconds) not in (int, float) or not 0 <= dwell_seconds <= 5:
        raise LightingError('Demo dwell must be between zero and five seconds')
    baseline = await session.lighting_read()
    if baseline[20] is not True or baseline[21] != 0:
        raise LightingError('This bounded recipe requires an On, white-mode baseline')
    timer = session.lighting.observed.get(26)
    if timer is None or timer[0]['type'] != 2 or timer[0]['value'] != 0:
        raise LightingError('Demo requires an observed zero countdown')
    result = {'recipe_version': RECIPE_VERSION, 'baseline': baseline, 'steps': [],
              'restore_reported_confirmed': False, 'optical_output_verified': False}
    started = asyncio.get_running_loop().time()
    write_exclusive(directory / 'basic-demo-baseline.json', baseline)

    async def apply(name, control):
        await session.lighting_read()
        before = asyncio.get_running_loop().time() - started
        outcome = await session.lighting_apply(control)
        record = {'step': name, 'requested': asdict(control), 'started_seconds': before,
                  'confirmed_seconds': asyncio.get_running_loop().time() - started,
                  'status': outcome.status.value,
                  'command_acknowledged': outcome.command_acknowledged,
                  'fresh_written_fields': sorted(outcome.fresh_written_fields),
                  'full_snapshot_rechecked': outcome.full_snapshot_rechecked}
        write_exclusive(directory / f'basic-step-{len(result["steps"]) + 1:02d}.json', record)
        result['steps'].append(record)
        print(f'{name}: {outcome.status.value}', flush=True)
        if outcome.status not in (Status.CONFIRMED, Status.UNCHANGED):
            raise LightingError('Demo stopped without a confirmed control')

    try:
        for name, control in RECIPE:
            await apply(name, control)
            await asyncio.sleep(dwell_seconds)
        result['demo_reported_confirmed'] = True
    except Exception as error:
        result['error_type'] = type(error).__name__
        if isinstance(error, (ValueError, RuntimeError)):
            result['error_reason'] = str(error)
    finally:
        # This controller does not send more writes after uncertain delivery.
        # An outer research coordinator may separately perform verified reset
        # recovery, but that is not part of the finished app-free runtime.
        if session.lighting.pending is not None and not session.lighting.uncertain and session.lighting.phase != 'blocked':
            async def restore():
                current = await session.lighting_read()
                if current[20] is False:
                    await apply('restore_power', Power(True))
                await apply('restore_saved_color', Color(*hsv(baseline[24])))
                await apply('restore_white', White(baseline[22], baseline[23]))
                observed = await session.lighting_read()
                result['restore_reported_confirmed'] = observed == baseline
                result['restore_full_snapshot_rechecked'] = observed == baseline
            cleanup = asyncio.create_task(restore())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
                raise
            except Exception as error:
                result['restore_error_type'] = type(error).__name__
                if isinstance(error, (ValueError, RuntimeError)):
                    result['restore_error_reason'] = str(error)
        result['elapsed_seconds'] = asyncio.get_running_loop().time() - started
    return result
