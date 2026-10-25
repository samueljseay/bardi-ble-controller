"""Read-only information query through a saved CoreBluetooth peripheral.

Bleak 3.0.2 represents CoreBluetooth device details as (peripheral, manager).
Cached lookup is not evidence that a device is currently present or bound.
"""
import asyncio
import hashlib
from activation_transport import _encrypted_request,information_fields,TransportError
from activation_store import validate_profile


def select_cached(peripherals,address):
    items=list(peripherals)
    if len(items)!=1 or str(items[0].identifier().UUIDString()).lower()!=address.lower():
        raise ValueError('Saved peripheral is absent or ambiguous in the CoreBluetooth cache')
    return items[0]


async def cached_device(target):
    from Foundation import NSUUID
    from bleak.backends.corebluetooth.CentralManagerDelegate import CentralManagerDelegate
    from bleak.backends.device import BLEDevice
    manager=CentralManagerDelegate()
    await asyncio.wait_for(manager.wait_until_ready(),15)
    address=target['peripheral_identifier']
    identifier=NSUUID.alloc().initWithUUIDString_(address)
    if identifier is None:raise ValueError('Invalid saved peripheral identifier')
    peripheral=select_cached(manager.central_manager.retrievePeripheralsWithIdentifiers_([identifier]),address)
    return BLEDevice(address=address,name=None,details=(peripheral,manager))


async def query_information(session,profile,*,boot_default=False):
    if session.stage!='new':raise TransportError('Information query requires a fresh connection')
    if type(boot_default) is not bool:raise ValueError('Key-source selection must be Boolean')
    validate_profile(profile)
    session.stage='legacy_information'
    prefix=bytes(6) if boot_default else profile['localKey'].encode('ascii')[:6]
    key=hashlib.md5(prefix).digest()
    await session._send(_encrypted_request(1,0,b'\0\x14',4,key))
    envelope,payload=await session._receive({4:key,0:None},opcode=0,ack=1,deadline=asyncio.get_running_loop().time()+12)
    if len(payload)<84 or payload[2:4]!=bytes([4,8]) or payload[5] not in (0,1):
        raise TransportError('Unsupported information response profile')
    session.temp=information_fields(payload)
    session.stage='legacy_information_complete'
    return {'protocol_version':'4.8','bound':bool(payload[5]),'cipher_mode':envelope[0],
            'key_source':'boot-default' if boot_default else 'generated',
            'local_key_prefix_verified':envelope[0]==4 and not boot_default,
            'reset_default_key_verified':envelope[0]==4 and boot_default,
            'complete_local_key_verified':False,'secret_key_verified':False,
            'assigned_trial_id_matches':payload[55:77]==profile['devId'].encode('ascii'),
            'fresh_nonce_present':bool(any(payload[6:12]))}


async def query_plain_information(session):
    from info_probe_codec import candidate_query
    if session.stage!='new':raise TransportError('Plain information requires a fresh connection')
    session.stage='plain_information'
    await session._send((candidate_query(),))
    envelope,payload=await session._receive({0:None},opcode=0,ack=1,deadline=asyncio.get_running_loop().time()+12)
    if len(payload)<84 or payload[2:4]!=bytes([4,8]) or payload[5] not in (0,1):
        raise TransportError('Unsupported plain information response profile')
    session.stage='plain_information_complete'
    return {'protocol_version':'4.8','bound':bool(payload[5]),'cipher_mode':envelope[0],
            'local_key_prefix_verified':False,'complete_local_key_verified':False,
            'virtual_id_present':bool(any(payload[55:77])),
            'fresh_nonce_present':bool(any(payload[6:12]))}
