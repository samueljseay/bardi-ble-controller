"""Synthetic peers and independent wire fixtures. No reference binaries or radio.

AES uses the controller's macOS backend. CRC expectations are independent of
the production codec. Every identity and key in this file is synthetic.
"""
import hashlib
import struct
from types import SimpleNamespace

from activation_transport import Assembler, SERVICE, WRITE, NOTIFY
from activation_verification import aes_cbc
from info_probe_codec import fragment

TARGET = {'peripheral_identifier': '11111111-1111-4111-8111-111111111111',
          'factory_uuid': '0123456789ABCDEF'}
TRANSPORT_NONCE = b'ABCDEF'
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
COLOR_MODE = bytes.fromhex('1504000101')


def wire_crc(data):
    value = 0xffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xa001 if value & 1 else 0)
    return value


def envelope(payload, *, serial, ack=0, opcode=0x8006, mode=5, key=SESSION_KEY):
    body = struct.pack('>IIHH', serial, ack, opcode, len(payload)) + payload
    body += wire_crc(body).to_bytes(2, 'big')
    if mode == 0:
        return b'\0' + body
    body += bytes(-len(body) % 16)
    return bytes([mode]) + IV + aes_cbc(body, key, IV, encrypt=True)


def report(*, serial=71, sequence=0x10203040, points=None, needs_ack=True):
    points = BASELINE if points is None else points
    header = b'\0' + sequence.to_bytes(4, 'big') + bytes([0 if needs_ack else 128, 0])
    return envelope(header + b''.join(points.values()), serial=serial)


def command_ack(*, serial=72, outer=20, inner=1, status=0, opcode=0x27, prefix=0):
    return envelope(bytes([prefix]) + inner.to_bytes(4, 'big') + bytes([status]),
                    serial=serial, ack=outer, opcode=opcode)


def information(profile=None):
    data = bytearray(121)
    data[2:6] = bytes([4, 8, 37, 1 if profile else 0])
    data[6:12] = TRANSPORT_NONCE
    data[52:55] = bytes([0, 4, 6 if profile else 2])
    data[95] = 16
    data[114] = 2
    data[115:117] = bytes([3, 192])
    if profile:
        data[55:77] = profile['devId'].encode()
    return bytes(data)


class FakeClient:
    """GATT interface only. Subclasses implement the synthetic device behavior."""

    def __init__(self, device, *, profile=None, directory=None):
        self.device = device
        self.profile = profile
        self.directory = directory
        self.written = []
        self.commands = []
        self.assembler = Assembler()
        self.serial = 0
        self.is_connected = False
        self.callback = None
        self.services = self

    def get_service(self, uuid):
        return self if uuid == SERVICE else None

    def get_characteristic(self, uuid):
        if uuid == WRITE:
            return SimpleNamespace(properties=['write'])
        if uuid == NOTIFY:
            return SimpleNamespace(properties=['notify'])

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = False

    async def start_notify(self, uuid, callback):
        self.callback = callback

    def reply(self, opcode, ack, payload, mode=0, key=None):
        self.serial += 1
        frame = envelope(payload, serial=self.serial, ack=ack, opcode=opcode, mode=mode, key=key)
        for packet in fragment(frame):
            self.callback(None, packet)
