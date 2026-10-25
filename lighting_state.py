"""Shared offline transaction state for one authenticated lighting connection.

No radio or storage operations occur here. The sole transport owner dispatches
frames and persists each command intent before sending the returned command.
"""
from dataclasses import dataclass, field
import hashlib
import math
import re
import struct
import time

from activation_transport import _decode
from activation_verification import aes_cbc
from info_probe_codec import crc16, fragment
from legacy_state_report import parse_report, report_ack_payload


class LightingError(ValueError):
    pass


def hsv(text):
    if not isinstance(text, str) or re.fullmatch('[0-9a-fA-F]{12}', text) is None:
        raise LightingError('Expected twelve hexadecimal color characters')
    h, s, v = (int(text[i:i + 4], 16) for i in (0, 4, 8))
    if not (0 <= h <= 360 and 0 <= s <= 1000 and 10 <= v <= 1000):
        raise LightingError('Color is outside the reference range')
    return h, s, v


def color_text(h, s, v):
    if any(type(x) is not int for x in (h, s, v)):
        raise LightingError('HSV values must be integers')
    text = f'{h:04x}{s:04x}{v:04x}'
    hsv(text)
    return text


def validate_point(identifier, kind, value):
    expected = {20: 1, 21: 4, 22: 2, 23: 2, 24: 3}
    if identifier not in expected or kind != expected[identifier]:
        raise LightingError('Datapoint type does not match the observed profile')
    if identifier == 20:
        if type(value) is not bool:
            raise LightingError('Invalid power value')
    elif identifier == 24:
        hsv(value)
    else:
        maximum = 3 if identifier == 21 else 1000
        minimum = 10 if identifier == 22 else 0
        if type(value) is not int or not minimum <= value <= maximum:
            raise LightingError('Invalid numeric datapoint')


@dataclass(frozen=True)
class Command:
    serial: int
    opcode: int
    acknowledgement: int
    payload: bytes = field(repr=False)

    def packets(self, local_key, nonce, iv):
        if not isinstance(local_key, str) or len(local_key) != 16 or not local_key.isascii():
            raise LightingError('Invalid local key shape')
        if not isinstance(nonce, bytes) or len(nonce) != 6 or not any(nonce):
            raise LightingError('Invalid session nonce')
        key = hashlib.md5(local_key.encode()[:6] + nonce).digest()
        body = struct.pack('>IIHH', self.serial, self.acknowledgement, self.opcode, len(self.payload)) + self.payload
        body += struct.pack('>H', crc16(body))
        body += bytes((-len(body)) % 16)
        return tuple(fragment(b'\x05' + iv + aes_cbc(body, key, iv, encrypt=True),
                              frame_sequence=(self.serial - 1) & 15))


class LightingState:
    """Serial allocation, replay checks, sparse observations and one pending write.

    Subclasses supply command policy, not a second receiver or state cache.
    Report confirmation never implies optical output or full-snapshot freshness.
    """

    response_limit = 64
    acknowledgement_limit = 32

    def __init__(self, local_key, nonce, reserve, *, clock=time.monotonic, next_serial=4):
        if (not isinstance(local_key, str) or len(local_key) != 16 or not local_key.isascii()
                or not isinstance(nonce, bytes) or len(nonce) != 6 or not any(nonce)):
            raise LightingError('Invalid session key material')
        if type(next_serial) is not int or not 1 <= next_serial <= 0xffffff00:
            raise LightingError('Invalid initial serial')
        self.key = hashlib.md5(local_key.encode()[:6] + nonce).digest()
        self.reserve = reserve
        self.clock = clock
        self.serial = next_serial
        self.phase = 'baseline'
        self.seen = {}
        self.inner = {}
        self.last_peer = 0
        self.last_report = -1
        self.points = {}
        self.observed = {}
        self.pending = None
        self.rejection_status = None
        self.ack_count = 0
        self.last_clock = None
        self.attempts = {}

    def now(self):
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(value)
                or (self.last_clock is not None and value < self.last_clock)):
            raise LightingError('Session clock moved backwards or became invalid')
        self.last_clock = value
        return value

    def command(self, opcode, ack, payload):
        value = Command(self.serial, opcode, ack, payload)
        self.serial += 1
        return value

    def decode(self, envelope):
        serial, ack, opcode, payload = _decode(envelope, {5: self.key})
        fingerprint = hashlib.sha256(struct.pack('>IIH', serial, ack, opcode) + payload).digest()
        if serial in self.seen:
            if self.seen[serial] != fingerprint:
                raise LightingError('Conflicting response replay')
            return serial, ack, opcode, payload, False
        if serial <= self.last_peer or len(self.seen) >= self.response_limit:
            raise LightingError('Response order or session budget exceeded')
        self.seen[serial] = fingerprint
        self.last_peer = serial
        return serial, ack, opcode, payload, True

    def receive_report(self, envelope):
        now = self.now()
        serial, ack, opcode, payload, new_outer = self.decode(envelope)
        if opcode != 0x8006 or ack != 0:
            raise LightingError('Expected an unsolicited datapoint report')
        report = parse_report(payload)
        sequence = report['report_sequence']
        digest = hashlib.sha256(payload).digest()
        new_inner = sequence not in self.inner
        if not new_inner and self.inner[sequence] != digest:
            raise LightingError('Conflicting report sequence')
        if new_inner:
            if sequence <= self.last_report:
                raise LightingError('Old report sequence')
            updates = []
            for point in report['points']:
                if point['id'] not in (20, 21, 22, 23, 24):
                    continue
                validate_point(point['id'], point['type'], point['value'])
                updates.append(point)
            if not new_outer:
                raise LightingError('Inconsistent duplicate report')
            self.inner[sequence] = digest
            self.last_report = sequence
            for point in report['points']:
                self.observed[point['id']] = (dict(point), now, sequence)
            for point in updates:
                self.points[point['id']] = (point['value'], now, sequence)
            self.check_confirmation()
        payload_ack = report_ack_payload(payload)
        if payload_ack is None:
            return None
        if self.ack_count >= self.acknowledgement_limit:
            raise LightingError('Report acknowledgement budget exceeded')
        self.ack_count += 1
        return self.command(0x8006, serial, payload_ack)

    def issue_payload(self, kind, updates, sequence, payload):
        if self.reserve(kind, hashlib.sha256(payload).hexdigest()) is not True:
            self.phase = 'blocked'
            raise LightingError('Durable command intent is not confirmed')
        command = self.command(0x27, 0, payload)
        self.attempts[command.serial] = sequence
        self.rejection_status = None
        self.pending = {'kind': kind, 'outer': command.serial, 'inner': sequence,
                        'updates': dict(updates), 'floor': self.last_report,
                        'ack': False, 'issued': self.now()}
        self.phase = kind + '_pending'
        return command

    def receive_command_ack(self, envelope):
        self.now()
        serial, ack, opcode, payload, new = self.decode(envelope)
        if not new:
            return
        p = self.pending
        if (opcode != 0x27 or ack not in self.attempts or len(payload) != 6
                or payload[0] != 0 or int.from_bytes(payload[1:5], 'big') != self.attempts[ack]):
            raise LightingError('Command acknowledgement does not match')
        if p is None or ack != p['outer']:
            return
        if payload[5] != 0:
            self.rejection_status = payload[5]
            self.pending = None
            self.phase = 'blocked'
            raise LightingError('Command returned an error; state remains uncertain')
        p['ack'] = True
        self.check_confirmation()

    def check_confirmation(self):
        p = self.pending
        if p is None or not p['ack'] or self.now() - p['issued'] > 8:
            return False
        for identifier, expected in p['updates'].items():
            observation = self.observed.get(identifier)
            value, sequence = (observation[0]['value'], observation[2]) if observation else (None, -1)
            if sequence <= p['floor']:
                return False
            if identifier == 24:
                if value is None or hsv(value) != hsv(expected):
                    return False
            elif value != expected:
                return False
        return True

    def full_snapshot_rechecked(self):
        p = self.pending
        return bool(p is not None and self.phase == p['kind'] + '_confirmed'
                    and all(self.points[identifier][2] > p['floor'] for identifier in (20, 21, 22, 23, 24)))
