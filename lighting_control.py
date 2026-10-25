"""Typed lighting controls over the shared transaction model.

Constructing a control does not touch a device. Scene and countdown contracts
are capability-gated against fresh reports. Callers must explicitly authorize
persistent startup settings separately from the basic demo.
"""
from dataclasses import dataclass
from enum import Enum

from lighting_state import LightingError, LightingState, color_text, hsv, validate_point


@dataclass(frozen=True)
class Power:
    on: bool

    def __post_init__(self):
        validate_point(20, 1, self.on)


@dataclass(frozen=True)
class White:
    brightness: int
    temperature: int

    def __post_init__(self):
        validate_point(22, 2, self.brightness)
        validate_point(23, 2, self.temperature)


@dataclass(frozen=True)
class Color:
    hue: int
    saturation: int
    value: int

    def __post_init__(self):
        color_text(self.hue, self.saturation, self.value)


@dataclass(frozen=True)
class Scene:
    frames: tuple[White | Color, ...]
    transition: str = 'fade'
    time: int = 50
    speed: int = 50

    def __post_init__(self):
        if (type(self.frames) is not tuple or not 1 <= len(self.frames) <= 8
                or any(not isinstance(frame, (White, Color)) for frame in self.frames)):
            raise LightingError('Scenes require one to eight typed white or color frames')
        if self.transition not in ('static', 'jump', 'fade'):
            raise LightingError('Unknown scene transition')
        if (self.transition == 'static') != (len(self.frames) == 1):
            raise LightingError('Static scenes require one frame; dynamic scenes require at least two')
        if any(type(value) is not int or not 0 <= value <= 100 for value in (self.time, self.speed)):
            raise LightingError('Scene timing bytes must be integers from zero to 100')

    def text(self):
        result = '00'  # Preserve the observed scene slot. No arbitrary slot writes.
        transition = {'static': 0, 'jump': 1, 'fade': 2}[self.transition]
        for frame in self.frames:
            if isinstance(frame, White):
                channels = (0, 0, 0, frame.brightness, frame.temperature)
            else:
                channels = (frame.hue, frame.saturation, frame.value, 0, 0)
            result += f'{self.time:02x}{self.speed:02x}{transition:02x}'
            result += ''.join(f'{value:04x}' for value in channels)
        return result


@dataclass(frozen=True)
class Countdown:
    seconds: int

    def __post_init__(self):
        if type(self.seconds) is not int or not 0 <= self.seconds <= 86400:
            raise LightingError('Countdown must be integer seconds from zero to 86400; zero cancels')


@dataclass(frozen=True)
class PowerOnMemory:
    mode: str
    light: White | Color | None = None

    def __post_init__(self):
        if self.mode not in ('initial', 'remember', 'custom'):
            raise LightingError('Unknown power-on memory mode')
        if ((self.mode == 'custom' and not isinstance(self.light, (White, Color))) or
                (self.mode != 'custom' and self.light is not None)):
            raise LightingError('Only custom memory accepts a typed white or color target')


@dataclass(frozen=True)
class DoNotDisturb:
    enabled: bool

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise LightingError('Do-not-disturb requires a Boolean')


class Status(str, Enum):
    PENDING = 'pending'
    CONFIRMED = 'reported_confirmed'
    UNCHANGED = 'already_observed'
    REJECTED = 'rejected'
    UNCERTAIN = 'uncertain'


@dataclass(frozen=True)
class Outcome:
    status: Status
    command_acknowledged: bool
    fresh_written_fields: frozenset[int]
    full_snapshot_rechecked: bool
    rejection_status: int | None = None


def control_updates(control, *, memory_parameters=None):
    if isinstance(control, Power):
        return {20: control.on}
    if isinstance(control, White):
        return {22: control.brightness, 23: control.temperature, 21: 0}
    if isinstance(control, Color):
        return {24: color_text(control.hue, control.saturation, control.value), 21: 1}
    if isinstance(control, Scene):
        return {25: control.text(), 21: 2}
    if isinstance(control, Countdown):
        return {26: control.seconds}
    if isinstance(control, PowerOnMemory):
        if control.mode == 'custom':
            light = control.light
            channels = ((0, 0, 0, light.brightness, light.temperature) if isinstance(light, White)
                        else (light.hue, light.saturation, light.value, 0, 0))
            parameters = ''.join(f'{value:04x}' for value in channels)
        else:
            if not isinstance(memory_parameters, bytes) or len(memory_parameters) != 10:
                raise LightingError('Non-custom memory requires the current ten-byte parameter tail')
            parameters = memory_parameters.hex()
        return {33: '00' + {'initial': '00', 'remember': '01', 'custom': '02'}[control.mode] + parameters}
    if isinstance(control, DoNotDisturb):
        return {34: control.enabled}
    raise LightingError('Unsupported typed lighting control')


def control_payload(sequence, control, *, memory_parameters=None):
    return _encode_updates(sequence, control_updates(control, memory_parameters=memory_parameters))


def _encode_updates(sequence, updates):
    if type(sequence) is not int or not 1 <= sequence <= 0xffffffff:
        raise LightingError('Invalid command sequence')
    payload = b'\0' + sequence.to_bytes(4, 'big')
    # Stage stored targets before selecting their mode. Never combine a power
    # write with target/mode updates, which could also cancel a running timer.
    for identifier, value in updates.items():
        kind = {20: 1, 21: 4, 22: 2, 23: 2, 24: 3, 25: 3, 26: 2, 33: 0, 34: 1}[identifier]
        if identifier <= 24:
            validate_point(identifier, kind, value)
        if kind == 0:
            raw = bytes.fromhex(value)
        elif kind == 3:
            raw = value.encode('ascii')
        elif kind == 2:
            raw = value.to_bytes(4, 'big')
        else:
            raw = bytes([value])
        payload += bytes([identifier, kind]) + len(raw).to_bytes(2, 'big') + raw
    return payload


class ControlSession(LightingState):
    """One bounded connection's basic controls, without automatic write retries.

    The transport owns this state and supplies durable intent reservation.
    Call outcome after a send exception or timeout with uncertain=True. Once
    delivery is uncertain or rejected, the connection cannot issue more writes.
    """

    # Full state refreshes can contain seven sparse reports per query.
    response_limit = 256
    acknowledgement_limit = 128

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.next_sequence = 1
        self.last_updates = {}
        self.last_acknowledged = False
        self.uncertain = False

    def read(self, *, max_age=5):
        now = self.now()
        if type(max_age) not in (int, float) or not 0 <= max_age <= 5:
            raise LightingError('Snapshot age must be between zero and five seconds')
        if set(self.points) != {20, 21, 22, 23, 24}:
            raise LightingError('A complete current snapshot is required')
        if any(not 0 <= now - item[1] <= max_age for item in self.points.values()):
            raise LightingError('Baseline state is stale')
        return {identifier: item[0] for identifier, item in self.points.items()}

    def apply(self, control):
        if self.uncertain or self.phase == 'blocked':
            raise LightingError('Uncertain or rejected delivery blocks further writes')
        if self.pending is not None and self.outcome().status != Status.CONFIRMED:
            raise LightingError('The previous control is not confirmed')
        snapshot = self.read()
        memory_parameters = None
        if isinstance(control, PowerOnMemory):
            memory = self.observed.get(33)
            if memory is None or memory[0]['type'] != 0:
                raise LightingError('Power-on memory requires an observed version-zero record')
            raw = bytes.fromhex(memory[0]['value'])
            if len(raw) != 12 or raw[0] != 0 or raw[1] not in (0, 1, 2):
                raise LightingError('Unsupported power-on memory version or layout')
            memory_parameters = raw[2:]
        updates = control_updates(control, memory_parameters=memory_parameters)
        if not isinstance(control, (Power, Countdown, PowerOnMemory, DoNotDisturb)) and snapshot[20] is not True:
            raise LightingError('Turn power on separately before changing lighting mode')
        for identifier, kind in ((25, 3), (26, 2), (33, 0), (34, 1)):
            if identifier not in updates:
                continue
            observed = self.observed.get(identifier)
            if (observed is None or observed[0]['type'] != kind or
                    not 0 <= self.now() - observed[1] <= 5):
                raise LightingError('Optional control requires a fresh matching capability report')
            snapshot[identifier] = observed[0]['value']
        if isinstance(control, Countdown) and control.seconds and snapshot[26] != 0:
            raise LightingError('Cancel the existing countdown before starting another')
        if isinstance(control, Power):
            timer = self.observed.get(26)
            if (timer is None or not 0 <= self.now() - timer[1] <= 5
                    or timer[0]['type'] != 2 or timer[0]['value'] != 0):
                raise LightingError('Power requires a fresh zero countdown to avoid cancelling a timer')
        # The bulb echoes changed fields only. Do not resend an unchanged mode
        # and then wait for a report the peer has no reason to produce.
        updates = {identifier: value for identifier, value in updates.items()
                   if (hsv(snapshot[identifier]) != hsv(value) if identifier == 24
                       else snapshot[identifier] != value)}
        if not updates:
            return None
        payload = _encode_updates(self.next_sequence, updates)
        self.last_updates = updates
        self.last_acknowledged = False
        try:
            command = self.issue_payload('control', updates, self.next_sequence, payload)
        except BaseException:
            self.uncertain = True
            raise
        self.next_sequence += 1
        return command

    def check_confirmation(self):
        if self.uncertain or not super().check_confirmation():
            return False
        self.last_acknowledged = True
        self.phase = 'control_confirmed'
        return True

    def outcome(self, *, uncertain=False):
        if self.pending is not None:
            self.last_acknowledged = self.pending['ack']
            if self.phase != 'control_confirmed' and self.now() - self.pending['issued'] > 8:
                uncertain = True
        self.uncertain = self.uncertain or uncertain
        fresh = frozenset()
        if self.pending is not None:
            fresh = frozenset(identifier for identifier in self.last_updates
                              if identifier in self.observed
                              and self.observed[identifier][2] > self.pending['floor'])
        if self.rejection_status is not None:
            status = Status.REJECTED
        elif self.uncertain or self.phase == 'blocked':
            status = Status.UNCERTAIN
        elif self.phase == 'control_confirmed':
            status = Status.CONFIRMED
        else:
            status = Status.PENDING
        return Outcome(status, self.last_acknowledged, fresh,
                       status == Status.CONFIRMED and self.full_snapshot_rechecked(),
                       self.rejection_status)
