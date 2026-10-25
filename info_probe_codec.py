# SPDX-License-Identifier: Apache-2.0
# Modified Python host implementation, not the upstream C runtime.
# Protocol reference copyright (C) 2014-2019 Tuya Inc. See NOTICES.md.
"""Offline-only codec for a candidate Tuya P4 device-information query.

This module has no Bluetooth, socket, or provisioning functions.
Response summaries omit device identifiers and registration material.
"""
import struct

MAX_FRAME = 4096


def crc16(data):
    value = 0xFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xA001 if value & 1 else 0)
    return value


def varint(value):
    if not 0 <= value < 0x10000000:
        raise ValueError("Transport integer out of range")
    out = bytearray()
    while True:
        digit = value & 0x7F
        value >>= 7
        out.append(digit | (0x80 if value else 0))
        if not value:
            return bytes(out)


def read_varint(data, offset):
    start = offset
    value = 0
    for shift in (0, 7, 14, 21):
        if offset >= len(data):
            raise ValueError("Truncated transport integer")
        digit = data[offset]
        offset += 1
        value |= (digit & 0x7F) << shift
        if not digit & 0x80:
            if data[start:offset] != varint(value):
                raise ValueError("Noncanonical transport integer")
            return value, offset
    raise ValueError("Transport integer exceeds four bytes")


def fragment(envelope, mtu=20, transport_version=2, frame_sequence=0):
    if not 15 <= len(envelope) <= MAX_FRAME or not 20 <= mtu <= 244:
        raise ValueError("Frame size or MTU out of range")
    if transport_version not in (2, 3, 4) or not 0 <= frame_sequence <= 15:
        raise ValueError("Unsupported transport version or sequence")
    packets = []
    offset = 0
    while offset < len(envelope):
        prefix = varint(len(packets))
        if not packets:
            prefix += varint(len(envelope)) + bytes([(transport_version << 4) | frame_sequence])
        take = min(mtu - len(prefix), len(envelope) - offset)
        packets.append(prefix + envelope[offset:offset + take])
        offset += take
    return packets


def candidate_query():
    # Command 0 is device information. The P4 payload is a two-byte data MTU.
    body = struct.pack(">IIHHH", 1, 0, 0, 2, 20)
    envelope = b"\0" + body + struct.pack(">H", crc16(body))
    packets = fragment(envelope)
    assert len(packets) == 1 and len(packets[0]) == 20
    return packets[0]


def reassemble(packets, mtu=20):
    if not packets or len(packets) > 256 or not 20 <= mtu <= 244:
        raise ValueError("Invalid packet count or MTU")
    assembled = bytearray()
    total = None
    for index, packet in enumerate(packets):
        if not packet or len(packet) > mtu:
            raise ValueError("Invalid GATT fragment length")
        number, offset = read_varint(packet, 0)
        if number != index:
            raise ValueError("Missing, duplicate, or out-of-order fragment")
        if index == 0:
            total, offset = read_varint(packet, offset)
            if not 15 <= total <= MAX_FRAME or offset >= len(packet):
                raise ValueError("Invalid frame header")
            if packet[offset] >> 4 not in (2, 3, 4):
                raise ValueError("Unsupported transport version")
            offset += 1
        if offset >= len(packet):
            raise ValueError("Empty fragment payload")
        assembled.extend(packet[offset:])
        if len(assembled) > total:
            raise ValueError("Frame contains excess data")
        if len(assembled) == total and index != len(packets) - 1:
            raise ValueError("Extra fragments after completion")
    if len(assembled) != total:
        raise ValueError("Incomplete frame")
    return bytes(assembled)


def parse_plaintext(envelope):
    if len(envelope) < 15 or len(envelope) > MAX_FRAME:
        raise ValueError("Invalid envelope size")
    if envelope[0] != 0:
        raise ValueError("Encrypted response: do not guess a key")
    body = envelope[1:-2]
    serial, ack, command, length = struct.unpack(">IIHH", body[:12])
    if length != len(body) - 12:
        raise ValueError("Payload length mismatch")
    if crc16(body) != int.from_bytes(envelope[-2:], "big"):
        raise ValueError("CRC mismatch")
    if serial == 0:
        raise ValueError("Invalid command sequence")
    return serial, ack, command, body[12:]


def summarize_info(envelope):
    _, ack, command, payload = parse_plaintext(envelope)
    if ack != 1 or command != 0:
        raise ValueError("Response does not match the single information query")
    if len(payload) < 84 or payload[2] != 4 or payload[5] not in (0, 1):
        raise ValueError("Unrecognized P4 device-information response")
    # Exclude nonce, registration material, identifiers, and firmware keys.
    return {
        "protocol_version": f"{payload[2]}.{payload[3]}",
        "firmware_version": ".".join(map(str, payload[46:49])),
        "hardware_version": ".".join(map(str, payload[49:52])),
        "bound": bool(payload[5]),
        "capability_flags": payload[4],
        "communication_ability": int.from_bytes(payload[52:54], "big"),
        "wifi_registration_mode": payload[83],
    }
