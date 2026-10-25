# SPDX-License-Identifier: Apache-2.0
# Modified Python host implementation; provenance and modification notes: NOTICES.md.
"""Offline study of the app's completed-activation message.

This module has no Bluetooth, network, file-write, or credential-generation API.
It does not establish that the bulb accepts these fields or permits schema omission.
"""
import json
from info_probe_codec import varint, read_varint

MAX_JSON_BYTES = 4096
FIELD_NAMES = frozenset({
    'devId', 'capability', 'resetFactory', 'secKey', 'stdTimeZone',
    'timeZone', 'dstIntervals', 'localKey',
})


def encode_no_schema_profile(profile):
    if set(profile) != FIELD_NAMES:
        raise ValueError('Unexpected or missing activation field')
    for name, size in [('devId', 22), ('localKey', 16), ('secKey', 16)]:
        value = profile[name]
        if not isinstance(value, str) or len(value) != size or not value.isascii() or not value.isalnum():
            raise ValueError('Invalid identifier or key shape')
    if type(profile['capability']) is not int or profile['capability'] != 1025:
        raise ValueError('Fixture supports the Wi-Fi plus Bluetooth capability combination only')
    if profile['resetFactory'] is not False:
        raise ValueError('Factory-reset request is not permitted')
    if profile['stdTimeZone'] != '+00:00' or profile['timeZone'] != '+00:00' or profile['dstIntervals'] != '[]':
        raise ValueError('Fixture supports UTC without daylight-saving intervals only')
    payload = json.dumps(profile, separators=(',', ':'), sort_keys=True).encode('ascii')
    if not 1 <= len(payload) <= MAX_JSON_BYTES:
        raise ValueError('Activation JSON exceeds the study limit')
    return payload


def split_application_payload(payload, packet_limit=960):
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_JSON_BYTES:
        raise ValueError('Invalid application payload size')
    if type(packet_limit) is not int or not 20 <= packet_limit <= 960:
        raise ValueError('Invalid application packet limit')
    chunks = []
    offset = 0
    while offset < len(payload):
        prefix = varint(len(chunks))
        if not chunks:
            prefix += varint(len(payload)) + b'\x20'
        count = min(packet_limit-len(prefix), len(payload)-offset)
        chunks.append(prefix + payload[offset:offset+count])
        offset += count
    return chunks


def join_application_payload(chunks, packet_limit=960):
    if type(packet_limit) is not int or not 20 <= packet_limit <= 960 or not 1 <= len(chunks) <= 256:
        raise ValueError('Invalid packet count or limit')
    result = bytearray()
    total = None
    for expected, chunk in enumerate(chunks):
        if not isinstance(chunk, bytes) or not 1 <= len(chunk) <= packet_limit:
            raise ValueError('Invalid application chunk')
        index, offset = read_varint(chunk, 0)
        if index != expected:
            raise ValueError('Application chunks are missing or out of order')
        if expected == 0:
            total, offset = read_varint(chunk, offset)
            if not 1 <= total <= MAX_JSON_BYTES or offset >= len(chunk) or chunk[offset] != 0x20:
                raise ValueError('Unsupported application header')
            offset += 1
        if offset >= len(chunk):
            raise ValueError('Empty application chunk')
        result.extend(chunk[offset:])
        if len(result) > total or len(result) == total and expected != len(chunks)-1:
            raise ValueError('Excess application data')
    if len(result) != total:
        raise ValueError('Incomplete application data')
    return bytes(result)
