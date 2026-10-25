# SPDX-License-Identifier: Apache-2.0
# Modified Python host implementation, not the upstream C runtime.
# Protocol reference copyright (C) 2014-2019 Tuya Inc. See NOTICES.md.
"""Offline mode-5 report decoder. No device operations or control encoder.

Mode 5 validates only the first six local-key characters, not the complete key
or secret key. A valid report does not establish persistence or full activation.
"""
import hashlib
from activation_transport import _decode


def parse_report(payload):
    if not 12<=len(payload)<=4096 or payload[0]!=0 or payload[5] not in (0,1,128,129) or payload[6] not in (0,1,2,3):
        raise ValueError('Unsupported report header')
    points=[];seen=set();offset=7
    while offset<len(payload):
        if offset+4>len(payload):raise ValueError('Truncated datapoint header')
        identifier,kind=payload[offset:offset+2]
        size=int.from_bytes(payload[offset+2:offset+4],'big');offset+=4
        if identifier in seen or not 1<=size<=1024 or offset+size>len(payload):
            raise ValueError('Invalid datapoint boundary or repeated identifier')
        seen.add(identifier);data=payload[offset:offset+size];offset+=size
        if kind==0:value=data.hex()
        elif kind==1 and size==1 and data[0] in (0,1):value=bool(data[0])
        elif kind==2 and size==4:value=int.from_bytes(data,'big',signed=True)
        elif kind==3:value=data.decode('utf8')
        elif kind==4 and size==1:value=data[0]
        else:raise ValueError('Unsupported datapoint type or value')
        points.append({'id':identifier,'type':kind,'value':value})
    return {'report_sequence':int.from_bytes(payload[1:5],'big'),'report_type':payload[5]&15,
            'raw_report_type':payload[5],'needs_ack':not bool(payload[5]&128),
            'flag':payload[6],'points':points}


def report_ack_payload(payload):
    report=parse_report(payload)
    return payload[:7]+b'\x00' if report['needs_ack'] else None


def decode_report(envelope,local_key,nonce):
    if not isinstance(local_key,str) or len(local_key)!=16 or not local_key.isascii():
        raise ValueError('Expected a complete ASCII local key')
    if not isinstance(nonce,bytes) or len(nonce)!=6 or not any(nonce):
        raise ValueError('Expected the captured session nonce')
    key=hashlib.md5(local_key.encode('ascii')[:6]+nonce).digest()
    serial,ack,opcode,payload=_decode(envelope,{5:key})
    if opcode!=0x8006 or ack!=0 or serial==0:raise ValueError('Not a supported unsolicited report')
    return dict(parse_report(payload),serial=serial)
