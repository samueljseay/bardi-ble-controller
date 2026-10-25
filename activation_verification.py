# SPDX-License-Identifier: Apache-2.0
# Modified Python host implementation, not the upstream C runtime.
# Protocol reference copyright (C) 2014-2019 Tuya Inc. See NOTICES.md.
"""Offline mode-14/15 codec and strict new-key identity verification.

No device, network, storage, reset, or activation-write APIs are present.
The CommonCrypto adapter is macOS-specific.
"""
import ctypes as C
from dataclasses import dataclass, field
import hashlib
import struct
from activation_store import validate_profile
from info_probe_codec import crc16, fragment, parse_plaintext

class VerificationError(Exception):
    pass

@dataclass(frozen=True)
class VerifiedInfo:
    nonce: bytes = field(repr=False)
    protocol_version: str = '4.8'
    bound: bool = True
    assigned_id_matches: bool = True


def key_for(profile, mode, nonce=None):
    validate_profile(profile)
    material=(profile['localKey']+profile['secKey']).encode('ascii')
    if mode == 15:
        if not isinstance(nonce,bytes) or len(nonce)!=6 or not any(nonce):
            raise VerificationError('A fresh verified nonce is required')
        material+=nonce
    elif mode != 14:
        raise VerificationError('Unsupported new-key mode')
    return hashlib.md5(material).digest()


def aes_cbc(data, key, iv, *, encrypt):
    if not isinstance(data,bytes) or not data or len(data)%16 or len(key)!=16 or len(iv)!=16 or len(data)>4096:
        raise VerificationError('Invalid cipher input shape')
    lib=C.CDLL('/usr/lib/system/libcommonCrypto.dylib')
    lib.CCCrypt.argtypes=[C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p,C.c_size_t,C.c_void_p,
                         C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
    lib.CCCrypt.restype=C.c_int
    out=C.create_string_buffer(len(data)+16);actual=C.c_size_t()
    status=lib.CCCrypt(0 if encrypt else 1,0,0,C.create_string_buffer(key),16,C.create_string_buffer(iv),
                      C.create_string_buffer(data),len(data),out,len(out),C.byref(actual))
    if status!=0:raise VerificationError('Cipher operation failed')
    return out.raw[:actual.value]


def information_request(profile, iv):
    body=struct.pack('>IIHHH',1,0,0,2,20)
    body+=struct.pack('>H',crc16(body))
    envelope=b'\x0e'+iv+aes_cbc(body,key_for(profile,14),iv,encrypt=True)
    return fragment(envelope)


def decode_new_key_frame(envelope, profile, *, mode, nonce=None):
    if mode not in (14,15) or not 33<=len(envelope)<=4096 or envelope[0]!=mode:
        raise VerificationError('Unexpected new-key response mode or size')
    body=aes_cbc(envelope[17:],key_for(profile,mode,nonce),envelope[1:17],encrypt=False)
    if len(body)<14:raise VerificationError('Truncated command body')
    length=int.from_bytes(body[10:12],'big');end=14+length
    if end>len(body):raise VerificationError('Truncated command payload')
    tail=body[end:]
    if len(tail)>15 or not (not any(tail) or all(x==len(tail) for x in tail)):
        raise VerificationError('Unexpected cipher padding')
    try:return parse_plaintext(b'\0'+body[:end])
    except ValueError:raise VerificationError('Command CRC or header validation failed') from None


def verify_bound_information(envelope, profile, *, previous_nonce=None):
    _,ack,opcode,payload=decode_new_key_frame(envelope,profile,mode=14)
    if ack!=1 or opcode!=0 or len(payload)<84:
        raise VerificationError('Information reply does not match its request')
    if payload[2:4]!=bytes([4,8]) or payload[5]!=1:
        raise VerificationError('Protocol or binding state differs from the trial')
    expected=profile['devId'].encode('ascii')
    if payload[55:77]!=expected:
        raise VerificationError('Assigned virtual identity does not match')
    nonce=payload[6:12]
    if not any(nonce) or nonce == previous_nonce:
        raise VerificationError('Device nonce is invalid or reused')
    return VerifiedInfo(nonce=nonce)
