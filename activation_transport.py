# SPDX-License-Identifier: Apache-2.0
# Modified Python host implementation, not the upstream C runtime.
# Protocol reference copyright (C) 2014-2019 Tuya Inc. See NOTICES.md.
"""Closed BLE operations for the one-message local-activation trial.

Real radio access occurs only when a BleSession context is entered. This module
has no generic public command sender. Captures must stay in private storage.
"""
import asyncio
from dataclasses import dataclass, field
import hashlib
import os
import struct
from activation_store import load_trial, reserve_write
from activation_wire_study import encode_no_schema_profile, split_application_payload
from activation_verification import aes_cbc, key_for, information_request, verify_bound_information
from info_probe_codec import crc16, fragment, parse_plaintext, read_varint

SERVICE='0000fd50-0000-1000-8000-00805f9b34fb'
WRITE='00000001-0000-1001-8001-00805f9b07d0'
NOTIFY='00000002-0000-1001-8001-00805f9b07d0'

class TransportError(Exception):pass
class OpaqueFrame(Exception):pass

@dataclass(frozen=True)
class TemporaryInfo:
    nonce: bytes=field(repr=False)
    packet_limit: int=960


def _encrypted_request(sn,opcode,payload,mode,key,iv=None):
    iv=os.urandom(16) if iv is None else iv
    body=struct.pack('>IIHH',sn,0,opcode,len(payload))+payload
    body+=struct.pack('>H',crc16(body));body+=bytes((-len(body))%16)
    return tuple(fragment(bytes([mode])+iv+aes_cbc(body,key,iv,encrypt=True),frame_sequence=(sn-1)&15))


def _decode(envelope,keys):
    if not 15<=len(envelope)<=4096:raise TransportError('Frame size is invalid')
    mode=envelope[0]
    if mode not in keys:
        if mode in (2,5):
            if len(envelope)<33 or (len(envelope)-17)%16:
                raise TransportError('Malformed opaque cipher frame')
            raise OpaqueFrame()
        raise TransportError('Unexpected cipher mode')
    if mode==0:body=envelope[1:]
    else:
        if len(envelope)<33:raise TransportError('Cipher frame is too short')
        body=aes_cbc(envelope[17:],keys[mode],envelope[1:17],encrypt=False)
    if len(body)<14:raise TransportError('Command body is too short')
    end=14+int.from_bytes(body[10:12],'big')
    if end>len(body):raise TransportError('Command payload is truncated')
    tail=body[end:]
    if len(tail)>15 or not (not any(tail) or all(x==len(tail) for x in tail)):
        raise TransportError('Invalid padding')
    return parse_plaintext(b'\0'+body[:end])


def information_fields(p):
    if (len(p)<96 or p[2:5]!=bytes([4,8,37]) or p[5] not in (0,1) or
        p[52:54]!=bytes([0,4]) or not p[54]&2 or not any(p[6:12])):
        raise TransportError('Information profile changed')
    cursor=96+p[95]
    for _ in range(2):
        if cursor>=len(p):raise TransportError('Missing capability field')
        cursor+=1+p[cursor]
    if cursor>=len(p):raise TransportError('Missing packet limit')
    size=p[cursor];cursor+=1
    if size not in (1,2,4) or cursor+size>len(p):raise TransportError('Invalid packet limit')
    limit=int.from_bytes(p[cursor:cursor+size],'big')
    if limit!=960:raise TransportError('Application packet limit changed from the verified profile')
    return TemporaryInfo(p[6:12],limit)


def temporary_info(envelope):
    _,ack,opcode,p=_decode(envelope,{0:None})
    if ack!=1 or opcode!=0 or len(p)<96 or p[5]!=0 or p[54]&6!=2:
        raise TransportError('Unbound profile changed')
    return information_fields(p)


class Assembler:
    def __init__(self):self.parts=[];self.total=None;self.count=0
    def add(self,packet):
        if not isinstance(packet,bytes) or not 1<=len(packet)<=244 or len(self.parts)>=256:
            raise TransportError('Notification bound exceeded')
        index,at=read_varint(packet,0)
        if index!=len(self.parts):raise TransportError('Fragment order is invalid')
        if index==0:
            self.total,at=read_varint(packet,at)
            if not 15<=self.total<=4096 or at>=len(packet) or packet[at]>>4 not in (2,3,4):
                raise TransportError('Invalid fragment header')
            at+=1
        if at>=len(packet):raise TransportError('Empty fragment')
        data=packet[at:];self.parts.append(data);self.count+=len(data)
        if self.count>self.total:raise TransportError('Excess fragment data')
        if self.count==self.total:
            result=b''.join(self.parts);self.__init__();return result
        return None


async def find_target(target,golden,*,bound,timeout=15):
    from bleak import BleakScanner
    found=asyncio.get_running_loop().create_future()
    def observe(device,ad):
        if device.address.lower()!=target['peripheral_identifier'].lower():return
        service=ad.service_data.get(SERVICE,b'')
        manufacturer=b'\xd0\x07'+ad.manufacturer_data.get(0x07d0,b'')
        if not -75<=ad.rssi<=0 or len(service)<2 or service[0]>>4!=4 or len(manufacturer)<6:return
        if bool(service[0]&8)!=bound:return
        if not bound and (manufacturer!=golden['manufacturer'] or service!=golden['service']):return
        if not found.done():found.set_result(device)
    async with BleakScanner(detection_callback=observe,service_uuids=[SERVICE]):
        return await asyncio.wait_for(found,timeout)


class BleSession:
    def __init__(self,device,target,client_factory=None):
        self.device=device;self.target=dict(target);self.client_factory=client_factory
        self.client=None;self.stage='new';self.temp=None;self.queue=asyncio.Queue(maxsize=96)
        self.assembler=Assembler();self.raw=[];self.bytes_received=0;self.overflow=False
        self.last_serial=0;self.writes=0;self.write_acks=0;self.opaque=0;self.closed=True
        self.clock_requests_unanswered=0
        self.transfer_complete=False;self.disconnect_confirmed=False;self.legacy_reports=[]
    async def __aenter__(self):
        if self.device.address.lower()!=self.target['peripheral_identifier'].lower():
            raise TransportError('Target identity mismatch')
        if self.client_factory is None:
            from bleak import BleakClient
            self.client_factory=BleakClient
        self.client=self.client_factory(self.device,timeout=12)
        try:
            await asyncio.wait_for(self.client.connect(),15)
            service=self.client.services.get_service(SERVICE)
            if service is None:raise TransportError('Expected service is absent')
            write=service.get_characteristic(WRITE)
            notify=service.get_characteristic(NOTIFY)
            if write is None or notify is None or 'write' not in write.properties or 'notify' not in notify.properties:
                raise TransportError('GATT properties changed')
            await asyncio.wait_for(self.client.start_notify(NOTIFY,self._notify),5)
            self.closed=False;return self
        except BaseException:
            await self.close();raise
    async def close(self):
        self.closed=True
        if self.client is not None:
            try:
                await asyncio.wait_for(self.client.disconnect(),5)
                self.disconnect_confirmed=self.client.is_connected is False
            except (Exception,asyncio.CancelledError):pass
    async def __aexit__(self,*args):await self.close()
    def _notify(self,characteristic,data):
        packet=bytes(data)
        packet_limit,byte_limit=(512,65536) if self.stage=='lighting_controls' else (96,12288)
        if len(self.raw)>=packet_limit or self.bytes_received+len(packet)>byte_limit or not 1<=len(packet)<=244:
            self.overflow=True;return
        self.raw.append(packet);self.bytes_received+=len(packet)
        try:self.queue.put_nowait(packet)
        except asyncio.QueueFull:self.overflow=True
    async def _send(self,packets):
        if self.closed or self.overflow:raise TransportError('Transport is unavailable')
        async def send_all():
            for packet in packets:
                limit=512 if self.stage=='lighting_controls' else 72 if self.stage=='legacy_demo_attempted' else 64
                if self.stage=='lighting_controls' and asyncio.get_running_loop().time()-self.lighting_started>180:
                    raise TransportError('Lighting connection lifetime exceeded')
                if self.closed or self.overflow or not 1<=len(packet)<=20 or self.writes>=limit:
                    raise TransportError('Write limit reached')
                self.writes+=1
                await self.client.write_gatt_char(WRITE,packet,response=True)
                self.write_acks+=1
        await asyncio.wait_for(send_all(),30)
    async def _next_envelope(self,deadline):
        loop=asyncio.get_running_loop()
        while loop.time()<deadline:
            if self.overflow:raise TransportError('Notification limit reached')
            packet=await asyncio.wait_for(self.queue.get(),max(0.001,deadline-loop.time()))
            envelope=self.assembler.add(packet)
            if envelope is not None:return envelope
        raise TimeoutError()
    async def _receive(self,keys,*,opcode,ack,deadline):
        loop=asyncio.get_running_loop()
        while loop.time()<deadline:
            envelope=await self._next_envelope(deadline)
            try:serial,received_ack,received_opcode,payload=_decode(envelope,keys)
            except OpaqueFrame:
                self.opaque+=1
                if self.opaque>4:raise TransportError('Opaque response limit reached')
                continue
            if serial<=self.last_serial:raise TransportError('Repeated response sequence')
            self.last_serial=serial
            if (received_opcode in opcode if isinstance(opcode,tuple) else received_opcode==opcode) and received_ack==ack:return envelope,payload
            if opcode==27 and received_ack==0 and received_opcode==0x8006 and envelope[0]==5:
                from legacy_state_report import parse_report
                if len(self.legacy_reports)>=8:raise TransportError('Legacy report limit reached')
                try:report=parse_report(payload)
                except ValueError as error:raise TransportError('Malformed legacy datapoint report') from error
                self.legacy_reports.append(report)
                continue
            if (self.stage=='legacy_handshake' and envelope[0]==5 and received_ack==0 and
                received_opcode==0x8014 and payload==b'\x01'):
                self.clock_requests_unanswered+=1
                if self.clock_requests_unanswered>2:raise TransportError('Clock request budget exceeded')
                continue
            if received_ack==0 and received_opcode==30:continue
            raise TransportError('Response does not match the request')
        raise TimeoutError()
    async def baseline(self):
        from info_probe_codec import candidate_query
        if self.stage!='new':raise TransportError('Invalid baseline phase')
        self.stage='baseline';await self._send((candidate_query(),))
        envelope,_=await self._receive({0:None},opcode=0,ack=1,deadline=asyncio.get_running_loop().time()+12)
        info=temporary_info(envelope);self.stage='baseline_complete';return info
    async def temporary_session(self):
        self.temp=await self.baseline()
        key=hashlib.md5(bytes(16)+self.temp.nonce).digest()
        identity=self.target['factory_uuid'].encode('ascii')
        if len(identity)!=16 or not identity.isalnum():raise TransportError('Invalid factory identity')
        self.stage='handshake'
        await self._send(_encrypted_request(2,1,identity,12,key))
        _,payload=await self._receive({12:key},opcode=1,ack=2,deadline=asyncio.get_running_loop().time()+12)
        if payload!=b'\0':raise TransportError('Temporary handshake rejected')
        self.stage='ready';return self.temp
    def _activation_packets(self,directory,*,on_durable_intent=None):
        if self.stage!='ready':raise TransportError('Activation session is not ready')
        record=load_trial(directory)
        if record['target']!=self.target:raise TransportError('Plan target changed')
        payload=encode_no_schema_profile(record['profile'])
        chunks=split_application_payload(payload,self.temp.packet_limit)
        if len(chunks)!=1:raise TransportError('Activation requires more than one application chunk')
        key=hashlib.md5(bytes(16)+self.temp.nonce).digest()
        packets=_encrypted_request(3,27,chunks[0],12,key)
        self.stage='activation_attempted'
        reserve_write(directory,expected_payload_sha256=hashlib.sha256(payload).hexdigest())
        if on_durable_intent is not None:on_durable_intent()
        return packets,record
    async def activate_once(self,directory,*,on_durable_intent=None):
        packets,record=self._activation_packets(directory,on_durable_intent=on_durable_intent)
        key=hashlib.md5(bytes(16)+self.temp.nonce).digest()
        await self._send(packets);self.transfer_complete=True
        keys={5:hashlib.md5(record['profile']['localKey'].encode('ascii')[:6]+self.temp.nonce).digest(),
              12:key,14:key_for(record['profile'],14),15:key_for(record['profile'],15,self.temp.nonce)}
        deadline=asyncio.get_running_loop().time()+12
        try:
            while True:
                _,status=await self._receive(keys,opcode=27,ack=3,deadline=deadline)
                if len(status)!=1 or status[0] not in (0,1,2,3):raise TransportError('Unknown activation status')
                if status[0]!=1:return int(status[0])
                # The sole application chunk is already sent. Never append another.
        except TimeoutError:return None
    async def verify_information(self,profile,*,previous_nonce=None):
        if self.stage!='new':raise TransportError('Invalid verification phase')
        self.stage='verification'
        await self._send(information_request(profile,os.urandom(16)))
        envelope,_=await self._receive({14:key_for(profile,14)},opcode=0,ack=1,deadline=asyncio.get_running_loop().time()+12)
        verified=verify_bound_information(envelope,profile,previous_nonce=previous_nonce)
        self.last_verified_envelope=envelope
        self.verified_info=verified
        self.verified_profile_digest=hashlib.sha256(encode_no_schema_profile(profile)).digest()
        self.stage='verified';return verified

    async def read_state(self,profile,verified):
        if (self.stage!='verified' or verified is not self.verified_info or
            hashlib.sha256(encode_no_schema_profile(profile)).digest()!=self.verified_profile_digest):
            raise TransportError('State read lacks matching new-key evidence')
        result={'query_sent':False,'query_acknowledged':False,'report_frame_received':False}
        key=key_for(profile,15,verified.nonce)
        self.stage='bound_handshake'
        await self._send(_encrypted_request(2,1,self.target['factory_uuid'].encode('ascii'),15,key))
        try:
            _,payload=await self._receive({15:key},opcode=1,ack=2,deadline=asyncio.get_running_loop().time()+12)
            if payload not in (b'\0',b'\2'):raise TransportError('Bound handshake rejected')
            self.stage='state_query'
            await self._send(_encrypted_request(3,3,b'',15,key));result['query_sent']=True
            deadline=asyncio.get_running_loop().time()+12
            _,payload=await self._receive({15:key},opcode=3,ack=3,deadline=deadline)
            if payload!=b'\0':raise TransportError('State query rejected')
            result['query_acknowledged']=True
            _,payload=await self._receive({15:key},opcode=(0x8001,0x8006,0x8007),ack=0,deadline=deadline)
            result['report_frame_received']=bool(payload)
        except TimeoutError:pass
        self.stage='state_read_complete'
        return result

    async def observe_unbound_state(self):
        if self.stage!='ready':raise TransportError('Temporary session is not ready')
        self.stage='unbound_state_observation'
        key=hashlib.md5(bytes(16)+self.temp.nonce).digest()
        await self._send(_encrypted_request(3,3,b'',12,key))
        # Retain bounded notifications without using opaque data to authorize commands.
        await asyncio.sleep(12)
        if self.overflow:raise TransportError('Notification limit reached')
        self.stage='unbound_state_observation_complete'

    async def legacy_reconnect(self,profile,*,boot_default=False):
        from cached_information import query_information
        metadata=await query_information(self,profile,boot_default=boot_default)
        verified=metadata['reset_default_key_verified'] if boot_default else metadata['local_key_prefix_verified']
        if not verified or not metadata['bound']:
            raise TransportError('Reconnect lacks encrypted bound information')
        self.legacy_login_key='\0'*16 if boot_default else profile['localKey']
        key=hashlib.md5(self.legacy_login_key.encode()[:6]+self.temp.nonce).digest()
        self.stage='legacy_handshake'
        await self._send(_encrypted_request(2,1,self.target['factory_uuid'].encode('ascii'),5,key))
        _,status=await self._receive({5:key},opcode=1,ack=2,deadline=asyncio.get_running_loop().time()+12)
        if status not in (b'\0',b'\2'):raise TransportError('Legacy reconnect handshake rejected')
        self.legacy_profile_digest=hashlib.sha256(encode_no_schema_profile(profile)).digest()
        self.stage='legacy_ready'
        metadata['handshake_clock_requests_unanswered']=self.clock_requests_unanswered
        return metadata

    async def lighting_start(self,directory,*,activation_directory=None,reconnect_profile=None):
        """Start basic controls in an explicit temporary or authenticated bound session.

        Configuration is never implicit. A fresh activation record is required
        when requested; historical research reservations cannot be reused.
        """
        from activation_store import check_private,write_exclusive
        from lighting_control import ControlSession
        if reconnect_profile is not None:
            if (activation_directory is not None or self.stage!='legacy_ready' or
                hashlib.sha256(encode_no_schema_profile(reconnect_profile)).digest()!=self.legacy_profile_digest):
                raise TransportError('Controls lack matching reconnect evidence')
        elif self.stage!='ready':raise TransportError('Temporary session is not ready')
        check_private(directory,directory=True)
        record=load_trial(activation_directory) if activation_directory is not None else None
        if record is not None and record['target']!=self.target:raise TransportError('Plan target changed')
        profile=record['profile'] if record is not None else reconnect_profile
        self.lighting_local_key=profile['localKey'] if profile is not None else '\0'*16
        if reconnect_profile is not None:self.lighting_local_key=self.legacy_login_key
        def reserve(kind,digest):
            write_exclusive(directory/f'control-{self.lighting.next_sequence:04d}-intent.json',{
                'payload_sha256':digest,'maximum_attempts':1,
                'reported_state_is_not_optical_proof':True,
            })
            return True
        self.lighting=ControlSession(self.lighting_local_key,self.temp.nonce,reserve)
        self.lighting.last_peer=self.last_serial
        self.lighting_queries={}
        self.lighting_started=asyncio.get_running_loop().time()
        self.lighting_initial_activation=record is not None
        if record is not None:packets,_=self._activation_packets(activation_directory)
        else:
            key=self.lighting.key if reconnect_profile is not None else hashlib.md5(bytes(16)+self.temp.nonce).digest()
            packets=_encrypted_request(3,3,b'',5 if reconnect_profile is not None else 12,key)
            self.lighting_queries[3]=False
        self.stage='lighting_controls'
        await self._send(packets)
        if record is not None:self.transfer_complete=True
        deadline=asyncio.get_running_loop().time()+12
        while True:
            try:
                snapshot=self.lighting.read()
                if record is not None or self.lighting_queries.get(3):return snapshot
            except ValueError:pass
            await self._lighting_receive(deadline)

    async def _lighting_receive(self,deadline):
        from lighting_state import LightingError
        if self.stage!='lighting_controls' or asyncio.get_running_loop().time()-self.lighting_started>180:
            raise TransportError('Lighting connection lifetime exceeded')
        envelope=await self._next_envelope(deadline)
        temp_key=hashlib.md5(bytes(16)+self.temp.nonce).digest()
        try:serial,ack,opcode,payload=_decode(envelope,{5:self.lighting.key,12:temp_key})
        except OpaqueFrame:
            self.opaque+=1
            if self.opaque>4:raise TransportError('Opaque response limit reached')
            return
        if envelope[0]==5 and opcode==0x8006 and ack==0:
            reply=self.lighting.receive_report(envelope)
            if reply is not None:await self._send(reply.packets(self.lighting_local_key,self.temp.nonce,os.urandom(16)))
        elif envelope[0]==5 and opcode==0x27:
            self.lighting.receive_command_ack(envelope)
        else:
            if envelope[0]==5:
                _,_,_,_,new=self.lighting.decode(envelope)
                if not new:return
            else:
                if serial<=self.lighting.last_peer:raise TransportError('Repeated response sequence')
                self.lighting.last_peer=serial
            if opcode==3 and ack in self.lighting_queries:
                if payload!=b'\0':raise LightingError('State query rejected')
                self.lighting_queries[ack]=True
            elif self.lighting_initial_activation and opcode==27 and ack==3:
                if payload not in (b'\0',b'\1'):raise LightingError('Configuration rejected')
            elif opcode==0x8014 and ack==0 and payload==b'\x01':
                self.clock_requests_unanswered+=1
                if self.clock_requests_unanswered>2:raise TransportError('Clock request budget exceeded')
            elif not (opcode==30 and ack==0):raise LightingError('Unexpected lighting response')
        self.last_serial=self.lighting.last_peer

    async def lighting_read(self):
        """Refresh all five basic fields; old observations cannot satisfy a query."""
        if self.stage!='lighting_controls':raise TransportError('Lighting session is not ready')
        floor=self.lighting.last_report
        command=self.lighting.command(3,0,b'')
        self.lighting_queries[command.serial]=False
        await self._send(command.packets(self.lighting_local_key,self.temp.nonce,os.urandom(16)))
        deadline=asyncio.get_running_loop().time()+12
        while True:
            try:
                snapshot=self.lighting.read()
                if (self.lighting_queries[command.serial] and
                    all(self.lighting.points[i][2]>floor for i in (20,21,22,23,24))):return snapshot
            except ValueError:pass
            await self._lighting_receive(deadline)

    async def lighting_apply(self,control,*,persistent_approved=False):
        """One durable, report-gated control. Never retry an uncertain write."""
        from lighting_control import DoNotDisturb,Outcome,PowerOnMemory,Status
        if self.stage!='lighting_controls':raise TransportError('Lighting session is not ready')
        if isinstance(control,(PowerOnMemory,DoNotDisturb)) and persistent_approved is not True:
            raise TransportError('Explicit persistent-setting approval is required')
        command=self.lighting.apply(control)
        if command is None:return Outcome(Status.UNCHANGED,False,frozenset(),False)
        deadline=self.lighting.pending['issued']+8
        try:
            async with asyncio.timeout_at(deadline):
                await self._send(command.packets(self.lighting_local_key,self.temp.nonce,os.urandom(16)))
                while self.lighting.outcome().status==Status.PENDING:
                    await self._lighting_receive(deadline)
            return self.lighting.outcome()
        except BaseException:
            self.lighting.outcome(uncertain=True)
            raise

    async def legacy_demo(self,directory,*,activation_directory=None,reconnect_profile=None,reference_semantics_approved=False,observe_only=False):
        """One report-gated color command and restoration. Never retries a write.

        A separate fresh activation directory is optional. Callers must arrange
        reset recovery after any activation intent, including interrupted runs.
        Returned confirmations describe reported state, not optical output.
        """
        from activation_store import check_private,write_exclusive
        from legacy_demo_study import DemoSession,DemoError
        from legacy_state_report import parse_report
        reconnecting=reconnect_profile is not None
        if reconnecting:
            if (activation_directory is not None or self.stage!='legacy_ready' or
                hashlib.sha256(encode_no_schema_profile(reconnect_profile)).digest()!=self.legacy_profile_digest):
                raise TransportError('Reconnect control lacks matching session evidence')
        elif self.stage!='ready':raise TransportError('Temporary session is not ready')
        if observe_only and activation_directory is not None:raise TransportError('Observation cannot activate')
        if not observe_only and reference_semantics_approved is not True:raise TransportError('Reference semantics were not approved')
        check_private(directory,directory=True)
        record=load_trial(activation_directory) if activation_directory is not None else None
        if record is not None and record['target']!=self.target:raise TransportError('Plan target changed')
        local_key=record['profile']['localKey'] if record is not None else reconnect_profile['localKey'] if reconnecting else '\0'*16
        def reserve(kind,payload_digest):
            write_exclusive(directory/(kind+'-intent.json'),{
                'payload_sha256':payload_digest,'baseline':model.snapshot,
                'maximum_attempts':1,'reported_state_is_not_optical_proof':True,
            })
            return True
        model=DemoSession(local_key,self.temp.nonce,reserve,next_serial=4)
        model.last_peer=self.last_serial
        temp_key=hashlib.md5(bytes(16)+self.temp.nonce).digest()
        result={'baseline_complete':False,'demo_may_have_sent':False,
                'demo_reported_confirmed':False,'restore_reported_confirmed':False,
                'demo_full_snapshot_rechecked':False,'restore_full_snapshot_rechecked':False,
                'optical_output_verified':False,'observed_points':{},'frames':[]}
        restoring=False;report_acks=0
        loop=asyncio.get_running_loop()
        async def emit(command):
            nonlocal report_acks
            packets=command.packets(local_key,self.temp.nonce,os.urandom(16))
            ceiling=72 if restoring else 54
            if self.writes+len(packets)>ceiling:raise TransportError('Restoration write reserve reached')
            if command.opcode==0x8006:
                if report_acks>=(14 if restoring else 10):raise TransportError('Report ACK reserve reached')
                report_acks+=1
            elif command.opcode==0x27 and not restoring:
                result['demo_may_have_sent']=True
            await self._send(packets)
        async def dispatch(deadline):
            envelope=await self._next_envelope(deadline)
            try:serial,ack,opcode,payload=_decode(envelope,{5:model.key,12:temp_key})
            except OpaqueFrame:
                self.opaque+=1
                if self.opaque>4:raise TransportError('Opaque response limit reached')
                result['frames'].append({'mode':envelope[0],'opaque':True})
                return
            result['frames'].append({'mode':envelope[0],'serial':serial,'ack':ack,'opcode':opcode})
            model.last_peer=max(model.last_peer,self.last_serial)
            if envelope[0]==5 and opcode==0x8006 and ack==0:
                command=model.receive_report(envelope)
                for point in parse_report(payload)['points']:
                    result['observed_points'][str(point['id'])]=point
                self.last_serial=max(self.last_serial,model.last_peer)
                if command is not None:await emit(command)
            elif envelope[0]==5 and opcode==0x27:
                model.receive_command_ack(envelope)
                self.last_serial=max(self.last_serial,model.last_peer)
            else:
                if serial<=self.last_serial:raise TransportError('Repeated response sequence')
                self.last_serial=serial
                if ack==3 and opcode==(27 if record is not None else 3):
                    if len(payload)!=1 or payload[0] not in ((0,1) if record is not None else (0,)):
                        raise TransportError('Initial request was rejected')
                    result['initial_status']=payload[0]
                elif envelope[0]==5 and ack==0 and opcode==0x8014 and payload==b'\x01':
                    # Retain the observed clock request without changing device time.
                    count=result.get('clock_requests_unanswered',0)+1
                    if count>2:raise TransportError('Clock request budget exceeded')
                    result['clock_requests_unanswered']=count
                elif not (ack==0 and opcode==30):raise TransportError('Unexpected demo response')
        async def confirm(kind):
            deadline=model.pending['issued']+8
            async with asyncio.timeout_at(deadline):
                while model.phase!=kind+'_confirmed':await dispatch(deadline)
        try:
            if record is not None:
                packets,_=self._activation_packets(activation_directory)
            else:
                packets=_encrypted_request(3,3,b'',5 if reconnecting else 12,model.key if reconnecting else temp_key)
            self.stage='legacy_demo_attempted'
            await self._send(packets)
            self.transfer_complete=record is not None
            deadline=loop.time()+12
            while True:
                try:snapshot=model.fresh_snapshot();break
                except DemoError:await dispatch(deadline)
            result['baseline_complete']=True
            write_exclusive(directory/'baseline.json',snapshot)
            if observe_only:return result
            command=model.start_demo(reference_semantics_approved=True)
            async with asyncio.timeout_at(model.pending['issued']+8):
                await emit(command);await confirm('demo')
            result['demo_reported_confirmed']=True
            result['demo_full_snapshot_rechecked']=model.full_snapshot_rechecked()
            # Keep the distinguishable state briefly, then restore even if confirmation failed.
            await asyncio.sleep(2)
        except Exception as error:
            result['error_type']=type(error).__name__
            if isinstance(error,(TransportError,ValueError)):result['error_reason']=str(error)
        finally:
            if result['demo_may_have_sent']:
                restoring=True
                async def restore():
                    command=model.start_restore()
                    async with asyncio.timeout_at(model.pending['issued']+8):
                        await emit(command);await confirm(model.pending['kind'])
                    if model.phase=='restore_color_confirmed':
                        command=model.finish_restore()
                        async with asyncio.timeout_at(model.pending['issued']+8):
                            await emit(command);await confirm('restore')
                    result['restore_reported_confirmed']=True
                    result['restore_full_snapshot_rechecked']=model.full_snapshot_rechecked()
                cleanup=asyncio.create_task(restore())
                try:await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    try:await cleanup
                    except Exception as error:result['restore_error_type']=type(error).__name__
                    raise
                except Exception as error:
                    result['restore_error_type']=type(error).__name__
                    if isinstance(error,(TransportError,DemoError)):result['restore_error_reason']=str(error)
            result['report_acknowledgements']=report_acks
            self.stage='legacy_demo_complete'
        return result
