"""Offline legacy demo model. No Bluetooth, socket, or file-write API.

This models a reference-based color experiment, not confirmed Bardi semantics.
A live runner still needs separate approval, durable storage, and reset recovery.
"""
import time
from lighting_state import LightingState,LightingError as DemoError,Command,hsv,color_text,validate_point


def write_payload(sequence,updates):
    if type(sequence) is not int or not 1<=sequence<=0xffffffff:raise DemoError('Invalid command sequence')
    if not isinstance(updates,dict) or not updates or set(updates)-{21,24}:raise DemoError('Only mode and color writes are permitted')
    data=b'\0'+sequence.to_bytes(4,'big')
    # Set the stored color before a possible transition out of white mode.
    for identifier in (24,21):
        if identifier not in updates:continue
        value=updates[identifier];kind=3 if identifier==24 else 4
        validate_point(identifier,kind,value)
        if identifier==21 and value not in (0,1):raise DemoError('Scene and music modes are excluded')
        raw=value.encode('ascii') if identifier==24 else bytes([value])
        data+=bytes([identifier,kind])+len(raw).to_bytes(2,'big')+raw
    return data


class DemoSession(LightingState):
    """One color command and one restoration command, with fresh report evidence.

The reserve callback must persist the intent and return literal True. This model
cannot prove external persistence and must not become a live authority boundary.
"""
    def __init__(self,local_key,nonce,reserve,*,clock=time.monotonic,next_serial=4):
        super().__init__(local_key,nonce,reserve,clock=clock,next_serial=next_serial)
        self.snapshot=None;self.demo_issued=False;self.restore_issued=False;self.restore_mode_issued=False
    def fresh_snapshot(self):
        now=self.now()
        if set(self.points)!={20,21,22,23,24}:raise DemoError('A complete current snapshot is required')
        if any(not 0<=now-item[1]<=5 for item in self.points.values()):raise DemoError('Baseline state is stale')
        values={k:v[0] for k,v in self.points.items()}
        if values[20] is not True or values[21] not in (0,1):raise DemoError('Demo requires On and white or color mode')
        return values
    def issue(self,kind,updates,sequence):
        payload=write_payload(sequence,updates)
        return self.issue_payload(kind,updates,sequence,payload)
    def start_demo(self,*,reference_semantics_approved=False):
        if reference_semantics_approved is not True:raise DemoError('Reference-based semantics require explicit approval')
        if self.demo_issued or self.phase!='baseline':raise DemoError('Demo command cannot repeat')
        self.snapshot=self.fresh_snapshot()
        _,_,old_value=hsv(self.snapshot[24]);value=min(old_value,100)
        candidate=color_text(120,1000,value)
        if self.snapshot[21]==1 and hsv(candidate)==hsv(self.snapshot[24]):candidate=color_text(240,1000,value)
        updates={24:candidate}
        if self.snapshot[21]!=1:updates[21]=1
        self.demo_issued=True
        try:return self.issue('demo',updates,1)
        except BaseException:self.phase='blocked';raise
    def start_restore(self):
        if not self.demo_issued or self.snapshot is None or self.restore_issued:raise DemoError('Restoration is unavailable or already issued')
        updates={24:self.snapshot[24]}
        kind='restore_color' if self.snapshot[21]==0 else 'restore'
        self.restore_issued=True
        try:return self.issue(kind,updates,2)
        except BaseException:self.phase='blocked';raise
    def finish_restore(self):
        if self.phase!='restore_color_confirmed' or self.restore_mode_issued:
            raise DemoError('White mode requires confirmed color restoration and cannot repeat')
        self.restore_mode_issued=True
        try:return self.issue('restore',{21:0},3)
        except BaseException:self.phase='blocked';raise
    def check_confirmation(self):
        p=self.pending
        if not super().check_confirmation():return False
        for identifier in (20,22,23):
            if self.points[identifier][0]!=self.snapshot[identifier]:return False
        if self.points[21][0]!=(1 if p['kind'] in ('demo','restore_color') else self.snapshot[21]):return False
        if p['kind']=='restore' and hsv(self.points[24][0])!=hsv(self.snapshot[24]):return False
        self.phase=p['kind']+'_confirmed';return True
