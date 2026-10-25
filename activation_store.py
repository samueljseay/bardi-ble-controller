"""Private durable storage for one approved local-activation trial.

No Bluetooth or network APIs. Callers must not print profile or key records.
"""
import fcntl
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import string
import uuid
from activation_wire_study import encode_no_schema_profile, split_application_payload


class StoreError(Exception):
    pass


def sync_fd(fd):
    os.fsync(fd)
    if hasattr(fcntl, 'F_FULLFSYNC'):
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:os.fsync(fd)
    finally:os.close(fd)


def check_private(path, *, directory=False):
    info = path.lstat()
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind_ok or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise StoreError('Private storage ownership, type, or mode mismatch')


def write_exclusive(path, value):
    check_private(path.parent, directory=True)
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf8')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(data); handle.flush(); sync_fd(fd)
    finally:os.close(fd)
    sync_directory(path.parent)
    check_private(path)


def load_private(path):
    check_private(path.parent, directory=True)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise StoreError('Private record is not a protected regular file')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read(16385)
        if len(data) > 16384:raise StoreError('Private record exceeds its size limit')
        return json.loads(data)
    finally:os.close(fd)


def validate_profile(profile):
    payload = encode_no_schema_profile(profile)
    # Public fixtures must never become live credentials.
    forbidden = {'0123456789ABCDEF','FEDCBA9876543210'}
    if profile['localKey'] in forbidden or profile['secKey'] in forbidden:
        raise StoreError('Synthetic fixture keys are not live credentials')
    if profile['localKey'] == profile['secKey']:
        raise StoreError('Local and secret keys must be independent')
    chunks = split_application_payload(payload, 960)
    if len(chunks) != 1:raise StoreError('Trial requires one application chunk')
    return payload, chunks[0]


def create_trial(root, *, approved, target_reference, trial_id=None):
    if approved is not True:raise StoreError('Persistent-trial approval is required')
    root = Path(root)
    check_private(root, directory=True)
    if root.is_symlink() or root.resolve() != root.absolute():
        raise StoreError('Trial root must not contain symlink components')
    if not isinstance(target_reference, dict) or set(target_reference) != {'peripheral_identifier','factory_uuid'}:
        raise StoreError('Exact target reference is required')
    uuid.UUID(target_reference['peripheral_identifier'])
    identity = target_reference['factory_uuid']
    if not isinstance(identity,str) or len(identity)!=16 or not identity.isascii() or not identity.isalnum():
        raise StoreError('Factory identity has an invalid shape')
    trial_id = str(uuid.uuid4()) if trial_id is None else trial_id
    if not isinstance(trial_id,str) or str(uuid.UUID(trial_id)) != trial_id:
        raise StoreError('Invalid trial identifier')
    # An interrupted preparation consumes the reservation. It cannot silently retry.
    target_hash=hashlib.sha256(json.dumps(target_reference,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    write_exclusive(root/'reservation.json', {'trial_id':trial_id,'purpose':'one-approved-persistent-activation','target_sha256':target_hash})
    directory = root/trial_id; directory.mkdir(mode=0o700); sync_directory(root)
    alphabet = string.ascii_letters+string.digits
    key = lambda: ''.join(secrets.choice(alphabet) for _ in range(16))
    profile = {
        'devId':'bf'+secrets.token_hex(10),'capability':1025,'resetFactory':False,
        'localKey':key(),'secKey':key(),'stdTimeZone':'+00:00','timeZone':'+00:00','dstIntervals':'[]',
    }
    payload, chunk = validate_profile(profile)
    record = {'trial_id':trial_id,'target':target_reference,'profile':profile,
              'payload_sha256':hashlib.sha256(payload).hexdigest(),'application_chunk_bytes':len(chunk)}
    write_exclusive(directory/'private-plan.json',record)
    if load_private(directory/'private-plan.json') != record:
        raise StoreError('Private plan did not survive read-back verification')
    return directory


def load_trial(directory):
    directory = Path(directory); check_private(directory,directory=True)
    if directory.resolve() != directory.absolute():raise StoreError('Trial path contains a symlink component')
    reservation = load_private(directory.parent/'reservation.json')
    record = load_private(directory/'private-plan.json')
    target_hash=hashlib.sha256(json.dumps(record['target'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if (record['trial_id'] != directory.name or reservation['trial_id'] != directory.name or
        reservation.get('purpose') != 'one-approved-persistent-activation' or
        reservation.get('target_sha256') != target_hash):
        raise StoreError('Trial reservation mismatch')
    payload, chunk = validate_profile(record['profile'])
    if hashlib.sha256(payload).hexdigest() != record['payload_sha256'] or len(chunk) != record['application_chunk_bytes']:
        raise StoreError('Private plan contents changed')
    return record


def reserve_write(directory, *, expected_payload_sha256=None):
    directory=Path(directory);record=load_trial(directory)
    if expected_payload_sha256 is not None and expected_payload_sha256 != record['payload_sha256']:
        raise StoreError('Prepared payload differs from the durable plan')
    write_exclusive(directory/'write-intent.json', {'trial_id':record['trial_id'],
        'may_have_committed':True,'activation_attempts':1,'payload_sha256':record['payload_sha256']})
    # Return only after the record and directory entry are durable.
    return True


def recovery_required(directory):
    directory=Path(directory)
    # Treat any intent entry, including a damaged one, as possibly committed.
    if not os.path.lexists(directory/'write-intent.json'):return False
    try:
        result=load_private(directory/'recovery-result.json')
        expected={'trial_id','functional_reset_verified','complete_flash_erasure_proven'}
        if not isinstance(result,dict) or set(result)!=expected:return True
        return not (result.get('trial_id')==directory.name and
                    result.get('functional_reset_verified') is True and
                    result.get('complete_flash_erasure_proven') is False)
    except (OSError,ValueError,TypeError,StoreError):return True


def record_recovery(directory, *, exact_identity, fresh_profile, fresh_unbound_info, writer_stopped):
    directory=Path(directory);load_trial(directory)
    if not all(v is True for v in (exact_identity,fresh_profile,fresh_unbound_info,writer_stopped)):
        raise StoreError('Recovery evidence is incomplete')
    if not os.path.lexists(directory/'write-intent.json'):
        raise StoreError('No activation intent exists')
    write_exclusive(directory/'recovery-result.json', {'trial_id':directory.name,
        'functional_reset_verified':True,'complete_flash_erasure_proven':False})


@contextmanager
def operator_lock(root):
    """Exclude concurrent physical prompts and writers; the OS releases a crash lock."""
    root=Path(root);check_private(root,directory=True)
    fd=os.open(root/'operator.lock',os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    locked=False
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
            raise StoreError('Invalid operator lock file')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locked=True
        yield
    finally:
        if locked:fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)
