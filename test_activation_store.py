import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import activation_store as store

TARGET={'peripheral_identifier':'11111111-1111-4111-8111-111111111111','factory_uuid':'0123456789ABCDEF'}

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve()
        os.chmod(self.root,0o700)
    def tearDown(self):self.temp.cleanup()
    def create(self):return store.create_trial(self.root,approved=True,target_reference=TARGET)

    def test_approval_and_private_root_required(self):
        for value in [False,None,1,'yes']:
            with self.assertRaises(store.StoreError):store.create_trial(self.root,approved=value,target_reference=TARGET)
        self.assertFalse(list(self.root.iterdir()))
        os.chmod(self.root,0o755)
        with self.assertRaises(store.StoreError):self.create()

    def test_durable_private_plan_and_one_reservation(self):
        directory=self.create();record=store.load_trial(directory)
        self.assertTrue(record['target']==TARGET)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        for p in [self.root/'reservation.json',directory/'private-plan.json']:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        self.assertEqual(record['application_chunk_bytes'],198)
        self.assertFalse(store.recovery_required(directory))
        with self.assertRaises(FileExistsError):self.create()

    def test_intent_is_durable_before_return_and_never_replaced(self):
        directory=self.create()
        with patch.object(store,'sync_fd',wraps=store.sync_fd) as sync:
            self.assertTrue(store.reserve_write(directory));self.assertEqual(sync.call_count,1)
        self.assertTrue(store.recovery_required(directory))
        with self.assertRaises(FileExistsError):store.reserve_write(directory)

    def test_failed_intent_sync_is_possibly_committed(self):
        directory=self.create()
        with patch.object(store,'sync_fd',side_effect=OSError('synthetic sync failure')):
            with self.assertRaises(OSError):store.reserve_write(directory)
        self.assertTrue(store.recovery_required(directory))
        with self.assertRaises(FileExistsError):store.reserve_write(directory)

    def test_failed_preparation_consumes_reservation(self):
        with patch.object(store,'sync_fd',side_effect=OSError('synthetic sync failure')):
            with self.assertRaises(OSError):self.create()
        self.assertTrue((self.root/'reservation.json').exists())
        with self.assertRaises(FileExistsError):self.create()

    def test_plan_changes_are_rejected(self):
        directory=self.create();p=directory/'private-plan.json';original=p.read_bytes()
        record=json.loads(original);record['profile']['localKey']='Z'*16
        p.write_text(json.dumps(record))
        with self.assertRaises(store.StoreError):store.load_trial(directory)
        p.write_bytes(original);record=json.loads(original);record['target']['factory_uuid']='F'*16
        p.write_text(json.dumps(record))
        with self.assertRaises(store.StoreError):store.load_trial(directory)

    def test_symlinks_and_exposed_files_are_rejected(self):
        directory=self.create();p=directory/'private-plan.json'
        os.chmod(p,0o644)
        with self.assertRaises(store.StoreError):store.load_trial(directory)
        os.chmod(p,0o600);saved=directory/'saved.json';p.rename(saved);p.symlink_to(saved)
        with self.assertRaises(OSError):store.load_trial(directory)

    def test_damaged_intent_and_incomplete_recovery_stay_blocked(self):
        directory=self.create();store.reserve_write(directory)
        (directory/'write-intent.json').write_bytes(b'')
        self.assertTrue(store.recovery_required(directory))
        with self.assertRaises(store.StoreError):
            store.record_recovery(directory,exact_identity=True,fresh_profile=True,fresh_unbound_info=False,writer_stopped=True)
        self.assertTrue(store.recovery_required(directory))
        (directory/'recovery-result.json').write_text('{')
        os.chmod(directory/'recovery-result.json',0o600)
        self.assertTrue(store.recovery_required(directory))

    def test_structurally_invalid_recovery_records_require_recovery(self):
        directory=self.create();store.reserve_write(directory)
        path=directory/'recovery-result.json'
        cases=[[],None,0,True,'fixture',
               {'trial_id':directory.name,'functional_reset_verified':True},
               {'trial_id':directory.name,'functional_reset_verified':True,'complete_flash_erasure_proven':True},
               {'trial_id':directory.name,'functional_reset_verified':True,'complete_flash_erasure_proven':False,'error':'reset failed'}]
        for value in cases:
            with self.subTest(kind=type(value).__name__):
                path.write_text(json.dumps(value));os.chmod(path,0o600)
                self.assertTrue(store.recovery_required(directory))

    def test_expected_payload_is_checked_before_intent_creation(self):
        directory=self.create()
        with self.assertRaises(store.StoreError):store.reserve_write(directory,expected_payload_sha256='0'*64)
        self.assertFalse((directory/'write-intent.json').exists())

    def test_supplied_trial_identifier_is_validated(self):
        for value in ['../escape','invalid',1]:
            with self.assertRaises((store.StoreError,ValueError)):
                store.create_trial(self.root,approved=True,target_reference=TARGET,trial_id=value)
        self.assertFalse((self.root/'reservation.json').exists())

    def test_functional_recovery_does_not_erase_intent_or_allow_retry(self):
        directory=self.create();store.reserve_write(directory)
        store.record_recovery(directory,exact_identity=True,fresh_profile=True,fresh_unbound_info=True,writer_stopped=True)
        self.assertFalse(store.recovery_required(directory))
        self.assertTrue((directory/'write-intent.json').exists())
        record=store.load_private(directory/'recovery-result.json')
        self.assertFalse(record['complete_flash_erasure_proven'])
        with self.assertRaises(FileExistsError):store.reserve_write(directory)
        with self.assertRaises(FileExistsError):self.create()

if __name__=='__main__':unittest.main(verbosity=2)
