from types import SimpleNamespace
import unittest
from cached_information import select_cached


def peripheral(address):
    return SimpleNamespace(identifier=lambda:SimpleNamespace(UUIDString=lambda:address))


class CacheTests(unittest.TestCase):
    def test_only_exact_saved_identifier_is_accepted(self):
        item=peripheral('KNOWN')
        self.assertIs(select_cached([item],'known'),item)
    def test_missing_wrong_or_ambiguous_cache_is_rejected(self):
        for items in [[],[peripheral('other')],[peripheral('known'),peripheral('known')]]:
            with self.subTest(count=len(items)),self.assertRaises(ValueError):select_cached(items,'known')

if __name__=='__main__':unittest.main()
