import unittest

import idn_domain_names.filesystem as fs
from idn_domain_names.domain import Domain


class FileSystemModuleTest(unittest.TestCase):
    def test_parse_target_source(self):
        source = [
            'foo\tfoo.bar\tadditional info', 'foo\tsome.domain\tdata data'
        ]
        actual = fs.parse_targets_source(source)
        expected = {Domain('foo.bar.'), Domain('some.domain.')}
        self.assertEqual(expected, actual)

    def test_parse_target_source_with_incorrect_domain(self):
        source = ['foo\txn--taksh091-2xk.rozblog.com.\tadditional info']
        self.assertFalse(fs.parse_targets_source(source))

    def test_read_datafile(self):
        actual = fs.read_datafile(['the.emperor.protects.', 'foo.bar'])
        self.assertEqual(2, len(list(actual)))
