import unittest

import idn_domain_names.filesystem as fs
from idn_domain_names.domain import Domain


class FileSystemModuleTest(unittest.TestCase):
    def test_pass_target_source(self):
        source = [
            'foo\tfoo.bar\tadditional info',
            'foo\tsome.domain\tdata data'
        ]
        actual = fs.parse_targets_source(source)
        expected = {Domain('foo.bar.'), Domain('some.domain.')}
        self.assertEqual(expected, actual)
