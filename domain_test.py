import unittest

from domain import Domain


class DomainTest(unittest.TestCase):
    def test_to_unicode(self):
        domain = Domain('xn--jana-sovkov-r7ad.seria-z.net.')
        actual = domain.to_unicode()
        expected = Domain('jana-sováková.seria-z.net.')
        self.assertEqual(expected, actual)
