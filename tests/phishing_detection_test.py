import unittest

import idn_domain_names.phishing_detection as pd
from idn_domain_names.domain import Domain


class PhishingDetectionTest(unittest.TestCase):
    def test_valid_punycode_filter(self):
        punycode = Domain('xn--bcher-kva.tld.')
        actual = pd.valid_punycode_filter([punycode])
        actual = next(actual)
        expected = (punycode, Domain('bücher.tld.'))
        self.assertEqual(expected, actual)
