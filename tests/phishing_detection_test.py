import unittest
from unittest.mock import Mock
from unittest.mock import PropertyMock

from ipaddress import IPv4Address

import idn_domain_names.phishing_detection as pd
from idn_domain_names.domain import Domain


class PhishingDetectionTest(unittest.TestCase):
    def test_valid_punycode_filter(self):
        punycode = Domain('xn--bcher-kva.tld.')
        actual = pd.valid_punycode_filter([punycode])
        actual = next(actual)
        expected = (punycode, Domain('bücher.tld.'))
        self.assertEqual(expected, actual)

    def test_get_lang_by_ip_when_response_is_none(self):
        lib = Mock()
        lib.map.side_effect = [[None]]
        actual = pd.get_lang_by_ip([IPv4Address('1.2.3.4')], lib)
        self.assertEqual([None], actual)
        lib.get.assert_called()

    def test_get_lang_by_ip_when_content_is_none(self):
        response = Mock()
        content = PropertyMock(return_value='')
        type(response).content = content

        lib = Mock()
        lib.map = Mock(return_value=[response])

        actual = pd.get_lang_by_ip([IPv4Address('1.2.3.4')], lib)
        self.assertEqual([None], actual)
        content.assert_called()

    def test_get_lang_by_ip(self):
        response = Mock()
        content = PropertyMock(return_value='<html lang="ru"></html>')
        type(response).content = content

        lib = Mock()
        lib.map = Mock(return_value=[response])

        actual = pd.get_lang_by_ip([IPv4Address('1.2.3.4')], lib)
        self.assertEqual(['ru'], actual)
