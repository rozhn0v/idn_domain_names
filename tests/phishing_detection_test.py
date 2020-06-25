import unittest
from ipaddress import IPv4Address
from unittest.mock import ANY, Mock, PropertyMock, patch

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

    @patch('idn_domain_names.phishing_detection._is_homoglyph_domain_valid')
    @patch('idn_domain_names.filesystem.report_phishing')
    def test_detect_phishing(self, report_phishing, domain_validation):
        phishing = Domain('xn--bcher-kva.tld.')
        delegate = {phishing: ('0.0.0.0', 1)}
        table = Mock()
        table.get_ip_and_asn = lambda k: delegate[k]

        domain_validation.return_value = -1

        pd.detect_phishing(domains_to_check=[phishing],
                           ip_table=table,
                           phishing_targets={Domain('bucher.tld.')},
                           path_to_output='unused')

        report_phishing.assert_called_with(phishing, ANY)
        self.assertTrue(domain_validation.mock_calls)
