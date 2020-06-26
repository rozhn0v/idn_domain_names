import unittest
from ipaddress import IPv4Address
from unittest.mock import ANY, Mock, PropertyMock, patch

import idn_domain_names.pipeline as pipeline
from idn_domain_names.domain import Domain


class PhishingDetectionTest(unittest.TestCase):
    def test_valid_punycode_filter(self):
        punycode = Domain('xn--bcher-kva.tld.')
        actual = pipeline.valid_punycode_filter([punycode])
        actual = next(actual)
        expected = (punycode, Domain('bücher.tld.'))
        self.assertEqual(expected, actual)

    @patch('grequests.get')
    @patch('grequests.map')
    def test_get_lang_by_ip_when_response_is_none(self, g_map, g_get):
        g_map.return_value = [None]

        actual = pipeline.get_lang_by_ip([IPv4Address('1.2.3.4')])

        self.assertEqual([None], actual)
        g_get.assert_called()
        g_map.assert_called()

    @patch('grequests.get')
    @patch('grequests.map')
    def test_get_lang_by_ip_when_content_is_none(self, g_map, g_get):
        response = Mock()
        content = PropertyMock(return_value='')
        type(response).content = content
        g_map.return_value = [response]

        actual = pipeline.get_lang_by_ip([IPv4Address('1.2.3.4')])

        self.assertEqual([None], actual)
        content.assert_called()
        g_get.assert_called()

    @patch('grequests.get')
    @patch('grequests.map')
    def test_get_lang_by_ip(self, g_map, g_get):
        response = Mock()
        content = PropertyMock(return_value='<html lang="ru"></html>')
        type(response).content = content
        g_map.return_value = [response]

        actual = pipeline.get_lang_by_ip([IPv4Address('1.2.3.4')])

        self.assertEqual(['ru'], actual)
        g_get.assert_called()

    @patch('idn_domain_names.pipeline._is_homoglyph_domain_valid')
    @patch('idn_domain_names.filesystem.report_phishing')
    def test_detect_phishing(self, report_phishing, domain_validation):
        phishing = Domain('xn--bcher-kva.tld.')
        delegate = {phishing: ('0.0.0.0', 1)}
        table = Mock()
        table.get_ip_and_asn = lambda k: delegate[k]

        domain_validation.return_value = -1

        pipeline.detect_phishing(domains_to_check=[phishing],
                                 ip_table=table,
                                 phishing_targets={Domain('bucher.tld.')},
                                 path_to_output='unused')

        report_phishing.assert_called_with(phishing, ANY)
        self.assertTrue(domain_validation.mock_calls)
