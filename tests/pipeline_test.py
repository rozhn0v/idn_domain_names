import unittest
from unittest.mock import Mock
from unittest.mock import PropertyMock
from unittest.mock import patch

from ipaddress import IPv4Address

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

    def test_detect_phishing_when_asn_match(self):
        phishing = Domain('xn--bcher-kva.tld.')
        homo = Domain('bucher.tld.')

        delegate = {phishing: ('0.0.0.0', 1), homo: ('0.0.0.0', 1)}
        table = Mock()
        table.get_ip_and_asn = lambda k: delegate[k]

        pipe = pipeline.Pipeline(table, dummy_domain_filter, Mock())

        actual = pipe.detect_phishing(domains_to_check=[phishing],
                                      phishing_targets={homo})
        self.assertFalse(list(actual))

    def test_detect_phishing_when_homo_unresolved(self):
        phishing = Domain('xn--bcher-kva.tld.')
        homo = Domain('bucher.tld.')

        delegate = {phishing: ('0.0.0.0', 1), homo: (None, None)}
        table = Mock()
        table.get_ip_and_asn = lambda k: delegate[k]

        pipe = pipeline.Pipeline(table, dummy_domain_filter, Mock())

        actual = pipe.detect_phishing(domains_to_check=[phishing],
                                      phishing_targets={homo})
        self.assertFalse(list(actual))

    def test_detect_phishing_when_negative_lang_check_and_different_asn(self):
        phishing = Domain('xn--bcher-kva.tld.')
        homo = Domain('bucher.tld.')

        delegate = {phishing: ('0.0.0.0', 1), homo: ('1.1.1.1', 123)}
        table = Mock()
        table.get_ip_and_asn = lambda k: delegate[k]

        pipe = pipeline.Pipeline(table, dummy_domain_filter,
                                 Mock(return_value=-1))

        actual = pipe.detect_phishing(domains_to_check=[phishing],
                                      phishing_targets={homo})
        self.assertEqual([phishing], list(actual))


def dummy_domain_filter(domains):
    return [(domain, domain.to_unicode()) for domain in domains]
