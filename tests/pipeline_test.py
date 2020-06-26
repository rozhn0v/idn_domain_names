import unittest
from unittest.mock import Mock
from unittest.mock import PropertyMock
from unittest.mock import patch

from ipaddress import IPv4Address

import idn_domain_names.pipeline as pipeline
from idn_domain_names.domain import Domain


# pylint: disable=protected-access
class ValidPunycodeFilterTest(unittest.TestCase):
    def test_valid_punycode_filter(self):
        punycode = Domain('xn--bcher-kva.tld.')

        actual = pipeline._valid_punycode_filter([punycode])
        actual = next(actual)

        expected = (punycode, Domain('bücher.tld.'))
        self.assertEqual(expected, actual)

    def test_valid_punycode_filter_with_dropped_values(self):
        ascii_domain = Domain('foo.bar.')
        broken = Mock(spec=Domain)
        broken.maybe_truncate_www = Mock(side_effect=UnicodeError('fail'))

        actual = pipeline._valid_punycode_filter([ascii_domain, broken])

        self.assertFalse(list(actual))


class GetLangByIpTest(unittest.TestCase):
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


class PipelineTest(unittest.TestCase):
    phishing = Domain('xn--bcher-kva.tld.')
    homo = Domain('bucher.tld.')

    def test_detect_phishing_when_asn_match(self):
        table = PipelineTest.make_table_stub(
            {self.phishing: ('0.0.0.0', 1), self.homo: ('0.0.0.0', 1)})

        pipe = pipeline.Pipeline(table, PipelineTest.dummy_domain_filter, None)

        actual = pipe.detect_phishing([self.phishing], {self.homo})
        self.assertFalse(list(actual))

    def test_detect_phishing_when_homo_unresolved(self):
        phishing = Domain('xn--bcher-kva.tld.')
        homo = Domain('bucher.tld.')

        table = PipelineTest.make_table_stub(
            {phishing: ('0.0.0.0', 1), homo: (None, None)})

        pipe = pipeline.Pipeline(table, PipelineTest.dummy_domain_filter, None)

        actual = pipe.detect_phishing([phishing], {homo})
        self.assertFalse(list(actual))

    def test_detect_phishing_when_negative_lang_check_and_different_asn(self):
        phishing = Domain('xn--bcher-kva.tld.')
        homo = Domain('bucher.tld.')

        table = PipelineTest.make_table_stub(
            {phishing: ('0.0.0.0', 1), homo: ('1.1.1.1', 123)})

        pipe = pipeline.Pipeline(table, PipelineTest.dummy_domain_filter,
                                 lang_check=Mock(return_value=-1))

        actual = pipe.detect_phishing([phishing], {homo})
        self.assertEqual([phishing], list(actual))

    @staticmethod
    def make_table_stub(mapping):
        result = Mock()
        result.get_ip_and_asn = lambda k: mapping[k]
        return result

    @staticmethod
    def dummy_domain_filter(domains):
        return [(domain, domain.to_unicode()) for domain in domains]
