import unittest
from ipaddress import IPv4Address

from idn_domain_names.domain import Domain
from idn_domain_names.ipv4util import ClosedRange, IpTable


class Ipv4UtilsTest(unittest.TestCase):
    def test_get_ip_for_unresolvable_domain(self):
        table = IpTable([])
        unresolvable_domain = Domain('unresolvable.domain.')
        self.assertIsNone(table.resolve_ip(unresolvable_domain))

    def test_get_asn(self):
        table = IpTable([
            make_range('1.1.188.0', '1.1.254.255', 23969),
            make_range('1.2.11.0', '1.2.11.255', 18046),
            make_range('1.1.6.0', '1.1.6.255', 138449)
        ])

        self.assertEqual('138449', table.lookup_asn(IPv4Address('1.1.6.123')))
        self.assertEqual('18046', table.lookup_asn(IPv4Address('1.2.11.23')))
        self.assertEqual('23969', table.lookup_asn(IPv4Address('1.1.188.45')))
        self.assertIsNone(table.lookup_asn(IPv4Address('1.1.7.1')))


class ClosedRangeTest(unittest.TestCase):
    def test_foo(self):
        interval = make_range('1.1.188.0', '1.1.254.255', 23969)
        self.assertTrue(interval.is_after(IPv4Address('1.1.177.255')))
        self.assertFalse(interval.is_after(IPv4Address('1.1.255.1')))


def make_range(start: str, end: str, asn: int) -> ClosedRange:
    return ClosedRange(IPv4Address(start), IPv4Address(end), str(asn))
