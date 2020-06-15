import unittest

from idn_domain_names.domain import Domain
from idn_domain_names.ipv4util import IpTable


class Ipv4UtilsTest(unittest.TestCase):
    def test_get_ip_for_unresolvable_domain(self):
        table = IpTable([])
        unresolvable_domain = Domain('unresolvable.domain.')
        self.assertIsNone(table.get_ip(unresolvable_domain))
