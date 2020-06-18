from __future__ import annotations

import csv
import logging
import socket
from functools import lru_cache
from typing import List
from typing import Optional
from typing import Tuple

from ipaddress import IPv4Address

from idn_domain_names.domain import Domain

log = logging.getLogger('app')  # pylint: disable=invalid-name


class ClosedRange:
    def __init__(self, start: IPv4Address, end: IPv4Address, asn: str):
        self.start = start
        self.end = end
        self.asn = asn

    def contains(self, address: IPv4Address):
        return self.start <= address <= self.end

    def is_after(self, address: IPv4Address):
        return address < self.start

    def __lt__(self, other):
        return self.end < other.start

    def __str__(self) -> str:
        return '{[%s; %s] %s}' % (self.start, self.end, self.asn)


def load_ipv4_table(file_path: str) -> IpTable:
    """
    Loads the IPV4 to ASN table into a python list

    Parameters
    ----------
    file_path : str
        Path for the IPV4 to ASN table, the table has a tsv (tab separated
        value format, and contains the fields:  range_start, range_end,
        AS_number, country_code and AS_description, in the given order.
        The table originally used in the code was taken from
        https://iptoasn.com/.

    Returns
    -------
    ipv4_table : list of list of str
        The table mapped to a python list.
    """
    ipv4_table = []
    log.debug('start load ipv4 table from %s', file_path)
    with open(file_path, 'r') as csvfile:
        csv_obj = csv.reader(csvfile, delimiter='\t')
        for row in csv_obj:
            start = IPv4Address(row[0])
            end = IPv4Address(row[1])
            asn = row[2]
            ipv4_table.append(ClosedRange(start, end, asn))
    log.debug('loaded phishing table with size %s', len(ipv4_table))
    return IpTable(ipv4_table)


class IpTable:  # pylint: disable=too-few-public-methods
    def __init__(self, delegate: List[ClosedRange]):
        self._delegate = delegate
        self._delegate.sort()

    def get_ip_and_asn(self, hostname: Domain) -> \
            Tuple[Optional[IPv4Address], Optional[str]]:
        """
        Get the IP address and AS number of the given hostname.
        ASN number returns None if not found.

        Parameters
        ----------
        hostname : Domain
            The host/domain name.

        Returns
        -------
        ip_obj : ipaddress.IPv4Address
            A wrapper object for the ip address, with comparative operations,
            i.e., less-equal, equal, less, greater, greater-equal.
        asn : str or None
             AS number of the given hostname.
        """
        address = self.resolve_ip(hostname)
        if not address:
            return None, None
        asn = self.lookup_asn(address)
        if asn:
            return address, asn
        log.debug('failed to resolve asn for %s, ip %s', hostname, address)
        return address, None

    @lru_cache(maxsize=128)
    def resolve_ip(self, domain: Domain) \
            -> Optional[IPv4Address]:  # pylint: disable=no-self-use
        """
        Get the ip address of domain, wrapped in a Ipv4Wrapper object.

        Parameters
        ----------
        domain : Domain
            A Domain object which wraps an url.

        Returns
        -------
        None or Ipv4Wrapper
            The ip address of domain, wrapped in a Ipv4Wrapper object.
        """
        try:
            ip_address = socket.gethostbyname(str(domain))
            return IPv4Address(ip_address)
        except (socket.gaierror, UnicodeError):
            log.exception('failed to resolve %s', domain)
            return None

    def lookup_asn(self, elem: IPv4Address) -> Optional[str]:
        """
        Finds the equivalent Ipv4Wrapper element in a sorted list
        of Ipv4Wrapper objects.

        Parameters
        ----------
        elem : Ipv4AWrapper
            An Ipv4Wrapper object to be found its equivalent in the given list.

        Returns
        -------
        None or Ipv4Wrapper
            The Ipv4Wrapper if its found in the list or None, otherwise.
        """
        arr_len = len(self._delegate)
        low = 0
        high = arr_len - 1
        mid = int((high + low) / 2)
        while low <= high:
            if self._delegate[mid].contains(elem):
                return self._delegate[mid].asn
            if self._delegate[mid].is_after(elem):
                high = mid - 1
            else:
                low = mid + 1
            mid = int((high + low) / 2)
        return None
