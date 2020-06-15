from __future__ import annotations

import csv
import ipaddress
import logging
import socket
from functools import lru_cache
from ipaddress import IPv4Address
from typing import List, Optional, Tuple

from idn_domain_names.domain import Domain

log = logging.getLogger('app')  # pylint: disable=invalid-name


class Ipv4AWrapper:
    """
    A wrapper to IPv4Address, it facilitates the comparison of ip addresses and
    ASN assigned entities in order to find the corresponding AS numbers
    """

    def __init__(self,
                 range_begin=None,
                 range_end=None,
                 as_number=None,
                 country=None,
                 single_ip=None):
        if not single_ip:
            self._begin = IPv4Address(range_begin)
            self._end = IPv4Address(range_end)
            if self._begin > self._end:
                raise ValueError(
                    'range_begin must be less or equal than range_end.')
            self._asn = as_number
            self._country = country
            self._ip = None
        else:
            self._begin = None
            self._end = None
            self._asn = None
            self._ip = IPv4Address(single_ip)

    def __eq__(self, rhs):
        if not self._ip and not rhs._ip:
            return self._begin == rhs._begin and self._end == rhs._end
        if not self._ip and rhs._ip:
            return self._begin <= rhs._ip <= self._end
        if self._ip and not rhs._ip:
            return rhs._begin <= self._ip <= rhs._end
        return self._ip == rhs._ip

    def __lt__(self, rhs):
        if not self._ip and not rhs._ip:
            return self._end < rhs._begin
        if not self._ip and rhs._ip:
            return self._begin < rhs._ip
        if self._ip and not rhs._ip:
            return self._ip < rhs._begin
        return self._ip < rhs._ip

    def __le__(self, rhs):
        if not self._ip and not rhs._ip:
            return self._end <= rhs._begin
        if not self._ip and rhs._ip:
            return self._begin <= rhs._ip
        if self._ip and not rhs._ip:
            return self._ip <= rhs._begin
        return self._ip <= rhs._ip

    def __str__(self):
        if not self._ip:
            return str(self._begin) + ' - ' + str(self._end)
        return str(self._ip)

    @property
    def asn(self):
        return self._asn

    @property
    def range_begin(self):
        return self._begin

    @property
    def range_end(self):
        return self._end

    @property
    def country(self):
        return self._country

    @property
    def ip(self):  # pylint: disable=invalid-name
        return self._ip


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
    print('start load ipv4 table from {}'.format(file_path))
    with open(file_path, 'r') as csvfile:
        csv_obj = csv.reader(csvfile, delimiter='\t')
        for row in csv_obj:
            ip_wrapper_obj = Ipv4AWrapper(*row[:4])
            ipv4_table.append(ip_wrapper_obj)
    ipv4_table.sort()
    print('loaded phishing table with size {}'.format(len(ipv4_table)))
    return IpTable(ipv4_table)


class IpTable:  # pylint: disable=too-few-public-methods
    def __init__(self, delegate: List[Ipv4AWrapper]):
        self._delegate = delegate

    def get_ip_and_asn(self, hostname: Domain) -> \
            Tuple[Optional[Ipv4AWrapper], Optional[str]]:
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
        address = self.get_ip(hostname)
        if not address:
            return None, None
        ip_obj = Ipv4AWrapper(single_ip=ipaddress.IPv4Address(address))
        match_obj = self._search(ip_obj)
        if match_obj:
            return ip_obj, match_obj.asn
        log.debug('failed to resolve asn for %s, ip %s', hostname, ip_obj)
        return ip_obj, None

    @lru_cache(maxsize=128)
    def get_ip(self, domain: Domain) \
            -> Optional[Ipv4AWrapper]:  # pylint: disable=no-self-use
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
            return Ipv4AWrapper(single_ip=ip_address)
        except (socket.gaierror, UnicodeError):
            log.exception('failed to resolve %s', domain)
            return None

    def _search(self, elem: Ipv4AWrapper) -> Optional[Ipv4AWrapper]:
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
            if self._delegate[mid] == elem:
                return self._delegate[mid]
            if self._delegate[mid] > elem:
                high = mid - 1
            else:
                low = mid + 1
            mid = int((high + low) / 2)
        return None
