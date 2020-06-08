from __future__ import annotations

import csv
import ipaddress
from ipaddress import IPv4Address
from typing import List
from typing import Optional
from typing import Tuple

from domain import Domain


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
            if not self._begin <= self._end:
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
        elif not self._ip and rhs._ip:
            return self._begin <= rhs._ip <= self._end
        elif self._ip and not rhs._ip:
            return rhs._begin <= self._ip <= rhs._end
        else:
            return self._ip == rhs._ip

    def __lt__(self, rhs):
        if not self._ip and not rhs._ip:
            return self._end < rhs._begin
        elif not self._ip and rhs._ip:
            return self._begin < rhs._ip
        elif self._ip and not rhs._ip:
            return self._ip < rhs._begin
        else:
            return self._ip < rhs._ip

    def __le__(self, rhs):
        if not self._ip and not rhs._ip:
            return self._end <= rhs._begin
        elif not self._ip and rhs._ip:
            return self._begin <= rhs._ip
        elif self._ip and not rhs._ip:
            return self._ip <= rhs._begin
        else:
            return self._ip <= rhs._ip

    def __str__(self):
        if not self._ip:
            return str(self._begin) + ' - ' + str(self._end)
        else:
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
    def ip(self):
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


class IpTable:
    def __init__(self, delegate: List[Ipv4AWrapper]):
        self._delegate = delegate

    def get_ip_and_asn(self,
                       hostname: Domain) -> Tuple[Ipv4AWrapper, Optional[str]]:
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
        ip = hostname.get_ip()
        ip_obj = Ipv4AWrapper(single_ip=ipaddress.IPv4Address(ip))
        match_obj = self._search(ip_obj)
        if match_obj:
            return ip_obj, match_obj.asn
        else:
            return ip_obj, None

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
            elif self._delegate[mid] > elem:
                high = mid - 1
            else:
                low = mid + 1
            mid = int((high + low) / 2)
        return None
