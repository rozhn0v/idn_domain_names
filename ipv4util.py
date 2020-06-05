from ipaddress import IPv4Address
from typing import List
from typing import Optional


class Ipv4AWrapper:
    """
    A wrapper to IPv4Address, it facilitates the comparison of ip addresses and ASN assigned entities
    in order to find the corresponding AS numbers
    """

    def __init__(self, range_begin=None, range_end=None, as_number=None, country=None, single_ip=None):
        if not single_ip:
            self._begin = IPv4Address(range_begin)
            self._end = IPv4Address(range_end)
            if not self._begin <= self._end:
                raise ValueError('range_begin must be less or equal than range_end.')
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


def binary_search_ip(sorted_list: List[Ipv4AWrapper], elem: Ipv4AWrapper) -> Optional[Ipv4AWrapper]:
    """
    Finds the equivalent Ipv4Wrapper element in a sorted list of Ipv4Wrapper objects.

    Parameters
    ----------
    sorted_list : List of Ipv4Wrapper objects
        A sorted list of Ipv4Wrapper objects.
    elem : Ipv4AWrapper
        An Ipv4Wrapper object to be found its equivalent in the given list.

    Returns
    -------
    None or Ipv4Wrapper
        The Ipv4Wrapper if its found in the list or None, otherwise.
    """
    arr_len = len(sorted_list)
    low = 0
    high = arr_len - 1
    mid = int((high + low) / 2)
    while low <= high:
        if sorted_list[mid] == elem:
            return sorted_list[mid]
        elif sorted_list[mid] > elem:
            high = mid - 1
        else:
            low = mid + 1
        mid = int((high + low) / 2)
    return None
