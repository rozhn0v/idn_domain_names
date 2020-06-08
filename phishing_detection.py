import argparse
import csv
import gzip
import ipaddress
import logging
import re
import socket
import sys
import time
from _io import TextIOWrapper
from pathlib import Path
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union

import grequests
import requests
from bs4 import BeautifulSoup

from domain import Domain
from ipv4util import Ipv4AWrapper
from ipv4util import binary_search_ip

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)
formatter = logging.Formatter(
    fmt="[%(asctime)s] %(process)d %(levelname)s %(message)s",
    datefmt='%H:%M:%S')
file_handler = logging.FileHandler('phishing.log')
file_handler.setFormatter(formatter)
log.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    """
    Parse the command line parameters and options.The options are "domain-list", which is the path to the
    tsv file containinga list of domain names, "output" which is the path to the file to store the
    detection results and ipv4toasn, which is the path to the file containing the IPV4 to ASN table, and the
    the phishingtargets, which is a tsv file containing the phishing targeted domains.

    Returns
    -------
    args : argparse.Namespace of str
        Contains the fields: domain_list, output_file, ipv4_table and phishing_targets, in that order.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d',
        '--domain-list',
        dest='domain_list',
        help=
        'The path to the file containing the list of domain to be analyzed (TSV format).',
        type=str,
        default=sys.stdin)
    parser.add_argument(
        '-o',
        '--output',
        dest='output_file',
        help='The path in which the output file will be created.',
        type=str,
        required=True)
    parser.add_argument('-i',
                        '--ipv4-to-asn',
                        dest='ipv4_table',
                        help='The path to the IPV4 to ASN table (TSV format).',
                        type=str,
                        required=True)

    parser.add_argument('-p',
                        '--phishing-targets',
                        dest='phishing_targets',
                        help='The path to the phishing target\'s list.',
                        type=str,
                        required=True)

    return parser.parse_args()


def load_phishing_targets(filename: str) -> Set[Domain]:
    """
    Creates a generator to the zipped phishing target list (tsv format).

    Parameters
    ----------
    filename : str
        The path to the zipped phishing target list.

    Returns
    -------
    Generator of the phishing target list.
    """
    result = set()
    with gzip.open(filename, 'rt') as f:
        tsv_f = csv.reader(f, delimiter='\t')
        for line in tsv_f:
            domain = Domain(line[1] + '.')
            domain = domain.maybe_truncate_www()
            if domain.is_idna():
                domain = domain.to_idna()
                result.add(domain)
    return result


def read_datafile(datafile: str) -> Iterator[Domain]:
    """
    Create a generator to the domain list to be classified.

    Parameters
    ----------
    datafile : str
        The path to the tsv file containing the list of domain names to be classified.

    Returns
    -------
    A generator for the domain list.
    """
    if isinstance(datafile, str):
        domain_list_file = open(datafile, 'r')
        domain_list_tsv = csv.reader(domain_list_file, delimiter='\t')
    else:
        domain_list_file = datafile
        domain_list_tsv = csv.reader(domain_list_file, delimiter='\t')
    for line in domain_list_tsv:
        yield Domain(line[0])


def load_ipv4_table(file_path: str) -> List[Ipv4AWrapper]:
    """
    Loads the IPV4 to ASN table into a python list

    Parameters
    ----------
    file_path : str
        Path for the IPV4 to ASN table, the table has a tsv (tab separated value format,
        and contains the fields:  range_start, range_end, AS_number, country_code and AS_description,
        in the given order. The table originally used in the code was taken from https://iptoasn.com/.

    Returns
    -------
    ipv4_table : list of list of str
        The table mapped to a python list.
    """
    ipv4_table = []
    with open(file_path, 'r') as csvfile:
        csv_obj = csv.reader(csvfile, delimiter='\t')
        for row in csv_obj:
            ip_wrapper_obj = Ipv4AWrapper(*row[:4])
            ipv4_table.append(ip_wrapper_obj)
    ipv4_table.sort()
    return ipv4_table


def get_ip_and_asn(hostname: Domain, ipv4_table: List[Ipv4AWrapper]) \
        -> Tuple[Ipv4AWrapper, Optional[str], Optional[str]]:
    """
    Get the IP address and AS number of the given hostname. ASN number returns None if not found.

    Parameters
    ----------
    hostname : Domain
        The host/domain name.
    ipv4_table : list of list of str
        The IPV4 to ASN table in the list format. In the order: [:][0] - range_start,
        [:][1] - range_end, [:][2] - AS_number, [:][3] - country_code, [:][4] - AS_description.

    Returns
    -------
    ip_obj : ipaddress.IPv4Address
        A wrapper object for the ip address, with comparative operations, i.e., less-equal,
        equal, less, greater, greater-equal.
    asn : str or None
         AS number of the given hostname.
    """
    ip = hostname.get_ip()
    ip_obj = Ipv4AWrapper(single_ip=ipaddress.IPv4Address(ip))
    match_obj = binary_search_ip(ipv4_table, ip_obj)
    if match_obj:
        return ip_obj, match_obj.asn, match_obj.country
    else:
        return ip_obj, None, None


def write_to_list_or_file(domain: Domain, phishing_list: List[int],
                          file: Optional[str], is_phishing: bool) -> None:
    """
    Writes the domain and is_phishing value to a file in a csv (comma separated values) format, if file is given,
    if file is None, appends is_phishing to phishing_list list.

    Parameters
    ----------
    domain : str
        Domain name to write to file, if file is given.
    phishing_list : list of int
        A list where the is_phishing value will be appended.
    file : str or None
        If file is a str, i.e, a valid path to a file, the information will be written to a file,
        if None, the is_phishing value will be appended to phishing_list.
    is_phishing : bool
        Contains the information whether the given domain is a phishing candidate or not.
    """
    if file:
        with open(file, 'a+') as f:
            file_ext = file.split('.')[-1]
            if file_ext == 'csv':
                f.write('%s,%d\n' % (domain, int(is_phishing)))
            elif file_ext == 'tsv':
                f.write('%s\t%d\n' % (domain, int(is_phishing)))
            else:
                raise ValueError(
                    'Invalid file extension, use TSV or CSV file.')
    else:
        phishing_list.append(int(is_phishing))


def is_phishing_list(datafile: Union[str, TextIOWrapper],
                     ipv4_table: str,
                     phishing_targets_file: str,
                     file: Optional[str] = None) -> Optional[List[int]]:
    """
    Classify the provided domains in the datafile tsv file list which domains are suspicious to be a phishing domain
    from the phishing detection routine, if file is provided. If not, returns a list is_phishing_list
    containing the results.

    Parameters
    ----------
    datafile : str or sys.stdin
        The path to the datafile containing the list of domains to be investigated.
    ipv4_table: str
        The path for the ipv4 to asn table in the tsv format. It contains the fields, range_start, range_end,
        AS_number, country_code, AS_description, in that order.
    phishing_targets_file : str
        The path to the tsv containing the phishing targeted domains' list.
    file : str or None
        A valid file path in which to write the results of the phishing detection, in a csv
        (comma separated value) format. If None, the detection results will be written to
        is_phishing_list list.

    Returns
    -------
    is_phishing_list : list of int or None
        If a valid file path is provided, returns None and writes the results to a csv file
        defined in the global variable PHISHINGFILE, if None, returns a list containing the results of the
        detection routine.

    """
    begin = time.time()
    phishing_targets = load_phishing_targets(phishing_targets_file)
    ipv4_to_asn_table = load_ipv4_table(ipv4_table)
    is_phishing_table = []
    _delete_if_present(file)
    domains_to_check = read_datafile(datafile)
    for domain in domains_to_check:
        if domain.is_idna():
            try:
                std_domain = domain.maybe_truncate_www()
                xn_idx = std_domain.punycode_idx()
                domain_unicode = std_domain.to_idna()
            except (UnicodeError, IndexError) as e:
                write_to_list_or_file(domain, is_phishing_table, file, False)
                log.error('KNOWNERROR({}): Domain: {}'.format(
                    type(e).__name__, domain))
                continue
            except Exception as e:
                write_to_list_or_file(domain, is_phishing_table, file, False)
                log.error('UNKERROR({}): Domain: {}'.format(
                    type(e).__name__, domain))
                continue
        else:
            write_to_list_or_file(domain, is_phishing_table, file, False)
            continue
        homoglyph_domains = domain_unicode.normalize_wrap(xn_idx)
        homoglyph_domains = phishing_targets.intersection(homoglyph_domains)
        false_true_counter = [0] * 2
        # If a domain is phishing, there possibly be more domains with different ASN than the same.
        # though, two domains could belong to the same ASN and one could be phishing,
        # if the ASN is of a ISP (not explored)
        for homo_domain in homoglyph_domains:
            try:
                domain_ip, domain_asn, _ = get_ip_and_asn(
                    domain, ipv4_to_asn_table)
            except (socket.gaierror, ipaddress.AddressValueError) as e:
                log.error('KNOWNERROR({}): Domain: {}'.format(
                    type(e).__name__, domain))
                write_to_list_or_file(domain, is_phishing_table, file,
                                      False)  # False or true ?
                continue
            try:
                homoglyph_ip, homoglyph_asn, _ = get_ip_and_asn(
                    homo_domain, ipv4_to_asn_table)
            except (socket.gaierror, ipaddress.AddressValueError) as e:
                log.error('KNOWNERROR({}): Homoglyph: {}'.format(
                    type(e).__name__, homo_domain))
                continue
            if domain_asn is None or homoglyph_asn is None:
                false_true_counter[0] += 1
                continue
            if domain_asn == homoglyph_asn:
                false_true_counter[0] += 1
            else:
                domain_lang = domain_unicode.domain_language(xn_idx) or 'en'
                homo_lang = homo_domain.domain_language(xn_idx)
                try:
                    domain_html_lang = _get_lang_by_ip(domain_ip)
                    homo_html_lang = _get_lang_by_ip(homoglyph_ip)
                    if domain_html_lang is None:
                        if homo_html_lang is not None:
                            domain_html_lang = homo_html_lang
                        else:
                            domain_html_lang = homo_html_lang = 'en'
                    else:
                        if homo_html_lang is None:
                            homo_html_lang = domain_html_lang
                    domain_html_lang = re.search(
                        r'[a-zA-Z]{2}', domain_html_lang).group(0).lower()
                    homo_html_lang = re.search(
                        r'[a-zA-Z]{2}', homo_html_lang).group(0).lower()
                except (AttributeError,
                        requests.exceptions.ConnectionError) as e:
                    log.error(
                        'KNOWNERROR({}): Domain: {} - Homoglyph: {}'.format(
                            type(e).__name__, domain, homo_domain))
                    false_true_counter[0] += 1
                    continue
                if domain_html_lang == homo_html_lang and domain_lang != homo_lang:
                    correct_dn_equal = domain_unicode.correct_accent_equal(
                        homo_domain, xn_idx)
                    if correct_dn_equal:
                        false_true_counter[0] += 1
                    else:
                        false_true_counter[1] += 1
                elif domain_html_lang == homo_html_lang and domain_lang == homo_lang:
                    false_true_counter[0] += 1
                elif domain_html_lang != homo_html_lang and domain_lang == homo_lang:
                    false_true_counter[1] += 1
                else:
                    false_true_counter[1] += 1
        is_phishing = false_true_counter[0] < false_true_counter[1]
        write_to_list_or_file(domain, is_phishing_table, file, is_phishing)
    print('Total time: %.5f' % (time.time() - begin))
    if file:
        return None
    else:
        return is_phishing_table


def _delete_if_present(file: Optional[str]):
    if file:
        file_obj = Path(file)
        if file_obj.exists():
            file_obj.unlink()


def _get_lang_by_ip(ip: Ipv4AWrapper) -> Optional[str]:
    request = grequests.get('http://' + str(ip))
    responses = grequests.map(request)
    response = responses[0]
    soup = BeautifulSoup(response.content, 'html.parser')
    html = soup.declared_html_encoding
    return html.get('lang')


def main():
    args = parse_args()
    is_phishing_list(args.domain_list, args.ipv4_table, args.phishing_targets,
                     args.output_file)


if __name__ == '__main__':
    main()
