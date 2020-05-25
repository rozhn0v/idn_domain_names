import socket
import csv
import ipaddress
import re
import argparse
import sys
import requests
from confusables import normalize
from itertools import product
from pathlib import Path
from typing import Tuple, List, Optional, Iterator
from collections import Counter
from bs4 import BeautifulSoup
from textblob import TextBlob, exceptions
from langdetect import detect
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format = "[%(asctime)s] %(process)d %(levelname)s %(message)s",
    datefmt = "%H:%M:%S"
)
log = logging.getLogger(__name__)


def parse_args() -> Tuple[str, str, str]:
    """
    Parse the command line parameters and options.The parameter is domain_list, which is the path to the TSV file
    containing a list of domain names.The options are "output" which is the path to the file to store the
    detection results and ipv4toasn, which is the path to the file containing the IPV4 to ASN table.

    Returns
    -------
    datafile: str
        The path to the tsv file containing the list of domain names in the first field.
    ipv4_to_asn_table: str
        The path to the tsv file containing the IPV4 to ASN table, the fields are range_start, range_end,
        AS_number, country_code and AS_description, in that order.
    phishing_file: str
        The path in which to write the csv file with the phishing detection results.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('domain_list',
                        help='The path to the file containing the list of domain to be analyzed (TSV format).',
                        type=str, default=sys.stdin)
    parser.add_argument('-o', '--output', dest='output_file',
                        help='The path in which the output file will be created.',
                        type=str, required=True)
    parser.add_argument('-i', '--ipv4toasn', dest='ipv4_table',
                        help='The path to the IPV4 to ASN table (TSV format).',
                        type=str, required=True)

    args = parser.parse_args()

    datafile = args.domain_list
    ipv4_to_asn_table = args.ipv4_table
    phishing_file = args.output_file

    return datafile, ipv4_to_asn_table, phishing_file


def load_ipv4_table(file_path: str) -> List[List[str]]:
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
            ipv4_table.append(row)
    return ipv4_table


def get_ip_and_asn(hostname: str, ipv4_table: List[List[str]]) \
        -> Tuple[ipaddress.IPv4Address, Optional[str], Optional[str]]:
    """
    Get the IP address and AS number of the given hostname. ASN number returns None if not found.

    Parameters
    ----------
    hostname : str
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
    ip = socket.gethostbyname(hostname)
    ip_obj = ipaddress.IPv4Address(ip)
    asn = None
    country = None
    for row in ipv4_table:
        ip_start = ipaddress.IPv4Address(row[0])
        ip_end = ipaddress.IPv4Address(row[1])
        if ip_start <= ip_obj <= ip_end:
            asn = row[2]
            country = row[3]
    return ip_obj, asn, country


def write_to_list_or_file(domain: str, is_phishing_list: List[int], file: Optional[str], is_phishing: bool) -> None:
    """
    Writes the domain and is_phishing value to a file in a csv (comma separated values) format, if file is given,
    if file is None, appends is_phishing to is_phishing_list list.

    Parameters
    ----------
    domain : str
        Domain name to write to file, if file is given.
    is_phishing_list : list of int
        A list where the is_phishing value will be appended.
    file : str or None
        If file is a str, i.e, a valid path to a file, the information will be written to a file,
        if None, the is_phishing value will be appended to is_phishing_list.
    is_phishing : bool
        Contains the information whether the given domain is a phishing candidate or not.
    """
    if file:
        with open(file, 'a+') as f:
            f.write('%s,%d\n' % (domain, int(is_phishing)))
    else:
        is_phishing_list.append(int(is_phishing))


def punycode_idx(dn: str) -> List[int]:
    """
    Generates a list containing the indexes of the valid punycode in the domain name,
    considering the '.' (dot) as a field separator.

    Parameters
    ----------
    dn : str
        A valid domain name.

    Returns
    -------
    xn_list : list of int
        A list containing the indexes of the domain name, in a dot-separated fashion, where
        valid punycode can be found.
    """
    dn_split = dn.split('.')
    xn_list = []
    for i, part in enumerate(dn_split):
        if 'xn--' in part:
            xn_list.append(i)
    return xn_list


def normalize_wrap(dn_unicode: str, xn_idx: List[int]) -> Iterator[str]:
    """
    Generator to a series of possible confusion domain names for the given dn_unicode.

    Parameters
    ----------
    dn_unicode : str
        Domain name in the unicode format.
    xn_idx : list of int
        Indexes of the valid punycode, considering the dot as a field separator.

    Returns
    -------
    An iterator of the possible confusions for the given dn_unicode, domain name.
    """
    dn_split = dn_unicode.split('.')
    for i in xn_idx:
        dn_split[i] = normalize(dn_split[i])
    dn_split = map(lambda x: x if isinstance(x, list) else [x], dn_split)
    dn_iter = map(lambda x: '.'.join(x), product(*dn_split))
    for dn in dn_iter:
        if dn != dn_unicode:
            yield dn


def domain_language(dn_unicode: str, xn_idx: List[int]) -> Optional[str]:
    """
    Returns the most probable language of the given dn_unicode domain name.

    Parameters
    ----------
    dn_unicode : str
        Domain name in the unicode format.
    xn_idx : list of int
        Indexes of the valid punycode, considering the dot as a field separator.

    Returns
    -------
    domain_language : str
        The most occurring language in the domain name, with a penallty to english
        language.

    """
    dn_list = dn_unicode.split('.')
    lang_counter = Counter()
    for idx in xn_idx:
        try:
            lang_opts = (TextBlob(dn_list[idx]).detect_language(), detect(dn_list[idx]))
            lang = None
            for lang_opt in lang_opts:
                if lang_opt != 'en':
                    lang = lang_opt
                    break
            if lang is None:
                lang = 'en'
            lang_counter[lang] += 1
        except exceptions.TranslatorError:
            continue
    if len(lang_counter) > 1:
        most_common_lang = lang_counter.most_common(2)
        if most_common_lang[0][0] == 'en':
            return most_common_lang[1][0]
        else:
            return most_common_lang[0][0]
    elif len(lang_counter) == 1:
        return lang_counter.most_common()[0][0]
    else:
        return None


def is_phishing_list(dn_list: List[str], ipv4_to_asn_table: str, file: Optional[str] = None) -> Optional[List[int]]:
    """
    Writes to a csv file, defined by the global variable PHISHINGFILE, the results
    from the phishing detection routine, if file is provided. If not, returns a list
    is_phishing_list containing the results.

    Parameters
    ----------
    dn_list : list of str
         List of ascii domain names, containing punycode and possible phishing candidates.
    ipv4_to_asn_table: str
        The path for the ipv4 to asn table in the tsv format. It contains the fields, range_start, range_end,
        AS_number, country_code, AS_description, in that order.
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
    dn_set = set()
    for dn in dn_list:
        if 'xn--' in dn:
            try:
                dn_set.add(dn.encode('ascii').decode('idna'))
            except (UnicodeError, IndexError):
                pass
            except Exception:
                pass
        else:
            dn_set.add(dn)
    is_phishing_table = []
    ipv4_to_asn = load_ipv4_table(ipv4_to_asn_table)
    if file:
        file_obj = Path(file)
        if file_obj.exists():
            file_obj.unlink()
    for domain in dn_list:
        if 'xn--' in domain:
            try:
                xn_idx = punycode_idx(domain)
                domain_unicode = domain.encode('ascii').decode('idna')
            except (UnicodeError, IndexError):
                write_to_list_or_file(domain, is_phishing_table, file, False)
                log.error('Problematic domain:KNOWERROR: {}'.format(domain))
                continue
            except Exception as e:
                log.error('Problematic domain:UNKERROR({}): {}'.format(type(e).__name__, domain))
                pass
        else:
            write_to_list_or_file(domain, is_phishing_table, file, False)
            continue
        try:
            homoglyphs_set = set(normalize_wrap(domain_unicode, xn_idx))
        except ValueError:
            homoglyphs_set = set()
        homoglyphs_set = dn_set.intersection(homoglyphs_set)
        false_true_counter = [0] * 2
        # If a domain is phishing, there possibly be more domains with different ASN than the same.
        # though, two domains could belong to the same ASN and one could be phishing,
        # if the ASN is of a ISP (not explored)
        for homo_domain in homoglyphs_set:
            try:
                _, domain_asn, _ = get_ip_and_asn(domain, ipv4_to_asn)
                _, homoglyph_asn, _ = get_ip_and_asn(homo_domain, ipv4_to_asn)
            except (socket.gaierror, ipaddress.AddressValueError):
                continue
            # TODO: How to reduce false positives ?
            if domain_asn is None or homoglyph_asn is None:
                false_true_counter[0] += 1
                continue
            if domain_asn == homoglyph_asn:
                false_true_counter[0] += 1
            else:
                url_lang = domain_language(domain_unicode, xn_idx)
                if url_lang is None:
                    url_lang = 'en'
                try:
                    domain_lang = BeautifulSoup(
                        requests.get('http://' + domain).content, 'html.parser').html.get('lang')
                    homo_lang = BeautifulSoup(
                        requests.get('http://' + homo_domain).content, 'html.parser').html.get('lang')
                    if domain_lang is None:
                        if homo_lang is not None:
                            domain_lang = homo_lang
                        else:
                            domain_lang = homo_lang = 'en'
                    else:
                        if homo_lang is None:
                            homo_lang = domain_lang
                    domain_lang = re.search(r'[a-zA-Z]{2}', domain_lang).group(0).lower()
                    homo_lang = re.search(r'[a-zA-Z]{2}', homo_lang).group(0).lower()
                except (AttributeError, requests.exceptions.ConnectionError):
                    false_true_counter[1] += 1
                    continue
                if url_lang == domain_lang and domain_lang == homo_lang \
                        and domain_lang != 'en':
                    false_true_counter[0] += 1
                else:
                    false_true_counter[1] += 1

        if false_true_counter[0] >= false_true_counter[1]:
            is_phishing = False
        else:
            is_phishing = True
        write_to_list_or_file(domain, is_phishing_table, file, is_phishing)

    if file:
        return None
    else:
        return is_phishing_table


def main():
    datafile, ipv4_to_asn_table, phishing_file = parse_args()
    dn_list = []
    if isinstance(datafile, str):
        with open(datafile, 'r') as f:
            f_tsv = csv.reader(f, delimiter='\t')
            for domain in f_tsv:
                domain = domain[0].rstrip('\n')
                dn_list.append(domain)
    else:
        f_tsv = csv.reader(datafile, delimiter='\t')
        for domain in f_tsv:
            domain = domain[0].rstrip('\n')
            dn_list.append(domain)

    is_phishing_list(dn_list, ipv4_to_asn_table, phishing_file)


if __name__ == '__main__':
    main()
