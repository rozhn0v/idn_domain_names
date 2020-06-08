import argparse
import csv
import gzip
import logging
import sys
from pathlib import Path
from typing import Iterator, List, Optional, Set, Union
from typing import Tuple

import grequests
from bs4 import BeautifulSoup

import ipv4util
from _io import TextIOWrapper
from domain import Domain
from ipv4util import Ipv4AWrapper

log = logging.getLogger(__name__)  # pylint: disable=invalid-name


def init_logger() -> None:
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="[%(asctime)s] %(process)d %(levelname)s %(message)s",
        datefmt='%H:%M:%S')
    file_handler = logging.FileHandler('phishing.log')
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    """
    Parse the command line parameters and options. The options are
    "domain-list",which is the path to the tsv file containinga list of domain
    names, "output" which is the path to the file to store the detection
    results and ipv4toasn, which is the path to the file containing the IPV4
    to ASN table, and the the phishingtargets, which is a tsv file containing
    the phishing targeted domains.

    Returns
    -------
    args : argparse.Namespace of str
        Contains the fields: domain_list, output_file, ipv4_table
        and phishing_targets, in that order.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d',
        '--domain-list',
        dest='domain_list',
        help='The path to the tsv file containing domains to be analyzed.',
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
    with gzip.open(filename, 'rt') as source:
        tsv_f = csv.reader(source, delimiter='\t')
        for line in tsv_f:
            domain = Domain(line[1] + '.')
            domain = domain.maybe_truncate_www()
            if domain.is_idna():
                domain = domain.to_unicode()
                result.add(domain)
    return result


def read_datafile(datafile: str) -> Iterator[Domain]:
    """
    Create a generator to the domain list to be classified.

    Parameters
    ----------
    datafile : str
        The path to the tsv file containing the list of domain names to be
        classified.

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


def write_to_list_or_file(domain: Domain, file: Optional[str],
                          is_phishing: bool) -> None:
    """
    Writes the domain and is_phishing value to a file in a csv (comma separated
    values) format, if file is given, if file is None, appends is_phishing
    to phishing_list list.

    Parameters
    ----------
    domain : str
        Domain name to write to file, if file is given.
    file : str or None
        If file is a str, i.e, a valid path to a file, the information will be
        written to a file, if None, the is_phishing value will be appended
        to phishing_list.
    is_phishing : bool
        Contains the information whether the given domain is a phishing
        candidate or not.
    """
    if file:
        with open(file, 'a+') as output:
            file_ext = file.split('.')[-1]
            if file_ext == 'csv':
                output.write('%s,%d\n' % (domain, int(is_phishing)))
            elif file_ext == 'tsv':
                output.write('%s\t%d\n' % (domain, int(is_phishing)))
            else:
                raise ValueError(
                    'Invalid file extension, use TSV or CSV file.')


def is_phishing_list(datafile: Union[str, TextIOWrapper],
                     ipv4_table: str,
                     phishing_targets_file: str,
                     file: Optional[str] = None) -> None:
    """
    Classify the provided domains in the datafile tsv file list which domains
    are suspicious to be a phishing domain from the phishing detection routine,
    if file is provided. If not, returns a list is_phishing_list containing
    the results.

    Parameters
    ----------
    datafile : str or sys.stdin
        The path to the datafile containing the list of domains
        to be investigated.
    ipv4_table: str
        The path for the ipv4 to asn table in the tsv format.
        It contains the fields, range_start, range_end,AS_number, country_code,
        AS_description, in that order.
    phishing_targets_file : str
        The path to the tsv containing the phishing targeted domains' list.
    file : str or None
        A valid file path in which to write the results of the phishing
        detection, in a csv (comma separated value) format. If None,
        the detection results will be written to is_phishing_list list.

    Returns
    -------
    is_phishing_list : list of int or None
        If a valid file path is provided, returns None and writes the results
        to a csv file defined in the global variable PHISHINGFILE, if None,
        returns a list containing the results of the detection routine.

    """
    phishing_targets = load_phishing_targets(phishing_targets_file)
    ip_table = ipv4util.load_ipv4_table(ipv4_table)
    _delete_if_present(file)
    domains_to_check = read_datafile(datafile)
    for domain in domains_to_check:
        if not domain.is_idna():
            continue

        domain_unicode, xn_idx = _index_and_convert_silently(domain)
        if (domain_unicode, xn_idx) == (None, None):
            continue
        assert domain_unicode is not None
        assert xn_idx is not None

        homoglyph_domains = domain_unicode.normalize_wrap(xn_idx)
        homoglyph_domains = phishing_targets.intersection(homoglyph_domains)
        false_true_counter = [0] * 2
        # If a domain is phishing, there possibly be more domains with
        # different ASN than the same. though, two domains could belong
        # to the same ASN and one could be phishing,
        # if the ASN is of a ISP (not explored)
        domain_ip, domain_asn = ip_table.get_ip_and_asn(domain)
        if domain_ip is None:
            log.debug('target %s is unresolvable, skip', domain)
            continue

        for homo_domain in homoglyph_domains:
            homoglyph_ip, homoglyph_asn = ip_table.get_ip_and_asn(homo_domain)
            if homoglyph_ip is None:
                log.debug('possible domain %s is unresolvable, skip',
                          homo_domain)
                continue

            if domain_asn is None or homoglyph_asn is None:
                false_true_counter[0] += 1
                continue
            if domain_asn == homoglyph_asn:
                false_true_counter[0] += 1
            else:
                domain_lang = domain_unicode.domain_language(xn_idx) or 'en'
                homo_lang = homo_domain.domain_language(xn_idx)
                (domain_html_lang, homo_html_lang) = _detect_html_languages(
                    domain_ip, homoglyph_ip)
                if domain_html_lang == homo_html_lang \
                        and domain_lang != homo_lang:
                    correct_dn_equal = domain_unicode.correct_accent_equal(
                        homo_domain, xn_idx)
                    if correct_dn_equal:
                        false_true_counter[0] += 1
                    else:
                        false_true_counter[1] += 1
                elif domain_html_lang == homo_html_lang \
                        and domain_lang == homo_lang:
                    false_true_counter[0] += 1
                elif domain_html_lang != homo_html_lang \
                        and domain_lang == homo_lang:
                    false_true_counter[1] += 1
                else:
                    false_true_counter[1] += 1
        is_phishing = false_true_counter[0] < false_true_counter[1]
        write_to_list_or_file(domain, file, is_phishing)


def _index_and_convert_silently(domain: Domain) -> Tuple[Optional[Domain],
                                                         Optional[List[int]]]:
    try:
        std_domain = domain.maybe_truncate_www()
        xn_idx = std_domain.punycode_idx()
        domain_unicode = std_domain.to_unicode()
        return domain_unicode, xn_idx
    except UnicodeError:
        log.debug('failed to convert %s, report as non-phishing', domain)
        return None, None


def _delete_if_present(file: Optional[str]):
    if file:
        file_obj = Path(file)
        if file_obj.exists():
            file_obj.unlink()


def _detect_html_languages(domain_ip, homoglyph_ip) -> Tuple[str, str]:
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
    domain_html_lang = domain_html_lang[:2].lower()
    homo_html_lang = homo_html_lang[:2].lower()
    return domain_html_lang, homo_html_lang


def _get_lang_by_ip(ip_address: Ipv4AWrapper) -> Optional[str]:
    request = [grequests.get('http://' + str(ip_address))]
    responses = grequests.map(request)
    response = responses[0]
    if response is None:
        log.debug('%s does not respond, return None', ip_address)
        return None
    soup = BeautifulSoup(response.content, 'html.parser')
    html = soup.html
    if html is None:
        log.debug('%s has no html, return none', ip_address)
        return None
    lang = html.get('lang')
    log.debug('lang of ip %s is %s', ip_address, lang)
    return lang


def main() -> None:
    init_logger()
    args = parse_args()
    is_phishing_list(args.domain_list, args.ipv4_table, args.phishing_targets,
                     args.output_file)


if __name__ == '__main__':
    main()
