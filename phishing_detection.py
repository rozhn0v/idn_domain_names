import argparse
import csv
import gzip
import logging
import sys
import time
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

import grequests
from bs4 import BeautifulSoup

import ipv4util
from domain import Domain
from ipv4util import Ipv4AWrapper

log = logging.getLogger('app')  # pylint: disable=invalid-name


def init_logger() -> None:
    """
    Configure the global log object.
    """
    log.setLevel(logging.ERROR)
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


def dump_result(domain: Domain, file_path: str,
                is_phishing: bool) -> None:
    """
    Writes the domain and is_phishing value to a file in a csv (comma separated
    values) format, if file is given, if file is None, appends is_phishing
    to phishing_list list.

    Parameters
    ----------
    domain : str
        Domain name to write to file, if file is given.
    file_path : str
        the information will be written to a file
    is_phishing : bool
        Contains the information whether the given domain is a phishing
        candidate or not.
    """
    if not is_phishing:
        return
    with open(file_path, 'a+') as output:
        file_ext = file_path.split('.')[-1]
        if file_ext == 'csv':
            output.write('%s,%d\n' % (domain, int(is_phishing)))
        elif file_ext == 'tsv':
            output.write('%s\t%d\n' % (domain, int(is_phishing)))
        else:
            raise ValueError(
                'Invalid file_path extension, use TSV or CSV file_path.')


def detect_phishing(domains_to_check: Iterator[Domain],
                    ip_table: ipv4util.IpTable,
                    phishing_targets: Set[Domain],
                    path_to_output: str) -> None:
    """
    Classify the provided domains in the datafile tsv file list which domains
    are suspicious to be a phishing domain from the phishing detection routine,
    if file is provided. If not, returns a list is_phishing_list containing
    the results.

    Parameters
    ----------
    domains_to_check: iterable of possible phishing domains
    ip_table: ipv4util.IpTable
        table of IPs and ASNs
    phishing_targets : Set[Domains]
        set of phishing targets
    path_to_output : str
        A valid file path in which to write the results of the phishing
        detection, in a csv (comma separated value) format.

    Returns
    -------
    is_phishing_list : list of int or None
        If a valid file path is provided, returns None and writes the results
        to a csv file defined in the global variable PHISHINGFILE, if None,
        returns a list containing the results of the detection routine.

    """
    for domain in domains_to_check:
        if not domain.is_idna():
            continue

        domain_unicode = _to_unicode_or_none(domain)
        if domain_unicode is None:
            continue
        assert domain_unicode is not None

        domain_ip, domain_asn = ip_table.get_ip_and_asn(domain)
        if domain_ip is None or domain_asn is None:
            log.debug('target %s is unresolvable, skip', domain)
            continue

        # If a domain is phishing, there possibly be more domains with
        # different ASN than the same. though, two domains could belong
        # to the same ASN and one could be phishing,
        # if the ASN is of a ISP (not explored)
        false_true_counter = 0
        homoglyph_domains = domain_unicode.generate_possible_confusions()
        homoglyph_domains = phishing_targets.intersection(homoglyph_domains)
        for homo_domain in homoglyph_domains:
            homoglyph_ip, homoglyph_asn = ip_table.get_ip_and_asn(homo_domain)
            if homoglyph_ip is None or homoglyph_asn is None:
                log.debug('domain %s is unresolvable, skip', homo_domain)
                continue
            if domain_asn == homoglyph_asn:
                false_true_counter += 1
            else:
                false_true_counter += _language_check(domain_unicode,
                                                      homo_domain, ip_table)
        is_phishing = false_true_counter < 0
        dump_result(domain, path_to_output, is_phishing)


def _language_check(domain_unicode: Domain, homo_domain: Domain,
                    ip_table: ipv4util.IpTable) -> int:
    """
    Check if the languages for the domain_unicode and homo_domain, and its
    html are potentially the same.

    Parameters
    ----------
    domain_unicode : Domain
        Domain object containing the url of the domain to be checked against
        its homoglyph.
    homo_domain : Domain
        Domain object containing the homoglyph url of the "domain_unicode"
        object.

    Returns
    -------
    1 or -1 : int
        1 if the languages of the domains and its html match, -1 if not.
    """
    domain_ip = ip_table.get_ip(domain_unicode)
    assert domain_ip is not None
    homo_ip = ip_table.get_ip(homo_domain)
    assert homo_ip is not None

    (domain_html_lang, homo_html_lang) = _detect_html_languages(
        domain_ip, homo_ip)
    false_true_counter = 0
    domain_lang = domain_unicode.domain_language() or 'en'
    homo_lang = homo_domain.domain_language()
    if domain_html_lang == homo_html_lang and domain_lang != homo_lang:
        correct_dn_equal = domain_unicode.correct_accent_equal(homo_domain)
        if correct_dn_equal:
            false_true_counter += 1
        else:
            false_true_counter -= 1
    elif domain_html_lang == homo_html_lang and domain_lang == homo_lang:
        false_true_counter += 1
    elif domain_html_lang != homo_html_lang and domain_lang == homo_lang:
        false_true_counter -= 1
    else:
        false_true_counter -= 1
    return false_true_counter


def _to_unicode_or_none(domain: Domain) -> Optional[Domain]:
    """
    Returns the converted idn domain, from punycode to unicode. Returns None
    if an invalid punycode is given.

    Parameters
    ----------
    domain : Domain
        A Domain object which encapsulates the domain string.

    Returns
    -------
    Domain or None
        A Domain object which encapsulates the unicode version of the given
        Domain, or None.
    """
    try:
        std_domain = domain.maybe_truncate_www()
        return std_domain.to_unicode()
    except UnicodeError:
        log.debug('failed to convert %s, report as non-phishing', domain)
        return None


def _delete_if_present(path: str):
    """
    Check if the file of the given path exists, if it does, it's deleted.

    Parameters
    ----------
    path : str
        A path to a file.
    """
    file_obj = Path(path)
    if file_obj.exists():
        file_obj.unlink()


def _detect_html_languages(domain_ip: Ipv4AWrapper,
                           homoglyph_ip: Ipv4AWrapper) -> Tuple[str, str]:
    """
    Requests the html of the given ip addresses, wrapped in a Ipv4Wrapper
    object, and returns the "lang" attribute of them.

    Parameters
    ----------
    domain_ip : Ipv4Wrapper
        The Ipv4Wrapper object for the domain ip.
    homoglyph_ip : Ipv4Wrapper
        The Ipv4Wrapper object for the homoglyph domain ip.

    Returns
    -------
    tuple of str
        A tuple containing the "lang" attribute for the domain html, and the
        homoglyph domain html, respectively.
    """
    domain_html_lang, homo_html_lang = _get_lang_by_ip([domain_ip,
                                                        homoglyph_ip])
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


def _get_lang_by_ip(ip_addresses: List[Ipv4AWrapper]) -> List[Optional[str]]:
    """
    Get the htmls' lang attribute for the list of Ipv4Wrapper objects
    provided.

    Parameters
    ----------
    ip_addresses : list of Ipv4Wrapper
        A list of Ipv4Wrapper objects.

    Returns
    -------
    None or list of str
        A list of strings containing the "lang" attribute of the provided
        urls. None if the html request fails.
    """
    request = [grequests.get('http://' + str(ip_address))
               for ip_address in ip_addresses]
    responses = grequests.map(request)
    lang_list = list()
    for ip_address, response in zip(ip_addresses, responses):
        if response is None:
            log.debug('%s does not respond, return None', ip_address)
            return [None] * len(ip_addresses)
        soup = BeautifulSoup(response.content, 'html.parser')
        html = soup.html
        if html is None:
            log.debug('%s has no html, return none', ip_address)
            return [None] * len(ip_addresses)
        lang = html.get('lang')
        log.debug('lang of ip %s is %s', ip_address, lang)
        lang_list.append(lang)
    return lang_list


def main() -> None:
    begin = time.time()

    init_logger()
    args = parse_args()

    ip_table = ipv4util.load_ipv4_table(args.ipv4_table)
    phishing_targets = load_phishing_targets(args.phishing_targets)
    domains_to_check = read_datafile(args.domain_list)
    _delete_if_present(args.output_file)

    detect_phishing(domains_to_check, ip_table, phishing_targets,
                    args.output_file)

    print(f'Total time: {time.time() - begin}')


if __name__ == '__main__':
    main()
