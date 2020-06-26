import logging
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from ipaddress import IPv4Address
import grequests
from bs4 import BeautifulSoup

from idn_domain_names import ipv4util
from idn_domain_names.domain import Domain

log = logging.getLogger('app')  # pylint: disable=invalid-name


class Pipeline:
    def __init__(self, ip_table, domain_filter, lang_check):
        self.ip_table = ip_table
        self.domain_filter = domain_filter
        self.lang_check = lang_check

    def detect_phishing(self, domains_to_check: Iterator[Domain],
                        phishing_targets: Set[Domain]) -> Iterator[Domain]:
        """
        Classify the provided domains in the datafile tsv file list which domains
        are suspicious to be a phishing domain from the phishing detection routine,
        if file is provided. If not, returns a list is_phishing_list containing
        the results.

        Parameters
        ----------
        domains_to_check : iterable of possible phishing domains.
        phishing_targets : Set[Domains]
            set of phishing targets

        Returns
        -------
        iterator of phishing domains

        """

        for (domain, domain_unicode) in self.domain_filter(domains_to_check):
            # If a domain is phishing, there possibly be more domains with
            # different ASN than the same. though, two domains could belong
            # to the same ASN and one could be phishing,
            # if the ASN is of a ISP (not explored)
            homoglyph_domains = domain_unicode.generate_possible_confusions()
            homoglyph_domains = phishing_targets.intersection(
                homoglyph_domains)
            if not homoglyph_domains:
                continue

            domain_ip, domain_asn = self.ip_table.get_ip_and_asn(domain)
            if domain_ip is None or domain_asn is None:
                log.debug('target %s is unresolvable, skip', domain)
                continue

            phishing_points = 0
            for homo_domain in homoglyph_domains:
                phishing_points += self._calculate_phishing_points(
                    domain_unicode,
                    homo_domain,
                    domain_asn)
            if phishing_points < 0:
                yield domain

    def _calculate_phishing_points(self, domain_unicode: Domain,
                                   homo_domain: Domain,
                                   domain_asn: str) -> int:
        """
        Check if homoglyph domain is a valid evidence that the domain_unicode is
        a phishing domain.

        Parameters
        ----------
        domain_unicode : Domain
            The suspect phishing idn.
        homo_domain : Domain
            A homoglyph of domain_unicode.
        domain_asn : str
            The ASN of domain_unicode.

        Returns
        -------
        int
            1, if the homoglyph domain belongs to the same entity as
            domain_unicode. 0, if the homoglyph domain is dead. -1 if the
            homoglyph domain is a valid evidence that domain_unicode is phishing.
        """
        homoglyph_ip, homoglyph_asn = self.ip_table.get_ip_and_asn(homo_domain)
        if homoglyph_ip is None or homoglyph_asn is None:
            log.debug('domain %s is unresolvable, skip', homo_domain)
            return 0
        if domain_asn == homoglyph_asn:
            return 1
        return self.lang_check(domain_unicode, homo_domain, self.ip_table)


def valid_punycode_filter(domains: Iterator[Domain]) \
        -> Iterator[Tuple[Domain, Domain]]:
    """
    Filter valid punycode domains on domains iterator and returns the punycode
    domain together with it's unicode version if possible.

    Parameters
    ----------
    domains : iterator of Domain
        An iterator of Domain objects.

    Returns
    -------
    iterator of tuple of Domain
        A tuple containing, [0]: The Domain object to the valid punycode
        domain, [1]: The Domain object of the unicode version of the valid
        pynycode domain.
    """
    for domain in domains:
        if not domain.is_idna():
            continue

        try:
            std_domain = domain.maybe_truncate_www()
            yield domain, std_domain.to_unicode()
        except UnicodeError:
            log.debug('failed to convert %s, report as non-phishing', domain)


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
    false_true_counter = 0
    domain_lang = domain_unicode.domain_language() or 'en'
    homo_lang = homo_domain.domain_language()
    (domain_html_lang, homo_html_lang) = _detect_html_languages(
        ip_table.resolve_ip(domain_unicode), ip_table.resolve_ip(homo_domain))
    if domain_html_lang == homo_html_lang and domain_lang != homo_lang:
        false_true_counter += domain_unicode.is_cognate_domains(homo_domain)
    elif domain_html_lang == homo_html_lang and domain_lang == homo_lang:
        false_true_counter += 1
    elif domain_html_lang != homo_html_lang and domain_lang == homo_lang:
        false_true_counter -= 1
    else:
        false_true_counter -= 1
    return false_true_counter


def _detect_html_languages(domain_ip: Optional[IPv4Address],
                           homoglyph_ip: Optional[IPv4Address]) \
        -> Tuple[str, str]:
    """
    Requests the html of the given ip addresses, wrapped in a Ipv4Wrapper
    object, and returns the "lang" attribute of them.

    Parameters
    ----------
    domain_ip : Ipv4Wrapper or None
        The Ipv4Wrapper object for the domain ip.
    homoglyph_ip : Ipv4Wrapper or None
        The Ipv4Wrapper object for the homoglyph domain ip.

    Returns
    -------
    tuple of str
        A tuple containing the "lang" attribute for the domain html, and the
        homoglyph domain html, respectively.
    """
    domain_html_lang, homo_html_lang = get_lang_by_ip([domain_ip,
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


def get_lang_by_ip(ip_addresses: List[Optional[IPv4Address]]) \
        -> List[Optional[str]]:
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
    if None in ip_addresses:
        return [None] * len(ip_addresses)
    request = [grequests.get('http://' + str(ip_address))
               for ip_address in ip_addresses]
    responses = grequests.map(request)
    lang_list: List[Optional[str]] = list()
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
