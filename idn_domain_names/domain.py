from __future__ import annotations

import typing
from collections import Counter
from itertools import product
from typing import List, Optional, Set

import langdetect
import validators
from confusables import normalize
from textblob import TextBlob, exceptions

from idn_domain_names.compatiblewords import CompatibleWords


class Domain:
    def __init__(self, fqdn: str):
        if not fqdn.endswith('.'):
            raise ValueError('%s must end with dot' % fqdn)
        self._fqdn = fqdn

    def domain_language(self) -> Optional[str]:
        """
        Returns the most probable language of the given dn_unicode domain name.

        Parameters
        ----------

        Returns
        -------
        domain_language : str
            The most occurring language in the domain name, with a penalty to
            english language.

        """
        lang_counter = self._count_label_languages()
        if len(lang_counter) > 1:
            most_common_lang = lang_counter.most_common(2)
            if most_common_lang[0][0] == 'en':
                return most_common_lang[1][0]
            return most_common_lang[0][0]
        if len(lang_counter) == 1:
            return lang_counter.most_common()[0][0]
        return None

    def _count_label_languages(self) -> typing.Counter[str]:
        labels = self._fqdn.split('.')
        lang_counter = Counter()  # type: typing.Counter[str]
        for idx in self.non_ascii_label_ids():
            try:
                lang = Domain._detect_language(labels[idx])
                lang_counter[lang] += 1
            except exceptions.TranslatorError:
                continue
        return lang_counter

    @staticmethod
    def _detect_language(label) -> str:
        lang_opt = TextBlob(label).detect_language()
        lang = None
        if lang_opt != 'en':
            lang = lang_opt
        else:
            lang_opt = langdetect.detect(label)
            if lang_opt != 'en':
                lang = lang_opt
        if lang is None:
            lang = 'en'
        return lang

    def non_ascii_label_ids(self) -> List[int]:
        """
        Generates a list containing the indexes of the valid punycode
        in the domain name, considering the '.' (dot) as a field separator.

        Returns
        -------
        xn_list : list of int
            A list containing the indexes of the domain name,
            in a dot-separated fashion, where valid punycode can be found.
        """

        def has_xn(string):
            return 'xn--' in string

        def has_non_ascii(string):
            return not Domain._is_ascii(string)

        if Domain._is_ascii(self._fqdn):
            predicate = has_xn
        else:
            predicate = has_non_ascii

        dn_split = self._fqdn.split('.')
        label_ids = list()
        for i, part in enumerate(dn_split):
            if predicate(part):
                label_ids.append(i)
        return label_ids

    @staticmethod
    def _is_ascii(string: str) -> bool:
        try:
            string.encode('ascii')
            return True
        except UnicodeEncodeError:
            return False

    def is_idna(self) -> bool:
        return 'xn--' in self._fqdn

    def get_label(self, i: int) -> str:
        return self._fqdn.split('.')[i]

    def maybe_truncate_www(self) -> Domain:
        return Domain(self._fqdn.lstrip('www.'))

    def to_unicode(self) -> Domain:
        fqdn = self._fqdn.encode('ascii').decode('idna')
        return Domain(fqdn)

    @staticmethod
    def _generate_homo_list(unicode: str) \
            -> List[str]:
        """
        Generate homoglyph list of unicode string.

        Parameters
        ----------
        unicode : str
            Unicode string.
        idx : int
            Index of dn_split of which the homoglyphs will be generated.

        Returns
        -------
        homo_list : list of str
            List of generated homoglyphs
        """
        homo_list = normalize(unicode)
        non_ascii_removed = unicode.encode('utf-8').decode('ascii', 'ignore')
        homo_list.append(non_ascii_removed)
        return homo_list

    def generate_possible_confusions(self) -> Set[Domain]:
        """
        Generator to a series of possible confusion domain names for the given
        dn_unicode.

        Returns
        -------
        An generator of the possible confusions for the given dn_unicode,
        domain name.
        """
        label_ids = self.non_ascii_label_ids()
        dn_split = self._fqdn.split('.')
        dn_lists = list()
        for idx, dn_part in enumerate(dn_split):
            if idx in label_ids:
                dn_lists.append(self._generate_homo_list(dn_part))
            else:
                dn_lists.append([dn_part])
        dn_iter = map('.'.join, product(*dn_lists))
        return {Domain(dn) for dn in dn_iter if
                dn != self._fqdn and validators.domain(dn[:-1])}

    def is_cognate_domains(self, homo_domain: Domain) -> int:
        """
            Check for domains with equivalent meaning taking into consideration
            the lack of correct accentuation in one of the cases and cognates
            between languages.

            Parameters
            ----------
            homo_domain : Domain
                Homoglyph domain of domain_unicode.

            Returns
            -------
            int
                1, if the domains are probably from the same language
                but one is lacking of accentuation or is a valid cognate.
                Otherwise, -1.
        """
        for idx in self.non_ascii_label_ids():
            domain_blob = TextBlob(self.get_label(idx))
            homo_blob = TextBlob(homo_domain.get_label(idx))
            is_compatible = CompatibleWords(domain_blob, homo_blob) \
                .check_compatibility()
            if not is_compatible:
                return -1
        return 1

    def __hash__(self) -> int:
        return hash(self._fqdn)

    def __eq__(self, o: object) -> bool:
        return (isinstance(o, Domain)) and (self._fqdn == o._fqdn)

    def __str__(self) -> str:
        return self._fqdn

    def __repr__(self) -> str:
        return str(self)
