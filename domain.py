from __future__ import annotations

import socket
from collections import Counter
from itertools import product
from typing import Iterator
from typing import List
from typing import Optional

import langdetect
from confusables import normalize
from textblob import TextBlob
from textblob import exceptions


class Domain:
    def __init__(self, fqdn: str):
        if not fqdn.endswith('.'):
            raise ValueError('%s must end with dot'.format(fqdn))
        self._fqdn = fqdn

    # TODO do not pass xn_idx
    def domain_language(self, xn_idx: List[int]) -> Optional[str]:
        """
        Returns the most probable language of the given dn_unicode domain name.

        Parameters
        ----------

        Returns
        -------
        domain_language : str
            The most occurring language in the domain name, with a penalty to english
            language.

        """
        dn_list = self._fqdn.split('.')
        lang_counter = Counter()
        for idx in xn_idx:
            try:
                lang_opt = TextBlob(dn_list[idx]).detect_language()
                lang = None
                if lang_opt != 'en':
                    lang = lang_opt
                else:
                    lang_opt = langdetect.detect(dn_list[idx])
                    if lang_opt != 'en':
                        lang = lang_opt
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

    # TODO make private
    def punycode_idx(self) -> List[int]:
        """
        Generates a list containing the indexes of the valid punycode in the domain name,
        considering the '.' (dot) as a field separator.

        Returns
        -------
        xn_list : list of int
            A list containing the indexes of the domain name, in a dot-separated fashion, where
            valid punycode can be found.
        """

        dn_split = self._fqdn.split('.')
        xn_list = []
        for i, part in enumerate(dn_split):
            if 'xn--' in part:
                xn_list.append(i)
        return xn_list

    def is_idna(self) -> bool:
        return 'xn--' in self._fqdn

    def get_label(self, i: int) -> str:
        return self._fqdn.split('.')[i]

    def get_ip(self):
        return socket.gethostbyname(self._fqdn)

    def maybe_truncate_www(self) -> Domain:
        return Domain(self._fqdn.lstrip('www.'))

    def to_idna(self) -> Domain:
        fqdn = self._fqdn.encode('acsii').decode('idna')
        return Domain(fqdn)

    def normalize_wrap(self, xn_idx: List[int]) -> Iterator[str]:
        """
        Generator to a series of possible confusion domain names for the given dn_unicode.

        Parameters
        ----------
        xn_idx : list of int
            Indexes of the valid punycode, considering the dot as a field separator.

        Returns
        -------
        An generator of the possible confusions for the given dn_unicode, domain name.
        """

        dn_split = self._fqdn.split('.')
        for i in xn_idx:
            dn_split[i] = normalize(dn_split[i])
        dn_split = map(lambda x: x if isinstance(x, list) else [x], dn_split)
        dn_iter = map(lambda x: '.'.join(x), product(*dn_split))
        for dn in dn_iter:
            if dn != self._fqdn:
                yield dn

    # TODO do not pass xn_idx
    def correct_accent_equal(self, homo_domain: Domain,
                             xn_idx: List[int]) -> bool:
        """
            Check for domains with equivalent meaning taking into consideration the lack of correct accentuation
            in one of the cases.

            Parameters
            ----------
            homo_domain : Domain
                Homoglyph domain of domain_unicode.
            xn_idx : list of int
                Indexes of the valid punycode, considering the dot as a field separator.

            Returns
            -------
            bool
                True, if the domains are probably from the same language but one is lacking of accentuation.
                Otherwise, False.
        """
        not_equivalent = 0
        for idx in xn_idx:
            domain_blob = TextBlob(self.get_label(idx))
            homo_blob = TextBlob(homo_domain.get_label(idx))
            if domain_blob == homo_blob:
                continue
            try:
                translation = domain_blob.translate(
                    from_lang=domain_blob.detect_language(),
                    to=homo_blob.detect_language())
            except exceptions.NotTranslated:
                try:
                    translation = homo_blob.translate(
                        from_lang=homo_blob.detect_language(),
                        to=domain_blob.detect_language())
                except exceptions.NotTranslated:
                    not_equivalent = 1
                    break
                else:
                    if translation == domain_blob:
                        continue
                    else:
                        not_equivalent = 1
                        break
            except exceptions.TranslatorError:
                not_equivalent = 1
                break
            else:
                if translation == homo_blob:
                    continue
                else:
                    not_equivalent = 1
        if not_equivalent:
            return False
        else:
            return True

    def __str__(self) -> str:
        return self._fqdn
