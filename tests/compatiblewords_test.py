import unittest

from textblob import TextBlob

import idn_domain_names.compatiblewords as cw
from idn_domain_names.compatiblewords import CompatibleWords
from idn_domain_names.compatiblewords import Words


class WordsTest(unittest.TestCase):
    def test_spellcheck_words(self):
        words = Words(['hrse', 'wyne'])
        expected = Words(['horse', 'wine'])
        self.assertEqual(expected, words.spellcheck_words('en'))


class CompatibleWordsTest(unittest.TestCase):
    def test_transfer_space_from_phrase_to_word(self):
        expected = 'hello there'
        actual = cw.transfer_space_from_phrase_to_word(expected, 'hellothere')
        self.assertEqual(expected, actual)

    def test_check_compatibility(self):
        word = TextBlob('frasescélebres')
        homoglyph = TextBlob('frasescelebres')
        self.assertTrue(CompatibleWords(word, homoglyph).check_compatibility())

    def test_check_compatibility_with_extra_symbol(self):
        word = TextBlob('gmailç')
        homoglyph = TextBlob('gmail')
        words = CompatibleWords(word, homoglyph)
        self.assertFalse(words.check_compatibility())
