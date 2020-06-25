import unittest
from unittest.mock import MagicMock

import idn_domain_names.compatiblewords as cw
from idn_domain_names.compatiblewords import CompatibleWords
from idn_domain_names.compatiblewords import Words


class WordsTest(unittest.TestCase):
    def test_spellcheck_words(self):
        def cons(language: str):
            result = MagicMock()
            result.correction.side_effect = ['horse', 'wine']
            return result

        words = Words(['hrse', 'wyne'], spell_checker=cons)
        expected = Words(['horse', 'wine'])
        self.assertEqual(expected, words.spellcheck('en'))


class CompatibleWordsTest(unittest.TestCase):
    def test_transfer_space_from_phrase_to_word(self):
        expected = 'hello there'
        actual = cw.transfer_space_from_phrase_to_word(expected, 'hellothere')
        self.assertEqual(expected, actual)

    def test_check_compatibility(self):
        word = TextBlobStub('frasescélebres', 'es', 'frases célebres')
        homoglyph = TextBlobStub('frasescelebres', 'pt')
        print(word.detect_language())
        self.assertTrue(CompatibleWords(word, homoglyph).check_compatibility())

    def test_check_compatibility_with_extra_symbol(self):
        word = TextBlobStub('gmailç', 'fr')
        homoglyph = TextBlobStub('gmail', 'en')
        words = CompatibleWords(word, homoglyph)
        self.assertFalse(words.check_compatibility())


class TextBlobStub:
    def __init__(self, word, lang, translation=None):
        self.word = word
        self.lang = lang
        self.translation = translation

    def __len__(self):
        return len(self.word)

    def detect_language(self):
        return self.lang

    def translate(self, from_lang, to):
        return self.translation

    def __repr__(self):
        return '{} {} {}'.format(self.word, self.lang, self.translation)

    def __str__(self) -> str:
        return self.word
