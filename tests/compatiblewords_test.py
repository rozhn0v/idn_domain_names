import unittest
from unittest.mock import MagicMock

import idn_domain_names.compatiblewords as cw
from idn_domain_names.compatiblewords import CompatibleWords


class WordsTest(unittest.TestCase):
    def test_spellcheck(self):
        expected = ['horse', 'wine']

        factory = MagicMock()
        factory().correction.side_effect = ['horse', 'wine']

        actual = cw.spell_check('hrse wyne', 'en', factory=factory)
        self.assertEqual(expected, actual)


class CompatibleWordsTest(unittest.TestCase):
    def test_transfer_space_from_phrase_to_word(self):
        expected = 'hello there'
        actual = cw.transfer_space_from_phrase_to_word(expected, 'hellothere')
        self.assertEqual(expected, actual)

    def test_check_compatibility(self):
        word = TextBlobStub('frasescélebres', 'es', 'frases célebres')
        homo = TextBlobStub('frasescelebres', 'pt')

        mapping = {
            'frases célebres': 'frases celebres',
            'frases celebres': 'frases celebres'
        }

        words = CompatibleWords(word, homo, lambda phrase, _: mapping[phrase])
        self.assertTrue(words.check_compatibility())

    def test_check_compatibility_with_extra_symbol(self):
        word = TextBlobStub('gmailç', 'fr')
        homoglyph = TextBlobStub('gmail', 'en')
        words = CompatibleWords(word, homoglyph, None)
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

    def translate(self, _, __):
        return self.translation

    def __repr__(self):
        return '{} {} {}'.format(self.word, self.lang, self.translation)

    def __str__(self) -> str:
        return self.word
