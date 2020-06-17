import unittest

from textblob import TextBlob
from idn_domain_names.compatiblewords import CompatibleWords


class CompatibleWordsTest(unittest.TestCase):
    def test__translate_word_to_another_lang(self):
        word = TextBlob('horse')
        actual = CompatibleWords._translate_word_to_another_lang(word, 'pt')
        expected = 'cavalo'
        self.assertEqual(expected, actual)

    def test__spellcheck_words(self):
        word_list = ['hrse', 'wyne']
        actual = CompatibleWords._spellcheck_words(word_list, 'en')
        expected = ['horse', 'wine']
        self.assertEqual(expected, actual)

    def test__transfer_space_from_phrase_to_word(self):
        phrase = 'hello there'
        word = 'hellothere'
        actual = CompatibleWords._transfer_space_from_phrase_to_word(phrase,
                                                                     word)
        expected = phrase
        self.assertEqual(expected, actual)

    def test__check_compatibility_left_to_right_when_true(self):
        left_word = TextBlob('frasescélebres')
        right_word = TextBlob('frasescelebres')
        actual = CompatibleWords._check_compatibility_left_to_right(left_word,
                                                                    right_word)
        self.assertTrue(actual)

    def test__check_compatibility_left_to_right_when_false(self):
        left_word = TextBlob('gmail')
        right_word = TextBlob('gmailç')
        actual = CompatibleWords._check_compatibility_left_to_right(left_word,
                                                                    right_word)
        self.assertFalse(actual)

    def test_check_compatibility_when_true(self):
        word = TextBlob('frasescélebres')
        homoglyph = TextBlob('frasescelebres')
        actual = CompatibleWords(word, homoglyph).check_compatibility()
        self.assertTrue(actual)

    def test_check_compatibility_when_false(self):
        word = TextBlob('gmailç')
        homoglyph = TextBlob('gmail')
        actual = CompatibleWords(word, homoglyph).check_compatibility()
        self.assertFalse(actual)
