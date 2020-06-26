from __future__ import annotations

from typing import List

from spellchecker import SpellChecker  # type: ignore
from textblob import TextBlob, exceptions


def spell_check(phrase: str, lang: str, factory=SpellChecker) -> List[str]:
    """
    Correct the spelling for the words in the given list for the given
    language.

    Parameters
    ----------
    phrase : str - checked phrase
    lang : str
        The ISO 639-1 code of the language which the words are gonna be
        checked to.
    factory: builder for wrapper spell checker

    Returns
    -------
    list of str
        The corrected list of words.
    """
    tokens = phrase.split(' ')
    try:
        spell_checker = factory(language=lang)
    except ValueError:
        return tokens

    corrected_word_list = []
    for word in tokens:
        corrected_word = spell_checker.correction(word)
        corrected_word_list.append(corrected_word)
    return corrected_word_list


class CompatibleWords:  # pylint: disable=too-few-public-methods
    def __init__(self,
                 word: TextBlob,
                 homoglyph: TextBlob,
                 checker=spell_check):
        self._spell_check = checker
        self._word = word
        self._homo = homoglyph

    @staticmethod
    def _translate(word_to_translate: TextBlob, target_lang: str) -> str:
        """
        Translate a word to a given language.

        Parameters
        ----------
        word_to_translate : TextBlob
            A TextBlob wrapped word to be translated.
        target_lang : str
            The ISO 639-1 code for the target language.

        Returns
        -------
        str
            The translation of the given word to the target language.
        """
        translation = word_to_translate.translate(
            word_to_translate.detect_language(), target_lang)
        return str(translation)

    def _check_compatibility_left_to_right(self, left_word: TextBlob,
                                           right_word: TextBlob) -> bool:
        """
        Check the words' compatibility from left to right.

        Parameters
        ----------
        left_word : TextBlob
            A TextBlob wrapped word.
        right_word : TextBlob
            A TextBlob wrapper word.

        Returns
        -------
        bool
            True, if the words are compatible, otherwise false.
        """
        if len(left_word) != len(right_word):
            return False
        target_lang = right_word.detect_language()
        translated_word = (CompatibleWords._translate(left_word, target_lang))
        right_phrase = transfer_space_from_phrase_to_word(
            translated_word, str(right_word))
        corrected_left_words = self._spell_check(translated_word, target_lang)
        corrected_right_words = self._spell_check(right_phrase, target_lang)
        return corrected_left_words == corrected_right_words

    def check_compatibility(self) -> bool:
        """
        Check the compatibility of the word and it's homoglyph.

        Returns
        -------
        bool
            True, if the word wrapped in the CompatibleWords object is
            compatible with it's homoglyph, otherwise false.
        """
        if self._word == self._homo:
            return True

        try:
            left_to_right_compatible = (
                self._check_compatibility_left_to_right(
                    self._word, self._homo))
            if left_to_right_compatible:
                return True
        except exceptions.NotTranslated:
            pass

        try:
            return self._check_compatibility_left_to_right(
                self._homo, self._word)
        except exceptions.NotTranslated:
            return False


def transfer_space_from_phrase_to_word(phrase: str, word: str) -> str:
    """
    Transfer the space present in the given phrase to the same position
    of the given word.

    Parameters
    ----------
    phrase : str
        Words separated by spaces.
    word : str
        A single word, without spaces.

    Returns
    -------
    str
        The word with spaces added to the same positions of the given
        phrase.
    """
    new_phrase = ''
    for phrase_letter, word_letter in zip(phrase, word):
        if phrase_letter == ' ':
            new_phrase += ' ' + word_letter
        else:
            new_phrase += word_letter
    return new_phrase
