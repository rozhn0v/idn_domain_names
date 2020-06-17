from __future__ import annotations

from typing import List

from spellchecker import SpellChecker  # type: ignore
from textblob import TextBlob, exceptions


class CompatibleWords:
    def __init__(self, word: TextBlob, homoglyph: TextBlob):
        self._word = word
        self._homo = homoglyph

    @staticmethod
    def _translate_word_to_another_lang(word_to_translate: TextBlob,
                                        target_lang: str) -> str:
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
            from_lang=word_to_translate.detect_language(),
            to=target_lang)
        return str(translation)

    @staticmethod
    def _spellcheck_words(word_list: List[str], lang: str) -> List[str]:
        """
        Correct the spelling for the words in the given list for the given
        language.

        Parameters
        ----------
        word_list : list of str
            A list of words to be checked for misspelling and corrected.
        lang : str
            The ISO 639-1 code of the language which the words are gonna be
            checked to.

        Returns
        -------
        list of str
            The corrected list of words.
        """
        spell_checker = SpellChecker(language=lang)
        corrected_word_list = []
        for word in word_list:
            corrected_word = spell_checker.correction(word)
            corrected_word_list.append(corrected_word)
        return corrected_word_list

    @staticmethod
    def _transfer_space_from_phrase_to_word(phrase: str, word: str) -> str:
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

    @staticmethod
    def _split_phrase_into_word_list(phrase: str) -> List[str]:
        """
        Turn a phrase with words separated by spaces into a list of words.

        Parameters
        ----------
        phrase : str
            A phrase of words separated by spaces.

        Returns
        -------
        list of str
            A list of the words of the given phrase.
        """
        return phrase.split(' ')

    @staticmethod
    def _word_list_to_phrase(word_list: List[str]) -> str:
        """
        Turn a list of words into a phrase of the same words separated by
        spaces.

        Parameters
        ----------
        word_list : list of str
            A list of words.

        Returns
        -------
        str
            A phrase containing the words of the given list separated by
            spaces.
        """
        return ' '.join(word_list)

    @staticmethod
    def _check_compatibility_left_to_right(left_word: TextBlob,
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
        translated_word = (CompatibleWords
                           ._translate_word_to_another_lang(left_word,
                                                            target_lang))
        right_phrase = (CompatibleWords._transfer_space_from_phrase_to_word(
            translated_word, str(right_word)))
        left_words = (CompatibleWords
                      ._split_phrase_into_word_list(translated_word))
        right_words = (CompatibleWords
                       ._split_phrase_into_word_list(right_phrase))
        corrected_left_words = CompatibleWords._spellcheck_words(left_words,
                                                                 target_lang)
        corrected_right_words = CompatibleWords._spellcheck_words(right_words,
                                                                  target_lang)
        corrected_left_phrase = (
            CompatibleWords._word_list_to_phrase(corrected_left_words))
        corrected_right_phrase = (
            CompatibleWords._word_list_to_phrase(corrected_right_words))
        return corrected_left_phrase == corrected_right_phrase

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
                self._check_compatibility_left_to_right(self._word,
                                                        self._homo))
            if left_to_right_compatible:
                return True
        except exceptions.NotTranslated:
            right_to_left_compatible = (
                self._check_compatibility_left_to_right(self._homo,
                                                        self._word))
            return right_to_left_compatible
        else:
            right_to_left_compatible = (
                self._check_compatibility_left_to_right(self._homo,
                                                        self._word))
            return right_to_left_compatible

    @property
    def word(self):
        return self._word

    @property
    def homoglyph(self):
        return self._homo
