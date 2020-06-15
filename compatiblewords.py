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
        translation = word_to_translate.translate(
            from_lang=word_to_translate.detect_language(),
            to=target_lang)
        return str(translation)

    @staticmethod
    def _spellcheck_words(word_list: List[str], lang: str) -> List[str]:
        spell_checker = SpellChecker(language=lang)
        corrected_word_list = []
        for word in word_list:
            corrected_word = spell_checker.correction(word)
            corrected_word_list.append(corrected_word)
        return corrected_word_list

    @staticmethod
    def _transfer_space_from_phrase_to_word(phrase: str, word: str) -> str:
        new_phrase = ''
        for phrase_letter, word_letter in zip(phrase, word):
            if phrase_letter == ' ':
                new_phrase += ' ' + word_letter
            else:
                new_phrase += word_letter
        return new_phrase

    @staticmethod
    def _split_phrase_into_word_list(phrase: str) -> List[str]:
        return phrase.split(' ')

    @staticmethod
    def _word_list_to_phrase(word_list: List[str]) -> str:
        return ' '.join(word_list)

    def _check_compatibility_left_to_right(self, left_word: TextBlob,
                                           right_word: TextBlob):
        target_lang = right_word.detect_language()
        translated_word = self._translate_word_to_another_lang(left_word,
                                                               target_lang)
        right_phrase = (
            self._transfer_space_from_phrase_to_word(translated_word,
                                                     str(right_word)))
        left_words = self._split_phrase_into_word_list(translated_word)
        right_words = self._split_phrase_into_word_list(right_phrase)
        corrected_left_words = self._spellcheck_words(left_words,
                                                      target_lang)
        corrected_right_words = self._spellcheck_words(right_words,
                                                       target_lang)
        corrected_left_phrase = (
            self._word_list_to_phrase(corrected_left_words))
        corrected_right_phrase = (
            self._word_list_to_phrase(corrected_right_words))
        return corrected_left_phrase == corrected_right_phrase

    def check_compatibility(self) -> bool:
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
