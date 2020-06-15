import unittest

from domain import Domain


class DomainTest(unittest.TestCase):
    def test_to_unicode(self):
        domain = Domain('xn--jana-sovkov-r7ad.seria-z.net.')
        actual = domain.to_unicode()
        expected = Domain('jana-sováková.seria-z.net.')
        self.assertEqual(expected, actual)

    def test_in_dictionary(self):
        key = Domain('foo.bar.')
        index = {key: 5}
        self.assertEqual(5, index[key])

    def test_in_set(self):
        youtube = Domain('youtube.com.')
        left = {youtube, Domain('gmail.com.')}
        right = {youtube, Domain('wikipedia.org.')}
        actual = left.intersection(right)
        expected = {youtube}
        self.assertEqual(expected, actual)

    def test_non_ascii_label_ids(self):
        punycode = Domain('xn--jana-sovkov-r7ad.seria-z.net.')
        unicode = Domain('jana-sováková.seria-z.net.')


        expected = [0]
        self.assertEqual(expected, punycode.non_ascii_label_ids())
        self.assertEqual(expected, unicode.non_ascii_label_ids())

    def test_domain_language_when_none(self):
        youtube = Domain('youtube.com.')
        actual = youtube.domain_language()
        expected = None
        self.assertEqual(expected, actual)

    def test_domain_language_when_ca(self):
        frasescelebres = Domain('xn--frasesclebres-hhb.com.')
        actual = frasescelebres.domain_language()
        expected = 'ca'  # ca, es and pt are very similar langs
        self.assertEqual(expected, actual)

    def test_is_cognate_domains(self):
        frases_ascii = Domain('frasescelebres.com.')
        frases_uni = Domain('xn--frasesclebres-hhb.com.').to_unicode()
        actual = frases_uni.is_cognate_domains(frases_ascii)
        expected = 1
        self.assertEqual(expected, actual)
