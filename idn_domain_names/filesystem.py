import csv
import gzip
from pathlib import Path
from typing import Iterator, Set

from idn_domain_names.domain import Domain


def load_phishing_targets(filename: str) -> Set[Domain]:
    """
    Creates a generator to the zipped phishing target list (tsv format).

    Parameters
    ----------
    filename : str
        The path to the zipped phishing target list.

    Returns
    -------
    Generator of the phishing target list.
    """
    with gzip.open(filename, 'rt') as source:
        return parse_targets_source(source)


def parse_targets_source(source: Iterator[str]) -> Set[Domain]:
    result = set()
    tsv_f = csv.reader(source, delimiter='\t')
    for line in tsv_f:
        domain = Domain(line[1] + '.')
        domain = domain.maybe_truncate_www()
        if domain.is_idna():
            domain = domain.to_unicode()
        result.add(domain)
    return result


def read_datafile(datafile) -> Iterator[Domain]:
    """
    Create a generator to the domain list to be classified.

    Parameters
    ----------
    datafile
        The path to the tsv file containing the list of domain names to be
        classified.

    Returns
    -------
    A generator for the domain list.
    """
    if isinstance(datafile, str):
        domain_list_file = open(datafile, 'r')
    else:
        domain_list_file = datafile
    for line in domain_list_file:
        yield Domain(line)


def report_phishing(domain: Domain, file_path: str):
    """
    Writes phishing domains

    Parameters
    ----------
    domain : str
        Domain name to write to file, if file is given.
    file_path : str
        the information will be written to a file
    """
    with open(file_path, 'a+') as output:
        output.write('%s\n' % domain)


def delete_if_present(path: str):
    """
    Check if the file of the given path exists, if it does, it's deleted.

    Parameters
    ----------
    path : str
        A path to a file.
    """
    file_obj = Path(path)
    if file_obj.exists():
        file_obj.unlink()
