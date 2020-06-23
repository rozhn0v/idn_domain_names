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


def parse_targets_source(source):
    result = set()
    tsv_f = csv.reader(source, delimiter='\t')
    for line in tsv_f:
        domain = Domain(line[1] + '.')
        domain = domain.maybe_truncate_www()
        if domain.is_idna():
            domain = domain.to_unicode()
        result.add(domain)
    return result


def read_datafile(datafile: str) -> Iterator[Domain]:
    """
    Create a generator to the domain list to be classified.

    Parameters
    ----------
    datafile : str
        The path to the tsv file containing the list of domain names to be
        classified.

    Returns
    -------
    A generator for the domain list.
    """
    if isinstance(datafile, str):
        domain_list_file = open(datafile, 'r')
        domain_list_tsv = csv.reader(domain_list_file, delimiter='\t')
    else:
        domain_list_file = datafile
        domain_list_tsv = csv.reader(domain_list_file, delimiter='\t')
    for line in domain_list_tsv:
        yield Domain(line[0])


def dump_result(domain: Domain, file_path: str, is_phishing: bool) -> None:
    """
    Writes the domain and is_phishing value to a file in a csv (comma separated
    values) format, if file is given, if file is None, appends is_phishing
    to phishing_list list.

    Parameters
    ----------
    domain : str
        Domain name to write to file, if file is given.
    file_path : str
        the information will be written to a file
    is_phishing : bool
        Contains the information whether the given domain is a phishing
        candidate or not.
    """
    if not is_phishing:
        return
    with open(file_path, 'a+') as output:
        file_ext = file_path.split('.')[-1]
        if file_ext == 'csv':
            output.write('%s,%d\n' % (domain, int(is_phishing)))
        elif file_ext == 'tsv':
            output.write('%s\t%d\n' % (domain, int(is_phishing)))
        else:
            raise ValueError(
                'Invalid file_path extension, use TSV or CSV file_path.')


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
