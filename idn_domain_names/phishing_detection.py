import argparse
import logging
import sys

import idn_domain_names.filesystem as fs
import idn_domain_names.ipv4util as ipv4util
import idn_domain_names.pipeline as pipeline

log = logging.getLogger('app')  # pylint: disable=invalid-name


def init_logger() -> None:
    """
    Configure the global log object.
    """
    log.setLevel(logging.ERROR)
    formatter = logging.Formatter(
        fmt="[%(asctime)s] %(process)d %(levelname)s %(message)s",
        datefmt='%H:%M:%S')
    file_handler = logging.FileHandler('../phishing.log')
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    """
    Parse the command line parameters and options. The options are
    "domain-list",which is the path to the tsv file containinga list of domain
    names, "output" which is the path to the file to store the detection
    results and ipv4toasn, which is the path to the file containing the IPV4
    to ASN table, and the the phishingtargets, which is a tsv file containing
    the phishing targeted domains.

    Returns
    -------
    args : argparse.Namespace of str
        Contains the fields: domain_list, output_file, ipv4_table
        and phishing_targets, in that order.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d',
        '--domain-list',
        dest='domain_list',
        help='The path to the tsv file containing domains to be analyzed.',
        type=str,
        default=sys.stdin)
    parser.add_argument(
        '-o',
        '--output',
        dest='output_file',
        help='The path in which the output file will be created.',
        type=str,
        required=True)
    parser.add_argument('-i',
                        '--ipv4-to-asn',
                        dest='ipv4_table',
                        help='The path to the IPV4 to ASN table (TSV format).',
                        type=str,
                        required=True)

    parser.add_argument('-p',
                        '--phishing-targets',
                        dest='phishing_targets',
                        help='The path to the phishing target\'s list.',
                        type=str,
                        required=True)

    return parser.parse_args()


def main() -> None:
    init_logger()
    args = parse_args()

    ip_table = ipv4util.load_ipv4_table(args.ipv4_table)
    phishing_targets = fs.load_phishing_targets(args.phishing_targets)
    domains_to_check = fs.read_datafile(args.domain_list)
    fs.delete_if_present(args.output_file)

    pipeline.detect_phishing(domains_to_check, ip_table, phishing_targets,
                             args.output_file)


if __name__ == '__main__':
    main()
