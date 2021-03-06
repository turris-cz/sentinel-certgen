"""
An argument parser for Sentinel:Certgen
"""

import argparse
import os

from . import __version__, DEFAULT_CERT_API_HOSTNAME, DEFAULT_CERT_API_PORT, DEFAULT_CERTS_CERTDIR, DEFAULT_MAILPASS_FILENAME


class StoreReadableDir(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (os.path.isdir(values)
                and os.access(values, os.R_OK)
                and os.access(values, os.X_OK)):
            setattr(namespace, self.dest, values)
        else:
            raise argparse.ArgumentError(
                    self,
                    "Path {} is not a readable directory".format(values)
            )


def get_arg_parser():
    """
    Returns argument parser object
    """
    def add_common_args(parser):
        parser.add_argument(
                "-H", "--cert-api-hostname",
                default=DEFAULT_CERT_API_HOSTNAME,
                help="Cert-API hostname"
        )
        parser.add_argument(
                "-p", "--cert-api-port",
                default=DEFAULT_CERT_API_PORT,
                help="Cert-API port"
        )
        parser.add_argument(
                "-a", "--capath",
                help="File with CA certificates for TLS connection"
        )
        parser.add_argument(
                "-v", "--verbose",
                action="store_true",
                help="Raise console logging level to debug"
        )
        parser.add_argument(
                "--insecure-connection",
                action="store_true",
                help="Use HTTP instead of HTTPS when communicating with the API server"
        )

    parser = argparse.ArgumentParser(
            description="Certgen - client for retrieving secrets and certs via Turris:Sentinel"
    )
    parser.add_argument(
            "--version",
            action="version",
            version="%(prog)s {}".format(__version__)
    )

    subparsers = parser.add_subparsers()
    subparsers.required = True
    subparsers.dest = "command"

    # CERTS
    sub = subparsers.add_parser(
            "certs",
            help="Retrieve Turris:Sentinel certificates"
    )
    add_common_args(sub)
    sub.add_argument(
            "--certdir",
            default=DEFAULT_CERTS_CERTDIR,
            help="Path to Sentinel certificate location"
    )
    sub.add_argument(
            "--regen-key",
            action="store_true",
            help="Remove private key, generate a new one and ask Sentinel:Cert-Api for a new certificate"
    )
    sub.add_argument(
            "-n", "--renew",
            action="store_true",
            help="Ask Sentinel:Cert-Api for a new certificate and reuse the existing key"
    )
    sub.add_argument(
            "-s", "--skip-renew",
            action="store_true",
            help="In case of renew (due to a valid certificate which is nearly "
                 "expired or --renew option) do not ask Sentinel:Cert-Api for "
                 "a new certificate but rather exit in valid state. This "
                 "is a less-blocking variant designed for upstart."
    )
    sub.add_argument(
            "--hooks-dir",
            action=StoreReadableDir,
            help="Configure hooks directory path (executable files within this directory would be executed if the certificate was issued)"
    )

    # MAILPASS
    sub = subparsers.add_parser(
            "mailpass",
            help="Retrieve secret for notifications mail server"
    )
    add_common_args(sub)
    sub.add_argument(
            "-f", "--filename",
            default=DEFAULT_MAILPASS_FILENAME,
            help="path to file where the secret is stored"
    )

    return parser
