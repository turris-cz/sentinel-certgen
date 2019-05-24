"""
Main entry point of Sentinel:Certgen package
"""

import logging
import os
import sys

from .argparser import get_arg_parser
from .crypto_wrapper import get_sn, get_auth_type
from .cryptography import clear_cert_dir
from .exceptions import CertgenError
from .logging import setup_logger
from .certmachine import CertMachine
from .mailpassmachine import MailpassMachine

from . import EXIT_RC_SETUP, MQTT_CSR_FILE, MQTT_CERT_FILE, MQTT_KEY_FILE

logger = logging.getLogger("certgen")


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    setup_logger(args.verbose)

    try:
        sn = get_sn()
        auth_type = get_auth_type()
    except CertgenError as e:
        logger.critical(str(e))
        sys.exit(EXIT_RC_SETUP)

    api_url = "{}:{}".format(args.cert_api_hostname, args.cert_api_port)
    ca_path = args.capath

    if args.command == "certs":
        if not os.path.exists(args.certdir):
            os.makedirs(args.certdir)

        key_path = os.path.join(args.certdir, MQTT_KEY_FILE)
        cert_path = os.path.join(args.certdir, MQTT_CERT_FILE)
        csr_path = os.path.join(args.certdir, MQTT_CSR_FILE)

        if args.regen_key:
            clear_cert_dir(key_path, csr_path, cert_path)

        flags = set()
        if not args.regen_key and args.renew:
            if os.path.exists(csr_path):
                os.remove(csr_path)
            flags.add("renew")

        machine = CertMachine(
                key_path, csr_path, cert_path,
                sn, auth_type, flags, api_url, ca_path, args.insecure_connection
        )

    elif args.command == "mailpass":
        flags = set()
        machine = MailpassMachine(
                args.filename,
                sn, auth_type, flags, api_url, ca_path, args.insecure_connection
        )

    # run StateMachine
    rc = machine.start()
    sys.exit(rc)


if __name__ == "__main__":
    main()
