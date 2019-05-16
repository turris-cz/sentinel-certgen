"""
CertMachine child class definition
"""

import logging
import os
import time

from cryptography.hazmat.primitives import serialization

from .cryptography import cert_expired, cert_to_expire, extract_cert, generate_csr_file, generate_priv_key_file, load_or_remove_cert, load_or_remove_key, load_or_remove_csr, save_cert
from .exceptions import CertgenError
from .statemachine import StateMachine

from . import RENEW_WAIT
from .statemachine import STATE_INIT, STATE_GET, STATE_VALID, STATE_FAIL

logger = logging.getLogger("certgen")


class CertMachine(StateMachine):
    def __init__(
            self, key_path, csr_path, cert_path, ca_path,
            sn, api_url, flags, auth_type, ic
    ):
        self.key_path = key_path
        self.csr_path = csr_path
        self.cert_path = cert_path
        super().__init__(ca_path, sn, api_url, flags, auth_type, ic)

    @property
    def ROUTE(self):
        """
        Get cert-api action route
        """
        return "certs"

    def action_spec_params(self):
        """
        Return certs action-specific parameters for get request
        """
        csr_str = self.csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return {"csr_str": csr_str}

    def action_spec_init(self):
        """
        Processing the initial state. In this state, private key and
        certificate are loaded from the certificate directory. If something in
        the process fails the private key may be re-generated and a certificate
        signing request is prepared.
        Depending on the status of certificate file this state continues with
        status:
            GET:    when no consistent cert is present
            VALID:  when the cert is present, consistent, valid and will not
                    expire nearly
        """
        self.key = None
        if os.path.exists(self.key_path):
            self.key = load_or_remove_key(self.key_path)
        if not self.key:
            logger.info("Private key file not found. Generating new one.")
            generate_priv_key_file(self.key_path)
            self.key = load_or_remove_key(self.key_path)
            self.remove_flag_renew()
        if not self.key:
            logger.critical("Unable to acquire private key!")
            raise CertgenError("Unable to acquire private key!")

        cert = None
        if os.path.exists(self.cert_path):
            cert = load_or_remove_cert(self.cert_path, self.key)
        if not cert:
            self.cert_sn = None
        else:  # we have a cert
            if cert_expired(cert, self.csr_path, self.cert_path):
                logger.info("Certificate expired. Removing...")
                if os.path.exists(self.csr_path):
                    os.remove(self.csr_path)
                os.remove(self.cert_path)
                self.cert_sn = None
            else:
                if cert_to_expire(cert):
                    self.flags.add("renew")
                    self.cert_sn = cert.serial_number
                    logger.info("Certificate to expire. Renew flagged.")
                else:
                    logger.info("Valid certificate found")
                    if "renew" in self.flags:
                        logger.info("Renew was requested")
                        self.cert_sn = cert.serial_number
                    else:
                        return STATE_VALID

        logger.info("Certificate file does not exist or is to be renewed. Re-certifying.")

        self.csr = None
        if os.path.exists(self.csr_path):
            self.csr = load_or_remove_csr(self.csr_path, self.key)
        if not self.csr:
            generate_csr_file(self.csr_path, self.sn, self.key)
            self.csr = load_or_remove_csr(self.csr_path, self.key)
        if self.csr:
            return STATE_GET
        else:
            logger.critical("Unable to acquire csr!")
            raise CertgenError("Unable to acquire csr!")

    def process_get_response(self, response):
        """
        Process data acquired from last get request and return the desired next
        state.
        This function may return on of the three next states:
            INIT:   when a valid certificate is downloaded and saved (init must
                    check consistency of the certificate file)
            FAIL:   the received certificate is not valid or some other error
                    occurred
            GET:    the certs sn does not match - old cert still in cache, we
                    have to wait
        """
        # extract & consistency check
        cert = extract_cert(response.get("cert", ""), self.key)
        if cert:
            if cert.serial_number != self.cert_sn:
                logger.info("New certificate successfully downloaded.")
                save_cert(cert, self.cert_path)
                return STATE_INIT
            else:
                logger.debug(
                        "New cert is not available yet. Sleeping for %d seconds",
                        RENEW_WAIT
                )
                time.sleep(RENEW_WAIT)
                return STATE_GET
        else:
            logger.error("Obtained cert key does not match.")
            return STATE_FAIL
