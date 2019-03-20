#!/usr/bin/env python3

# Turris:Sentinel Certgen - Client application for automated CA
# Copyright (C) 2018 CZ.NIC z.s.p.o. (https://www.nic.cz/)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import datetime
import time
import os
import subprocess
import urllib.request
import ssl
import argparse
import logging
import logging.handlers
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


ELLIPTIC_CURVE = ec.SECP256R1()
MAX_TIME_TO_EXPIRE = 30*24*60*60
ERROR_WAIT = 5*60
API_VERSION = "v1"
RENEW_WAIT = 10
MIN_MAILPASS_CHARS = 8

logger = logging.getLogger("certgen")
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())


class CertgenError(Exception):
    pass


def get_arg_parser():
    """ Returns argument parser object.
    """
    def add_common_args(parser):
        parser.add_argument("-H", "--cert-api-hostname",
                            default="sentinel.turris.cz",
                            help="cert-api hostname")
        parser.add_argument("-p", "--cert-api-port",
                            default="443",
                            help="cert-api port")
        parser.add_argument("-a", "--capath",
                            help="file with CA certificates for TLS connection")
        parser.add_argument("-v", "--verbose",
                            action="store_true",
                            help="raise console logging level to debug")
        parser.add_argument("--insecure-connection",
                            action="store_true",
                            help="use HTTP instead of HTTPS"
                                 " when communicating with the API server")

    parser = argparse.ArgumentParser(description="Certgen - client for retrieving"
                                     " secrets and certs via Turris:Sentinel")
    subparsers = parser.add_subparsers()
    subparsers.required = True
    subparsers.dest = "command"

    # CERTS
    sub = subparsers.add_parser("certs", help="Retrieve Turris:Sentinel certificates")
    add_common_args(sub)
    sub.add_argument("--certdir",
                     default="/etc/sentinel",
                     help="path to Sentinel certificate location")
    sub.add_argument("--regen-key",
                     action="store_true",
                     help="remove private key, generate a new one and ask Sentinel:Cert-Api for a new certificate")
    sub.add_argument("-n", "--renew",
                     action="store_true",
                     help="ask Sentinel:Cert-Api for a new certificate and reuse the existing key")

    # MAILPASS
    sub = subparsers.add_parser("mailpass", help="Retrieve secret for notifications mail server")
    add_common_args(sub)
    sub.add_argument("-f", "--filename",
                     default="/etc/sentinel/mailpass",
                     help="path to file where the secret is stored")

    return parser


def key_match(obj, key):
    return obj.public_key().public_numbers() == key.public_key().public_numbers()


def load_or_remove_key(key_path):
    """ Load the private key from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(data=f.read(),
                                                     password=None,
                                                     backend=default_backend())
        return key
    except (ValueError, AssertionError):
        logger.info("Private key is inconsistent. Removing...")
        os.remove(key_path)
        return None


def load_or_remove_cert(cert_path, key):
    """ Load the certificate from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    except (ValueError, AssertionError):
        logger.info("Certificate file broken. Removing...")
        os.remove(cert_path)
        return None
    if key_match(cert, key):
        return cert
    else:
        logger.info("Certificate public key does not match. Removing...")
        os.remove(cert_path)
        return None


def load_or_remove_csr(csr_path, key):
    """ Load the certificate from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(csr_path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())
    except (ValueError, AssertionError):
        os.remove(csr_path)
        return None
    if key_match(csr, key):
        return csr
    else:
        os.remove(csr_path)
        return None


def extract_cert(cert_str, key):
    cert = x509.load_pem_x509_certificate(cert_str.encode("utf-8"), default_backend())
    if key_match(cert, key):
        return cert
    else:
        return None


def cert_expired(cert, csr_path, cert_path):
    now = datetime.datetime.utcnow()
    if cert.not_valid_after < now:
        logger.info("Certificate expired. Removing...")
        if os.path.exists(csr_path):
            os.remove(csr_path)
        if os.path.exists(cert_path):
            os.remove(cert_path)
        return True
    else:
        return False


def cert_to_expire(cert):
    now = datetime.datetime.utcnow()
    max_time_to_expire = datetime.timedelta(seconds=MAX_TIME_TO_EXPIRE)
    return cert.not_valid_after < (now + max_time_to_expire)


def clear_cert_dir(key_path, csr_path, cert_path):
    """ Remove (if exist) private and public keys and certificate
    signing request from Sentinel certificate directory.
    """
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(csr_path):
        os.remove(csr_path)
    if os.path.exists(cert_path):
        os.remove(cert_path)


def generate_priv_key_file(key_path):
    key = ec.generate_private_key(curve=ELLIPTIC_CURVE,
                                  backend=default_backend())
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.NoEncryption()))


def generate_csr_file(csr_path, sn, key):
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, sn),
    ]))
    csr = csr.sign(key, hashes.SHA256(), default_backend())

    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def save_cert(cert, cert_path):
    """ Save received certificate to a file.
    """
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


def get_digest(nonce):
    """ Returns atsha-based digest based on nonce.
    """
    process = subprocess.Popen(["atsha204cmd", "challenge-response"],
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE)
    nonce = "{}\n".format(nonce).encode("utf-8")
    # the return value is a list
    # remove "\n" at the and
    digest = process.communicate(input=nonce)[0][:-1]
    digest = digest.decode("utf-8")
    return digest


def get_sn():
    """ Returns atsha-based serial number.
    """
    process = subprocess.Popen(["atsha204cmd", "serial-number"], stdout=subprocess.PIPE)
    if process.wait() == 0:
        sn = process.stdout.read()[:-1].decode("utf-8")
        return sn
    else:
        raise CertgenError("ATSHA204 failed: sn")


class StateMachine:
    def __init__(self, ca_path, sn, api_url, flags, insecure_conn):
        self.ca_path = ca_path
        self.sn = sn
        self.api_url = api_url
        self.flags = flags
        self.use_tls = not insecure_conn
        self.start()

    def send_request(self, req_json):
        """ Send http POST request.
        """
        # Creating GET request to obtain
        req = urllib.request.Request("{}://{}/{}/{}".format(
                "https" if self.use_tls else "http",
                self.api_url, API_VERSION, self.ROUTE))
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        data = json.dumps(req_json).encode("utf8")

        # create ssl context
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self.ca_path:
            ctx.load_verify_locations(self.ca_path)
        else:
            ctx.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)
        resp = urllib.request.urlopen(req, data,
                                      context=ctx if self.use_tls else None)
        resp_json = resp.read()
        return resp_json

    def send_get(self):
        """ Send http request in the GET state.
        """
        req = {
            "type": "get",
            "auth_type": "atsha204",
            "sn": self.sn,
            "sid": self.sid,
            "flags": list(self.flags),
        }
        req.update(self.action_spec_params())
        recv = self.send_request(req)
        return json.loads(recv.decode("utf-8"))

    def send_auth(self, digest):
        """ Send http request in the AUTH state.
        """
        req = {
            "type": "auth",
            "auth_type": "atsha204",
            "sn": self.sn,
            "sid": self.sid,
            "digest": digest,
        }
        recv = self.send_request(req)
        return json.loads(recv.decode("utf-8"))

    def remove_flag_renew(self):
        if "renew" in self.flags:
            self.flags.remove("renew")

    def process_init(self):
        """ Processing the initial state. In this state, private key and
        certificate or any other possible files are loaded and checked.
        If something in the process fails the corrupted, inconsistent or invalid
        files may be deleted. Depending on the overall result this state may
        continue with states:
            GET:   when no consistent data are present or some data are missing
            VALID: when all the data are present and consistent
        """
        self.sid = ""
        # This section is handled by action-specific functions
        return self.action_spec_init()

    def process_get(self):
        """ Processing the GET state. In this state the application tries to
        download and save new data from Cert-api server. This state may
        continue with three states:
            INIT: * when a valid data are downloaded and saved (init must check
                    consistency and validity once more)
                  * the received data are not valid or some other error occurred
            AUTH: when there is no valid data available without authentication
            GET:  the certification process is still running, we have to wait
        """
        recv_json = self.send_get()
        self.nonce = None

        if recv_json.get("status") == "ok":
            return self.process_get_response(recv_json)

        elif recv_json.get("status") == "wait":
            logger.debug("Sleeping for {} seconds".format(recv_json["delay"]))
            time.sleep(recv_json["delay"])
            return "GET"

        elif recv_json.get("status") == "error":
            logger.error("Get Error. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
            time.sleep(ERROR_WAIT)
            return "INIT"

        elif recv_json.get("status") == "fail":
            logger.error("Get Fail. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
            time.sleep(ERROR_WAIT)
            return "INIT"

        elif recv_json.get("status") == "authenticate":
            self.sid = recv_json["sid"]
            self.nonce = recv_json["nonce"]
            return "AUTH"

        else:
            logger.error("Get: Unknown status {}".format(recv_json.get("status")))
            return "INIT"

    def process_auth(self):
        """ Processing the AUTH state. In this state the application authenticates to
        the Cert-api server. This state may continue with two states:
            GET:  authentication was successful, we can continue to download the
                  new data
            INIT: there was an error in the authentication process
        """
        # we do not save digest to a member variable because we won't use it anymore
        digest = get_digest(self.nonce)
        recv_json = self.send_auth(digest)

        if recv_json.get("status") == "accepted":
            self.remove_flag_renew()
            logger.debug("Auth accepted, sleeping for {} sec.".format(recv_json["delay"]))
            time.sleep(recv_json["delay"])
            return "GET"

        elif recv_json.get("status") == "error":
            logger.error("Auth Error. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
            time.sleep(ERROR_WAIT)
            return "INIT"

        elif recv_json.get("status") == "fail":
            logger.error("Auth Fail. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
            time.sleep(ERROR_WAIT)
            return "INIT"

        else:
            logger.error("Auth: Unknown status {}".format(recv_json.get("status")))
            return "INIT"

    def action_spec_init(self):
        """ Execute an action-specific processes at the beginning of the INIT
        state and return an appropriate next state name.
        """
        raise NotImplementedError("action_spec_init")

    def action_spec_params(self):
        """ Return action-specific parameters for get request.
        """
        return {}

    def process_get_response(self, response):
        """ Process data acquired from last get request and return the desired
        next state.
        """
        raise NotImplementedError("process_get_response")

    def start(self):
        state = "INIT"

        while True:
            if state == "INIT":  # look for file with consistent and fully valid cert or secret
                logger.debug("---> INIT state")
                state = self.process_init()

            elif state == "GET":  # if there is no cert/secret in file, download & save it form Cert-api
                logger.debug("---> GET state")
                state = self.process_get()

            elif state == "AUTH":  # if the API requires authentication
                logger.debug("---> AUTH state")
                state = self.process_auth()

            elif state == "VALID":  # final state
                logger.debug("---> VALID state")
                return

            else:
                logger.critical("Unknown next state %s", state)
                raise CertgenError("Unknown next state {}".format(state))


class CertMachine(StateMachine):
    ROUTE = "certs"

    def __init__(self, key_path, csr_path, cert_path, ca_path, sn, api_url, flags, ic):
        self.key_path = key_path
        self.csr_path = csr_path
        self.cert_path = cert_path
        super().__init__(ca_path, sn, api_url, flags, ic)

    def action_spec_params(self):
        """ Return certs action-specific parameters for get request
        """
        csr_str = self.csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return {"csr": csr_str}

    def action_spec_init(self):
        """ Processing the initial state. In this state, private key and certificate
        are loaded from the certificate directory. If something in the process fails
        the private key may be re-generated and a certificate signing request is
        prepared.
        Depending on the status of certificate file this state continues with status:
            GET:   when no consistent cert is present
            VALID: when the cert is present, consistent, valid and will not
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
            self.cert_sn = 0
        else:  # we have a cert
            if cert_expired(cert, self.csr_path, self.cert_path):
                self.cert_sn = 0
            else:
                if cert_to_expire(cert):
                    self.flags.add("renew")
                    self.cert_sn = cert.serial_number
                    logger.info("Certificate to expire. Renew flagged.")
                else:
                    if "renew" in self.flags:
                        self.cert_sn = cert.serial_number
                    else:
                        return "VALID"

        logger.info("Certificate file does not exist or is to be renewed. Re-certifying.")

        self.csr = None
        if os.path.exists(self.csr_path):
            self.csr = load_or_remove_csr(self.csr_path, self.key)
        if not self.csr:
            generate_csr_file(self.csr_path, self.sn, self.key)
            self.csr = load_or_remove_csr(self.csr_path, self.key)
        if self.csr:
            return "GET"
        else:
            logger.critical("Unable to acquire csr!")
            raise CertgenError("Unable to acquire csr!")

    def process_get_response(self, response):
        """ Process data acquired from last get request and return the desired
            next state.
            This function may return on of the three next states:
            INIT: * when a valid certificate is downloaded and saved (init must
                    check consistency of the certificate file)
                  * the received certificate is not valid or some other error
                    occurred
            GET:  the certs sn does not match - old cert still in cache, we have
                  to wait
        """
        cert = extract_cert(response["cert"], self.key)  # extract & consistency check
        if cert:
            if cert.serial_number != self.cert_sn:
                logger.info("New certificate successfully downloaded.")
                save_cert(cert, self.cert_path)
                return "INIT"
            else:
                logger.debug("New cert not yet available.  Sleeping for {} seconds".format(RENEW_WAIT))
                time.sleep(RENEW_WAIT)
                return "GET"
        else:
            logger.error("Obtained cert key does not match.")
            return "INIT"


def secret_ok(secret):
    return (len(secret) >= MIN_MAILPASS_CHARS)


class MailpassMachine(StateMachine):
    ROUTE = "mailpass"

    def __init__(self, filename, ca_path, sn, api_url, flags, ic):
        self.filename = filename
        super().__init__(ca_path, sn, api_url, flags, ic)

    def action_spec_init(self):
        """ Checks secret file existence and consistency of its content.
            Returns with "GET" when something fails and with "VALID" otherwise.
        """
        if not os.path.exists(self.filename):
            return "GET"

        try:
            with open(self.filename, "r") as f:
                secret = f.readline()
                if secret_ok(secret):
                    return "VALID"
            logger.info("Secret is not valid. Removing...")
        except (ValueError, AssertionError):
            logger.info("Secret is inconsistent. Removing...")
        except PermissionError:
            logger.critical("Can't read from the selected file '{}' - "
                            "permission denied".format(self.filename))
            exit()
        try:
            os.remove(self.filename)
        except PermissionError:
            logger.critical("Can't remove the selected file '{}' - "
                            "permission denied".format(self.filename))
            exit()
        return "GET"

    def process_get_response(self, response):
        """ Process data acquired from last get request and return the desired
            next state
        """
        if secret_ok(response.get("secret")):
            try:
                with open(self.filename, "w") as f:
                    f.write(response.get("secret"))
            except PermissionError:
                logger.critical("Can't write to the selected file '{}' - "
                                "permission denied".format(self.filename))
                exit()
            return "INIT"
        logger.debug("Obtained secret is invalid")
        return "INIT"


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    formatter = logging.Formatter("sentinel: %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
                                  "%Y-%m-%d %H:%M:%S")
    time_formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
                                       "%Y-%m-%d %H:%M:%S")
    syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
    syslog_handler.setFormatter(formatter)
    syslog_handler.setLevel(logging.INFO)
    logger.addHandler(syslog_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(time_formatter)
    logger.addHandler(console_handler)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)

    try:
        sn = get_sn()
    except CertgenError as e:
        logging.critical(str(e))
        return

    api_url = "{}:{}".format(args.cert_api_hostname, args.cert_api_port)
    ca_path = args.capath

    if args.command == "certs":
        if not os.path.exists(args.certdir):
            os.makedirs(args.certdir)

        csr_path = os.path.join(args.certdir, "mqtt_csr.pem")
        cert_path = os.path.join(args.certdir, "mqtt_cert.pem")
        key_path = os.path.join(args.certdir, "mqtt_key.pem")

        if args.regen_key:
            clear_cert_dir(key_path, csr_path, cert_path)

        flags = set()
        if not args.regen_key and args.renew:
            if os.path.exists(csr_path):
                os.remove(csr_path)
            flags.add("renew")

        CertMachine(key_path, csr_path, cert_path, ca_path, sn, api_url, flags,
                    args.insecure_connection)

    elif args.command == "mailpass":
        flags = set()
        MailpassMachine(args.filename, ca_path, sn, api_url, flags,
                        args.insecure_connection)


if __name__ == "__main__":
    main()
