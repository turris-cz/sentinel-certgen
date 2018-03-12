#!/usr/bin/env python

from OpenSSL import crypto
import os
import subprocess
import urllib2
import ssl
import json
import argparse
import re
import time
import datetime
import logging


KEY_TYPE = crypto.TYPE_RSA
KEY_LEN = 4096
MAX_TIME_TO_EXPIRE = 30*24*60*60


def hexa_match(string):
    """ Check whether the string contains only hexadecimal characters
    """
    return not re.compile(r'[^a-fA-f0-9]').search(string)


def serial(string):
    """ Value-checking for argument parser.
    """
    if len(string) != 16 or not hexa_match(string):
        raise argparse.ArgumentTypeError(
            "Serial number must be 16 character long hexadecimal number"
        )
    return string


def get_arg_parser():
    """ Returns argument parser object.
    """
    parser = argparse.ArgumentParser(
        description='Certgen - client for retrieving Turris:Sentinel '
        ' certificates'
    )
    parser.add_argument(
        '--debug-sn',
        nargs=1,
        type=serial,
        help='emulate serial number for debug purposes. DEBUG-SN is a '
        '16-digit hexadecimal number.'
    )
    parser.add_argument(
        '--certdir',
        nargs=1,
        required=True,
        help='path to Sentinel certificate location'
    )
    parser.add_argument(
        '--auth-api-address',
        nargs=1,
        required=True,
        help='authentication api address'
    )
    parser.add_argument(
        '--auth-api-port',
        nargs=1,
        required=True,
        help='authentication api port'
    )
    parser.add_argument(
        '--console-log',
        type=int,
        choices=range(1, 51),
        help='Enables logging to console for the level 1..50'
    )
    parser.add_argument(
        '--force-renew',
        action='store_true',
        help='remove private key, generate a new one and ask '
        ' Sentinel:Authenticator for a new certificate'
    )
    return parser


def key_match(obj, key):
    """ Compares two public keys in different formats and returns true if they
    match.
    """
    obj_pubkey_str = crypto.dump_publickey(
        type=crypto.FILETYPE_PEM,
        pkey=obj.get_pubkey(),
    ).decode("utf-8")
    key_pubkey_str = crypto.dump_publickey(
        type=crypto.FILETYPE_PEM,
        pkey=key,
    ).decode("utf-8")
    return obj_pubkey_str == key_pubkey_str


class Certgen:
    def __init__(self, sn, cert_dir, auth_address, auth_port):
        self.sn = sn
        self.cert_dir = cert_dir
        self.auth_address = auth_address
        self.auth_port = auth_port
        self.key_path = self.get_crypto_name("key")
        self.csr_path = self.get_crypto_name("csr")
        self.cert_path = self.get_crypto_name("pem")

    def get_crypto_name(self, ext):
        return str.join(
            '/', (self.cert_dir, str.join('.', (str(self.sn), ext)))
        )

    def set_state_init(self):
        """ Initial state. Checking existance and validity of the private key
        and certificate. If something of this fail, new CSR (certificate sign
        request) is created and state GET is set.
        """
        self.key_path = self.get_crypto_name("key")
        self.csr_path = self.get_crypto_name("csr")
        self.cert_path = self.get_crypto_name("pem")
        self.key = None
        self.csr = None
        self.cert = None
        self.sid = 0

        while True:
            root_logger.debug("---> INIT state")
            if not self.key:
                if os.path.exists(self.key_path):
                    root_logger.debug("Private key file exists.")
                    try:
                        with open(self.key_path, "r") as key_file:
                            key = crypto.load_privatekey(
                                crypto.FILETYPE_PEM,
                                key_file.read()
                            )
                    except crypto.Error:
                        root_logger.debug(
                           "Private key is inconsistent, generating a new one."
                        )
                        self.clear_cert_dir()
                        self.generate_priv_key()
                        continue
                    if key.check():
                            self.key = key
                            root_logger.debug("Private key loaded.")
                    else:
                        root_logger.debug(
                           "Private key is inconsistent, generating a new one."
                        )
                        self.clear_cert_dir()
                        self.generate_priv_key()
                        continue

                else:
                    root_logger.debug("Private key file not found")
                    root_logger.debug("Private key: generating a new one.")
                    self.clear_cert_dir()
                    self.generate_priv_key()
                    continue

            if os.path.exists(self.cert_path):
                root_logger.debug("Certificate file exists.")
                try:
                    with open(self.cert_path, "r") as cert_file:
                        cert = crypto.load_certificate(
                            crypto.FILETYPE_PEM,
                            cert_file.read()
                        )
                except crypto.Error:
                    root_logger.debug(
                        "Certificate file broken. Re-certifying...")
                    os.remove(self.cert_path)
                    continue
                due_date = time.mktime(datetime.datetime.strptime(
                    cert.get_notAfter().decode("utf-8"),
                    "%Y%m%d%H%M%SZ",
                ).timetuple())
                now = time.time()
                if (due_date - now < MAX_TIME_TO_EXPIRE):
                    root_logger.debug(
                        "Certificate is about to expire. Re-certifying.."
                    )
                    self.key = None
                    self.clear_cert_dir()
                    continue
                else:
                    root_logger.debug("Certificate not expired.")
                if key_match(cert, self.key):
                    self.cert = cert
                    root_logger.debug("Certificate loaded.")
                    break
                else:
                    root_logger.debug(
                        "Certificate public key does not match. "
                        "Re-certifying..."
                    )
                    os.remove(self.cert_path)
                    continue

            else:
                root_logger.debug(
                    "Certificate file does not exist. Re-certyfing.")
                if os.path.exists(self.csr_path):
                    root_logger.debug("CSR file exist.")
                    try:
                        with open(self.csr_path, "r") as csr_file:
                            csr = crypto.load_certificate_request(
                                crypto.FILETYPE_PEM,
                                csr_file.read()
                            )
                    except crypto.Error:
                        root_logger.debug(
                            "CSR file is inconsistent, generating a new one."
                        )
                        os.remove(self.csr_path)
                        self.generate_csr()
                        continue

                    if key_match(csr, self.key):
                        self.csr = csr
                        root_logger.debug("CSR loaded.")
                        while (not self.set_state_get()):
                            pass
                    else:
                        root_logger.debug(
                            "CSR public key does not match, "
                            "generating a new one."
                        )
                        os.remove(self.csr_path)
                        self.generate_csr()
                        continue

                else:
                    root_logger.debug(
                        "CSR file not found. Generating a new one.")
                    self.generate_csr()
                    continue

    def set_state_get(self):
        """ In this state, certificate is being requested using CSR. If no
        certificate that corresponds to the CSR exists, new certificate must
        be generated - to resolve this Certgen is switched to the AUTH state.
        """
        root_logger.debug("---> GET state")
        csr_str = crypto.dump_certificate_request(
            type=crypto.FILETYPE_PEM,
            req=self.csr
        ).decode("utf-8")
        req = {
            "api_version": "0.1",
            "type": "get_cert",
            "sn": self.sn,
            "sid": self.sid,
            "csr": csr_str,
        }

        recv = self.send_request(req)
        recv_json = json.loads(recv.decode("utf-8"))

        if recv_json.get("status") == 'ok':
            cert = crypto.load_certificate(
                crypto.FILETYPE_PEM,
                recv_json['cert']
            )
            if key_match(cert, self.key):
                self.save_cert(cert)
                root_logger.debug("Saving obtained certificate.")
                return True
            else:
                root_logger.debug("Obtained cert key does not match.")
                return False
        elif recv_json.get("status") == 'wait':
            root_logger.debug(
                "Sleeping for {} seconds".format(recv_json['delay']))
            time.sleep(recv_json['delay'])
        elif recv_json.get("status") == 'error':
            root_logger.debug("Get Error.")
            return False
        elif recv_json.get("status") == 'fail':
            root_logger.debug("Get Fail.")
            return False
        elif recv_json.get("status") == 'authenticate':
            self.sid = recv_json['sid']
            self.nonce = recv_json['nonce']
            self.set_state_auth()
        else:
            root_logger.debug("Get: Unknown error.")

    def set_state_auth(self):
        """ In this state we get a nonce andi, using Atcha, generate digest.
        The digest is sent to the cert-api to complete the authentication and
        certificate creation.
        """
        root_logger.debug("---> AUTH state")
        self.digest = self.get_digest(self.nonce)
        req = {
            "api_version": "0.1",
            "type": "auth",
            "sn": self.sn,
            "sid": self.sid,
            "digest": self.digest,
        }

        recv = self.send_request(req)
        recv_json = json.loads(recv.decode("utf-8"))
        if recv_json.get("status") == "accepted":
            root_logger.debug("Auth accepted, sleeping for {} sec.".format(
                recv_json['delay']
            ))
            time.sleep(recv_json['delay'])
        else:
            root_logger.debug("Auth: Unknown error.")

    def clear_cert_dir(self):
        """ Remove (if exist) private and public keys and certificate
        sifning request from Sentinel certificate directory.
        """
        root_logger.debug("Clearing certificate directory.")

        if os.path.exists(self.key_path):
            os.remove(self.key_path)
        if os.path.exists(self.csr_path):
            os.remove(self.csr_path)
        if os.path.exists(self.cert_path):
            os.remove(self.cert_path)

    def generate_priv_key(self):
        key = crypto.PKey()
        key.generate_key(KEY_TYPE, KEY_LEN)
        with open(self.key_path, "w") as key_file:
            key_file.write(crypto.dump_privatekey(
                type=crypto.FILETYPE_PEM,
                pkey=key
            ).decode("utf-8"))

    def generate_csr(self):
        csr = crypto.X509Req()
        csr.get_subject().CN = self.sn
        csr.get_subject().countryName = "cz"
        csr.get_subject().stateOrProvinceName = "Prague"
        csr.get_subject().localityName = "Prague"
        csr.get_subject().organizationName = "CZ.NIC"
        csr.get_subject().organizationalUnitName = "Turris"

        # Add in extensions
        x509_extensions = ([
            crypto.X509Extension(
                b"keyUsage",
                False,
                b"Digital Signature, Non Repudiation, Key Encipherment"
            ),
            crypto.X509Extension(
                b"basicConstraints",
                False,
                b"CA:FALSE"),
        ])
        csr.add_extensions(x509_extensions)

        csr.set_pubkey(self.key)
        csr.sign(self.key, "sha256")

        with open(self.csr_path, "w") as csr_file:
            csr_file.write(crypto.dump_certificate_request(
                type=crypto.FILETYPE_PEM,
                req=csr
            ).decode("utf-8"))

    def save_cert(self, cert):
        """ Save received certificate to a file.
        """
        with open(self.cert_path, "w") as cert_file:
            cert_file.write(crypto.dump_certificate(
                type=crypto.FILETYPE_PEM,
                cert=cert
            ).decode("utf-8"))

    def send_request(self, req_json):
        """ Send http POST request.
        """
        # Creating GET request to obtain / check uuid
        req = urllib2.Request(
                "{}:{}".format(self.auth_address, self.auth_port)
        )
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        data = json.dumps(req_json).encode('utf8')

        # create ssl context
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_default_verify_paths()
        ctx.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)
        ctx.load_verify_locations("ca.pem")
        resp = urllib2.urlopen(req, data, context=ctx)
        resp_json = resp.read()
        return resp_json

    def get_digest(self, nonce):
        process = subprocess.Popen(
            ["atsha204cmd", "challenge-response"],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        digest = process.communicate(input=nonce+'\n')[0]
        return digest


if __name__ == "__main__":
    root_logger = logging.getLogger()
    root_logger.setLevel('DEBUG')
    root_logger.addHandler(logging.NullHandler())

    parser = get_arg_parser()
    args = parser.parse_args()

    if args.console_log:
        cl = logging.StreamHandler()
        cl.setLevel(args.console_log)
        cl.formatter = logging.Formatter('%(levelname)s:%(message)s')
        root_logger.addHandler(cl)

    if args.debug_sn:
        sn = args.debug_sn[0]
    else:
        process = subprocess.Popen(
            ["atsha204cmd", "serial-number"],
            stdout=subprocess.PIPE
        )
        if process.wait() == 0:
            sn = process.stdout.read()[:-1]
        else:
            logging.critical("Atcha failed: sn")
            exit()

    certgen = Certgen(
            sn, args.certdir[0], args.auth_api_address[0],
            args.auth_api_port[0])
    if args.force_renew:
        certgen.clear_cert_dir()
    certgen.set_state_init()
