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
        raise argparse.ArgumentTypeError("Serial number must be 16 character long hexadecimal number")
    return string


def get_arg_parser():
    """ Returns argument parser object.
    """
    parser = argparse.ArgumentParser(description='Certgen - client for retrieving Turris:Sentinel certificates')
    parser.add_argument(
        '--debug-sn',
        nargs=1,
        type=serial,
        help='emulate serial number for debug purposes. DEBUG-SN is a 16-digit hexadecimal number.'
    )
    parser.add_argument(
        '--certdir',
        nargs=1,
        required=True,
        help='path to Sentinel certificate location'
    )
    parser.add_argument(
        '--cert-api-address',
        nargs=1,
        required=True,
        help='Certgen api address'
    )
    parser.add_argument(
        '--cert-api-port',
        nargs=1,
        required=True,
        help='Certgen api port'
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
        help='remove private key, generate a new one and ask Sentinel:Cert-Api for a new certificate'
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


class CertgenError(Exception):
    pass


def get_crypto_name(cert_dir, sn, ext):
        return str.join('/', (cert_dir, str.join('.', (str(sn), ext))))


def load_key(key_path):
        """ Load the private key from a file or, if it is damaged, remove it from
        the filesystem.
        """
        try:
            with open(key_path, "r") as key_file:
                key = crypto.load_privatekey(
                    crypto.FILETYPE_PEM,
                    key_file.read()
                )
        except crypto.Error:
            root_logger.debug("Private key is inconsistent. Removing..")
            os.remove(key_path)
            return None
        if key.check():
            root_logger.debug("Private key loaded.")
            return key
        else:
            root_logger.debug("Private key is inconsistent. Removing..")
            os.remove(key_path)
            return None


def load_cert(cert_path, key):
        """ Load the certificate from a file or, if it is damaged, remove it from
        the filesystem.
        """
        try:
            with open(cert_path, "r") as cert_file:
                cert = crypto.load_certificate(
                    crypto.FILETYPE_PEM,
                    cert_file.read()
                )
        except crypto.Error:
            root_logger.debug("Certificate file broken. Removing..")
            os.remove(cert_path)
            return None
        if key_match(cert, key):
            root_logger.debug("Certificate loaded.")
            return cert
        else:
            root_logger.debug("Certificate public key does not match. Removing..")
            os.remove(cert_path)
            return None


def load_csr(csr_path, key):
        """ Load the certificate from a file or, if it is damaged, remove it from
        the filesystem.
        """
        try:
            with open(csr_path, "r") as csr_file:
                csr = crypto.load_certificate_request(
                    crypto.FILETYPE_PEM,
                    csr_file.read()
                )
        except crypto.Error:
            root_logger.debug("CSR file is inconsistent. Removing..")
            os.remove(csr_path)
            return None
        if key_match(csr, key):
            root_logger.debug("CSR loaded.")
            return csr
        else:
            root_logger.debug("CSR public key does not match. Removing..")
            os.remove(csr_path)
            return None


def prepare_key(key_path):
        """ Load or re-generate private key.
        """
        key = None
        if os.path.exists(key_path):
            root_logger.debug("Private key file exists.")
            key = load_key(key_path)
        if key:
            return key

        root_logger.debug("Private key file not found. Generating new one.")
        generate_priv_key_file(key_path)
        key = load_key(key_path)
        if key:
            return key
        else:
            root_logger.critical("Unable to acquire private key!")
            raise CertgenError("Unable to acquire private key!")


def extract_cert(cert_str, key):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)
    if key_match(cert, key):
        return cert
    else:
        return None


def cert_expired(cert):
        due_date = cert.get_notAfter().decode("utf-8")
        due_date = datetime.datetime.strptime(due_date, "%Y%m%d%H%M%SZ")
        due_date = time.mktime(due_date.timetuple())
        now = time.time()
        return due_date - now < MAX_TIME_TO_EXPIRE


def clear_cert_dir(key_path, csr_path, cert_path):
        """ Remove (if exist) private and public keys and certificate
        sifning request from Sentinel certificate directory.
        """
        if os.path.exists(key_path):
            os.remove(key_path)
        if os.path.exists(csr_path):
            os.remove(csr_path)
        if os.path.exists(cert_path):
            os.remove(cert_path)


def generate_priv_key_file(key_path):
        key = crypto.PKey()
        key.generate_key(KEY_TYPE, KEY_LEN)
        with open(key_path, "w") as key_file:
            key_file.write(crypto.dump_privatekey(
                type=crypto.FILETYPE_PEM,
                pkey=key
            ).decode("utf-8"))


def generate_csr_file(cert_path, sn, key):
        csr = crypto.X509Req()
        csr.get_subject().CN = sn
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

        csr.set_pubkey(key)
        csr.sign(key, "sha256")

        with open(csr_path, "w") as csr_file:
            csr_file.write(crypto.dump_certificate_request(
                type=crypto.FILETYPE_PEM,
                req=csr
            ).decode("utf-8"))


def save_cert(cert, cert_path):
        """ Save received certificate to a file.
        """
        with open(cert_path, "w") as cert_file:
            cert_file.write(crypto.dump_certificate(
                type=crypto.FILETYPE_PEM,
                cert=cert
            ).decode("utf-8"))


def send_request(url, req_json):
        """ Send http POST request.
        """
        # Creating GET request to obtain / check uuid
        req = urllib2.Request(url)
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


def get_digest(nonce):
        process = subprocess.Popen(
            ["atsha204cmd", "challenge-response"],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        digest = process.communicate(input=nonce+'\n')[0]
        return digest


def send_get(url, csr, sn, sid):
    csr_str = crypto.dump_certificate_request(
        type=crypto.FILETYPE_PEM,
        req=csr
    ).decode("utf-8")
    req = {
        "api_version": "0.1",
        "type": "get_cert",
        "sn": sn,
        "sid": sid,
        "csr": csr_str,
    }
    recv = send_request(url, req)
    return json.loads(recv.decode("utf-8"))


def send_auth(url, nonce, sn, sid):
    digest = get_digest(nonce)
    req = {
        "api_version": "0.1",
        "type": "auth",
        "sn": sn,
        "sid": sid,
        "digest": digest,
    }
    recv = send_request(url, req)
    return json.loads(recv.decode("utf-8"))


def process_init(key_path, csr_path, cert_path):
    sid = 0
    key = prepare_key(key_path)
    cert = None
    if os.path.exists(cert_path):
        root_logger.debug("Certificate file exists.")
        cert = load_cert(cert_path, key)
    if cert:
        if cert_expired(cert):
            root_logger.debug("Certificate is about to expire. Removing..")
            clear_cert_dir(key_path, csr_path, cert_path)
            key = prepare_key(key_path)
            cert = None
        else:
            root_logger.debug("Certificate not expired.")
            root_logger.debug("Success, quitting..")
            exit()

    root_logger.debug("Certificate file does not exist. Re-certyfing.")
    csr = None
    if os.path.exists(csr_path):
        root_logger.debug("CSR file exist.")
        csr = load_csr(csr_path, key)
    if not csr:
        root_logger.debug("CSR file not found. Generating a new one.")
        generate_csr_file(csr_path, sn, key)
        csr = load_csr(csr_path, key)
    if csr:
        state = "GET"
        return (state, sid, key, csr)
    else:
        root_logger.critical("Unable to acquire csr!")
        raise CertgenError("Unable to acquire csr!")


def process_get(cert_path, sn, sid, api_url, key, csr):
    recv_json = send_get(api_url, csr, sn, sid)
    nonce = None
    state = "GET"
    if recv_json.get("status") == 'ok':
        cert = extract_cert(recv_json["cert"], key)
        if cert:
            root_logger.debug("Saving obtained certificate.")
            save_cert(cert, cert_path)
            state = "INIT"
        else:
            root_logger.error("Obtained cert key does not match.")
            state = "INIT"

    elif recv_json.get("status") == 'wait':
        root_logger.debug("Sleeping for {} seconds".format(recv_json['delay']))
        time.sleep(recv_json['delay'])
    elif recv_json.get("status") == 'error':
        root_logger.error("Get Error.")
        state = "INIT"
    elif recv_json.get("status") == 'fail':
        root_logger.error("Get Fail.")
        state = "INIT"
    elif recv_json.get("status") == 'authenticate':
        root_logger.debug("Authentication request.")
        sid = recv_json['sid']
        nonce = recv_json['nonce']
        state = "AUTH"
    else:
        root_logger.error("Get: Unknown error.")
    return (state, sid, nonce)


def process_auth(sn, sid, api_url, nonce):
    recv_json = send_auth(api_url, nonce, sn, sid)
    if recv_json.get("status") == "accepted":
        root_logger.debug("Auth accepted, sleeping for {} sec.".format(recv_json['delay']))
        time.sleep(recv_json['delay'])
        state = "GET"
    else:
        root_logger.error("Auth: Unknown error.")
        state = "INIT"
    return state


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
    api_url = "{}:{}".format(args.cert_api_address[0], args.cert_api_port[0])

    csr_path = get_crypto_name(args.certdir[0], sn, "csr")
    cert_path = get_crypto_name(args.certdir[0], sn, "pem")
    key_path = get_crypto_name(args.certdir[0], sn, "key")

    if args.force_renew:
        clear_cert_dir(key_path, csr_path, cert_path)

    state = "INIT"
    while True:
        if state == "INIT":
            root_logger.debug("---> INIT state")
            state, sid, key, csr = process_init(key_path, csr_path, cert_path)
        elif state == "GET":
            root_logger.debug("---> GET state")
            state, sid, nonce = process_get(cert_path, sn, sid, api_url, key, csr)

        elif state == "AUTH":
            root_logger.debug("---> AUTH state")
            state = process_auth(sn, sid, api_url, nonce)
