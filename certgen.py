#!/usr/bin/env python3

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


KEY_TYPE = ec.SECP256R1()
MAX_TIME_TO_EXPIRE = 30*24*60*60
ERROR_WAIT = 5*60
API_VERSION = "v1"
RENEW_WAIT = 10

logger = logging.getLogger("certgen")
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())


def get_arg_parser():
    """ Returns argument parser object.
    """
    parser = argparse.ArgumentParser(description="Certgen - client for retrieving Turris:Sentinel certificates")
    parser.add_argument("--certdir",
                        nargs=1,
                        required=True,
                        help="path to Sentinel certificate location")
    parser.add_argument("-H", "--cert-api-hostname",
                        nargs=1,
                        required=True,
                        help="Certgen api hostname")
    parser.add_argument("-p", "--cert-api-port",
                        nargs=1,
                        required=True,
                        help="Certgen api port")
    parser.add_argument("-a", "--ca-certs",
                        nargs=1,
                        required=True,
                        help="File with CA certificates for TLS connection")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Raise console logging level to debug.")
    parser.add_argument("-n", "--renew",
                        action="store_true",
                        help="ask Sentinel:Cert-Api for a new certificate and reuse the existing key")
    parser.add_argument("--regen-key",
                        action="store_true",
                        help="remove private key, generate a new one and ask Sentinel:Cert-Api for a new certificate")
    return parser


def key_match(obj, key):
    """ Compares two public keys in different formats and returns true if they
    match.
    """
    try:
        obj_str = obj.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        key_str = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        return obj_str == key_str
    except (ValueError, AssertionError):
        return False


class CertgenError(Exception):
    pass


def get_crypto_name(cert_dir, sn, ext):
    return os.path.join(cert_dir, str.join(".", (str(sn), ext)))


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


def cert_expired(cert):
    due_date = time.mktime(cert.not_valid_after.timetuple())
    now = time.time()
    return due_date < now


def cert_to_expire(cert):
    due_date = time.mktime(cert.not_valid_after.timetuple())
    now = time.time()
    return due_date < (now + MAX_TIME_TO_EXPIRE)


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
    key = ec.generate_private_key(KEY_TYPE,
                                  backend=default_backend())
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.NoEncryption()))


def generate_csr_file(csr_path, sn, key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
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


def send_request(ca_path, url, req_json):
    """ Send http POST request.
    """
    # Creating GET request to obtain
    req = urllib.request.Request("https://{}".format(url))
    # TODO: remove next line before deployment to production
    if url[0:9] == "127.0.0.1":
        req = urllib.request.Request("http://{}/{}".format(url, API_VERSION))
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    data = json.dumps(req_json).encode("utf8")

    # TODO: remove next section before deployment to production
    if url[0:9] == "127.0.0.1":
        resp = urllib.request.urlopen(req, data)
        resp_json = resp.read()
        return resp_json

    # create ssl context
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.load_verify_locations(ca_path)
    resp = urllib.request.urlopen(req, data, context=ctx)
    resp_json = resp.read()
    return resp_json


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


def send_get(ca_path, url, csr, sn, sid, flags):
    """ Send http request in the GET state.
    """
    csr_str = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    req = {
        "api_version": API_VERSION,
        "type": "get_cert",
        "sn": sn,
        "sid": sid,
        "csr": csr_str,
        "flags": list(flags),
    }
    recv = send_request(ca_path, url, req)
    return json.loads(recv.decode("utf-8"))


def send_auth(ca_path, url, nonce, sn, sid):
    """ Send http request in the AUTH state.
    """
    digest = get_digest(nonce)
    req = {
        "api_version": API_VERSION,
        "type": "auth",
        "sn": sn,
        "sid": sid,
        "digest": digest,
    }
    recv = send_request(ca_path, url, req)
    return json.loads(recv.decode("utf-8"))


def remove_flag_renew(flags):
    if "renew" in flags:
        flags.remove("renew")


def process_init(key_path, csr_path, cert_path, sn, flags):
    """ Processing the initial state. In this state, private key and certicate
    are loaded from the certificate directory. If something in the process fails
    the private key may be re-generated and a certificate signing request is
    prepared.
    Depending on the status of certificate file this state continus with status:
        GET - when no consistent cert is present
        VALID - when the cert is present and consistent
    """
    sid = 0

    key = None
    if os.path.exists(key_path):
        key = load_or_remove_key(key_path)
    if not key:
        logger.info("Private key file not found. Generating new one.")
        generate_priv_key_file(key_path)
        key = load_or_remove_key(key_path)
        remove_flag_renew(flags)
    if not key:
        logger.critical("Unable to acquire private key!")
        raise CertgenError("Unable to acquire private key!")

    cert = None
    if os.path.exists(cert_path):
        cert = load_or_remove_cert(cert_path, key)
    if not cert:
        remove_flag_renew(flags)
        cert_sn = 0
    else:
        if "renew" not in flags:
            cert_sn = 0
            state = "VALID"
            return (state, sid, key, cert, None, cert_sn)
        else:
            cert_sn = cert.serial_number

    logger.info("Certificate file does not exist or is to be renewed. Re-certifying.")

    csr = None
    if os.path.exists(csr_path):
        csr = load_or_remove_csr(csr_path, key)
    if not csr:
        generate_csr_file(csr_path, sn, key)
        csr = load_or_remove_csr(csr_path, key)
    if csr:
        state = "GET"
        return (state, sid, key, None, csr, cert_sn)
    else:
        logger.critical("Unable to acquire csr!")
        raise CertgenError("Unable to acquire csr!")


def process_get(cert_path, ca_path, sn, sid, api_url, key, csr, flags, cert_sn):
    """ Processing the GET state. In this state the application tries to
    download and save new certificate from Cert-api server. This state may
    continue with three statuses:
        INIT: when a valid certificate is downloaded and saved (init must check
            consistency of certificate file)
        AUTH: when there is no valid cert in the server and authentication for
            the certification process in needed
        GET: the certification process is still running, we have to wait
        INIT: the received certificate is not valid or some other error occured
    """
    recv_json = send_get(ca_path, api_url, csr, sn, sid, flags)
    nonce = None
    if recv_json.get("status") == "ok":
        cert = extract_cert(recv_json["cert"], key)  # extract & consistency check
        if cert:
            if cert.serial_number != cert_sn:
                logger.info("New certificate succesfully downloaded.")
                save_cert(cert, cert_path)
                state = "INIT"
            else:
                logger.debug("New cert not yet available.  Sleeping for {} seconds".format(RENEW_WAIT))
                time.sleep(RENEW_WAIT)
                state = "GET"
        else:
            logger.error("Obtained cert key does not match.")
            state = "INIT"
    elif recv_json.get("status") == "wait":
        logger.debug("Sleeping for {} seconds".format(recv_json["delay"]))
        time.sleep(recv_json["delay"])
        state = "GET"
    elif recv_json.get("status") == "error":
        logger.error("Get Error. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
        state = "INIT"
        time.sleep(ERROR_WAIT)
    elif recv_json.get("status") == "fail":
        logger.error("Get Fail. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
        state = "INIT"
        time.sleep(ERROR_WAIT)
    elif recv_json.get("status") == "authenticate":
        sid = recv_json["sid"]
        nonce = recv_json["nonce"]
        state = "AUTH"
    else:
        logger.error("Get: Unknown error.")
        state = "INIT"
    return (state, sid, nonce)


def process_auth(ca_path, sn, sid, api_url, nonce, flags):
    """ Processing the AUTH state. In this state the application authenticates to
    the Cert-api server. This state may continue with two statuses:
        GET: authectication was succesfull, we can continue to download the
            new certificate
        INIT: there was an error in the authentication process
    """
    recv_json = send_auth(ca_path, api_url, nonce, sn, sid)
    if recv_json.get("status") == "accepted":
        remove_flag_renew(flags)
        logger.debug("Auth accepted, sleeping for {} sec.".format(recv_json["delay"]))
        time.sleep(recv_json["delay"])
        state = "GET"
    elif recv_json.get("status") == "error":
        logger.error("Auth Error. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
        state = "INIT"
        time.sleep(ERROR_WAIT)
    elif recv_json.get("status") == "fail":
        logger.error("Auth Fail. Sleeping for {} seconds before restart.".format(ERROR_WAIT))
        state = "INIT"
        time.sleep(ERROR_WAIT)
    else:
        logger.error("Auth: Unknown error.")
        state = "INIT"
    return state


def process_valid(key_path, csr_path, cert_path, cert, flags):
    """ Processing the VALID state. In this state the application checks the
    expiracy of the certificate. This state may continue with two statuses:
        VALID: the certificate did not expired and is not going to expire in
            within a defined time
        INIT: the certificate fully or nearly expired, it will be removed
            or/and replaced by a new one.
    """
    if cert_expired(cert):
        logger.info("Certificate expired. Removing...")
        if os.path.exists(csr_path):
            os.remove(csr_path)
        if os.path.exists(cert_path):
            os.remove(cert_path)
        state = "INIT"
        return state

    if cert_to_expire(cert):
        flags.add("renew")
        logger.info("Certificate to expire. Renew flagged.")
        state = "INIT"
        return state

    else:
        state = "VALID"
    return state


def start_state_machine(key_path, csr_path, cert_path, ca_path, sn, api_url, flags):
    state = "INIT"
    while True:
        if state == "INIT":  # look for file with consistent certificate
            logger.debug("---> INIT state")
            state, sid, key, cert, csr, cert_sn = process_init(key_path, csr_path, cert_path, sn, flags)
        elif state == "GET":  # if there is no cert in file, download & save cert form Cert-api
            logger.debug("---> GET state")
            state, sid, nonce = process_get(cert_path, ca_path, sn, sid, api_url, key, csr, flags, cert_sn)
        elif state == "AUTH":  # if there is no valid cert in Cert-api, ask for a new one
            logger.debug("---> AUTH state")
            state = process_auth(ca_path, sn, sid, api_url, nonce, flags)
        elif state == "VALID":  # Check certificate expiration
            logger.debug("---> VALID state")
            state = process_valid(key_path, csr_path, cert_path, cert, flags)
            if state == "VALID":  # if the VALID state stays valid, exit the app
                break


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

    process = subprocess.Popen(["atsha204cmd", "serial-number"], stdout=subprocess.PIPE)
    if process.wait() == 0:
        sn = process.stdout.read()[:-1].decode("utf-8")
    else:
        logging.critical("ATSHA204 failed: sn")
        return
    api_url = "{}:{}".format(args.cert_api_hostname[0], args.cert_api_port[0])

    csr_path = get_crypto_name(args.certdir[0], sn, "csr")
    cert_path = get_crypto_name(args.certdir[0], sn, "pem")
    key_path = get_crypto_name(args.certdir[0], sn, "key")
    ca_path = args.ca_certs[0]

    if args.regen_key:
        clear_cert_dir(key_path, csr_path, cert_path)

    flags = set()
    if not args.regen_key and args.renew:
        if os.path.exists(csr_path):
            os.remove(csr_path)
        flags.add("renew")

    start_state_machine(key_path, csr_path, cert_path, ca_path, sn, api_url, flags)


if __name__ == "__main__":
    main()
