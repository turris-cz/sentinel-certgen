#!/usr/bin/env python

from OpenSSL import crypto
import os
import subprocess
import urllib2
import ssl
import json
import argparse
import time
import datetime
import logging


KEY_TYPE = crypto.TYPE_RSA
KEY_LEN = 4096
MAX_TIME_TO_EXPIRE = 30*24*60*60

logger = logging.getLogger("certgen")
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())


def get_arg_parser():
    """ Returns argument parser object.
    """
    parser = argparse.ArgumentParser(description="Certgen - client for retrieving Turris:Sentinel certificates")
    parser.add_argument(
        "--certdir",
        nargs=1,
        required=True,
        help="path to Sentinel certificate location"
    )
    parser.add_argument(
        "-H", "--cert-api-hostname",
        nargs=1,
        required=True,
        help="Certgen api hostname"
    )
    parser.add_argument(
        "-p", "--cert-api-port",
        nargs=1,
        required=True,
        help="Certgen api port"
    )
    parser.add_argument(
        "-a", "--ca-certs",
        nargs=1,
        required=True,
        help="File with CA certificates for TLS connection"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Raise logging level to debug"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enables logging to console"
    )
    parser.add_argument(
        "--force-renew",
        action="store_true",
        help="remove private key, generate a new one and ask Sentinel:Cert-Api for a new certificate"
    )
    return parser


def key_match(obj, key):
    """ Compares two public keys in different formats and returns true if they
    match.
    """
    obj_pubkey_str = crypto.dump_publickey(type=crypto.FILETYPE_PEM, pkey=obj.get_pubkey()).decode("utf-8")
    key_pubkey_str = crypto.dump_publickey(type=crypto.FILETYPE_PEM, pkey=key).decode("utf-8")
    return obj_pubkey_str == key_pubkey_str


class CertgenError(Exception):
    pass


def get_crypto_name(cert_dir, sn, ext):
    return str.join("/", (cert_dir, str.join(".", (str(sn), ext))))


def load_key(key_path):
    """ Load the private key from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(key_path, "r") as key_file:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    except crypto.Error:
        logger.info("Private key is inconsistent. Removing..")
        os.remove(key_path)
        return None
    if key.check():
        return key
    else:
        logger.info("Private key is inconsistent. Removing..")
        os.remove(key_path)
        return None


def load_cert(cert_path, key):
    """ Load the certificate from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(cert_path, "r") as cert_file:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
    except crypto.Error:
        logger.info("Certificate file broken. Removing..")
        os.remove(cert_path)
        return None
    if key_match(cert, key):
        return cert
    else:
        logger.info("Certificate public key does not match. Removing..")
        os.remove(cert_path)
        return None


def load_csr(csr_path, key):
    """ Load the certificate from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(csr_path, "r") as csr_file:
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_file.read())
    except crypto.Error:
        os.remove(csr_path)
        return None
    if key_match(csr, key):
        return csr
    else:
        os.remove(csr_path)
        return None


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
        key_file.write(crypto.dump_privatekey(type=crypto.FILETYPE_PEM, pkey=key).decode("utf-8"))


def generate_csr_file(csr_path, sn, key):
    csr = crypto.X509Req()
    csr.get_subject().CN = sn
    csr.get_subject().countryName = "cz"
    csr.get_subject().stateOrProvinceName = "Prague"
    csr.get_subject().localityName = "Prague"
    csr.get_subject().organizationName = "CZ.NIC"
    csr.get_subject().organizationalUnitName = "Turris"

    # Add in extensions
    x509_extensions = ([
        crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE")
    ])
    csr.add_extensions(x509_extensions)

    csr.set_pubkey(key)
    csr.sign(key, "sha256")

    with open(csr_path, "w") as csr_file:
        csr_file.write(crypto.dump_certificate_request(type=crypto.FILETYPE_PEM, req=csr).decode("utf-8"))


def save_cert(cert, cert_path):
    """ Save received certificate to a file.
    """
    with open(cert_path, "w") as cert_file:
        cert_file.write(crypto.dump_certificate(type=crypto.FILETYPE_PEM, cert=cert).decode("utf-8"))


def send_request(ca_path, url, req_json):
    """ Send http POST request.
    """
    # Creating GET request to obtain / check uuid
    req = urllib2.Request("https://{}".format(url))
    # TODO: remove next line before deployment to production
    if url[0:9] == "127.0.0.1":
        req = urllib.request.Request("http://{}/{}".format(url, API_VERSION))
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    data = json.dumps(req_json).encode("utf8")

    # TODO: remove next section before deployment to production
    if url[0:9] == "127.0.0.1":
        resp = urllib2.urlopen(req, data)
        resp_json = resp.read()
        return resp_json

    # create ssl context
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.set_default_verify_paths()
    ctx.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.load_verify_locations(ca_path)
    resp = urllib2.urlopen(req, data, context=ctx)
    resp_json = resp.read()
    return resp_json


def get_digest(nonce):
    """ Returns atsha-based digest based on nonce.
    """
    process = subprocess.Popen(
            ["atsha204cmd", "challenge-response"],
            stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # the return value is a list
    # remove "\n" at the and
    digest = process.communicate(input=nonce+"\n")[0][:-1]
    return digest


def send_get(ca_path, url, csr, sn, sid):
    """ Send http request in the GET state.
    """
    csr_str = crypto.dump_certificate_request(type=crypto.FILETYPE_PEM, req=csr).decode("utf-8")
    req = {
        "api_version": "0.1",
        "type": "get_cert",
        "sn": sn,
        "sid": sid,
        "csr": csr_str,
    }
    recv = send_request(ca_path, url, req)
    return json.loads(recv.decode("utf-8"))


def send_auth(ca_path, url, nonce, sn, sid):
    """ Send http request in the AUTH state.
    """
    digest = get_digest(nonce)
    req = {
        "api_version": "0.1",
        "type": "auth",
        "sn": sn,
        "sid": sid,
        "digest": digest,
    }
    recv = send_request(ca_path, url, req)
    return json.loads(recv.decode("utf-8"))


def process_init(key_path, csr_path, cert_path, sn):
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
        key = load_key(key_path)
    if not key:
        logger.info("Private key file not found. Generating new one.")
        generate_priv_key_file(key_path)
        key = load_key(key_path)
    if not key:
        logger.critical("Unable to acquire private key!")
        raise CertgenError("Unable to acquire private key!")

    cert = None
    if os.path.exists(cert_path):
        cert = load_cert(cert_path, key)
    if cert:
        state = "VALID"
        return (state, sid, key, cert, None)
    logger.info("Certificate file does not exist. Re-certifying.")

    csr = None
    if os.path.exists(csr_path):
        csr = load_csr(csr_path, key)
    if not csr:
        generate_csr_file(csr_path, sn, key)
        csr = load_csr(csr_path, key)
    if csr:
        state = "GET"
        return (state, sid, key, None, csr)
    else:
        logger.critical("Unable to acquire csr!")
        raise CertgenError("Unable to acquire csr!")


def process_get(cert_path, ca_path, sn, sid, api_url, key, csr):
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
    recv_json = send_get(ca_path, api_url, csr, sn, sid)
    nonce = None
    if recv_json.get("status") == "ok":
        cert = extract_cert(recv_json["cert"], key)  # extract & consistency check
        if cert:
            logger.info("New certificate succesfully downloaded.")
            save_cert(cert, cert_path)
            state = "INIT"
        else:
            logger.error("Obtained cert key does not match.")
            state = "INIT"
    elif recv_json.get("status") == "wait":
        logger.debug("Sleeping for {} seconds".format(recv_json["delay"]))
        time.sleep(recv_json["delay"])
        state = "GET"
    elif recv_json.get("status") == "error":
        logger.error("Get Error.")
        state = "INIT"
    elif recv_json.get("status") == "fail":
        logger.error("Get Fail.")
        state = "INIT"
    elif recv_json.get("status") == "authenticate":
        sid = recv_json["sid"]
        nonce = recv_json["nonce"]
        state = "AUTH"
    else:
        logger.error("Get: Unknown error.")
    return (state, sid, nonce)


def process_auth(ca_path, sn, sid, api_url, nonce):
    """ Processing the AUTH state. In this state the application authenticates to
    the Cert-api server. This state may continue with two statuses:
        GET: authectication was succesfull, we can continue to download the
            new certificate
        INIT: there was an error in the authentication process
    """
    recv_json = send_auth(ca_path, api_url, nonce, sn, sid)
    if recv_json.get("status") == "accepted":
        logger.debug("Auth accepted, sleeping for {} sec.".format(recv_json["delay"]))
        time.sleep(recv_json["delay"])
        state = "GET"
    else:
        logger.error("Auth: Unknown error.")
        state = "INIT"
    return state


def process_valid(key_path, csr_path, cert_path, cert):
    """ Processing the VALID state. In this state the application checks the
    expiracy of the certificate. This state may continue with two statuses:
        VALID: the certificate did not expired and is not going to expire in
            within a defined time
        INIT: the certificate fully or nearly expired, it will be removed
    """
    if cert_expired(cert):
        logger.info("Certificate is about to expire. Removing..")
        clear_cert_dir(key_path, csr_path, cert_path)
        state = "INIT"
    else:
        state = "VALID"
    return state


def start_state_machine(key_path, csr_path, cert_path, ca_path, sn, api_url):
    state = "INIT"
    while True:
        if state == "INIT":  # look for file with consistent certificate
            logger.debug("---> INIT state")
            state, sid, key, cert, csr = process_init(key_path, csr_path, cert_path, sn)
        elif state == "GET":  # if there is no cert in file, download & save cert form Cert-api
            logger.debug("---> GET state")
            state, sid, nonce = process_get(cert_path, ca_path, sn, sid, api_url, key, csr)
        elif state == "AUTH":  # if there is no valid cert in Cert-api, ask for a new one
            logger.debug("---> AUTH state")
            state = process_auth(ca_path, sn, sid, api_url, nonce)
        elif state == "VALID":  # Check certificate expiration
            logger.debug("---> VALID state")
            state = process_valid(key_path, csr_path, cert_path, cert)
            if state == "VALID":  # if the VALID state stays valid, exit the app
                break


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    if args.verbose:
        cl = logging.StreamHandler()
        cl.setLevel(logging.DEBUG)
        cl.formatter = logging.Formatter("%(levelname)s:%(message)s")
        logger.addHandler(cl)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    process = subprocess.Popen(["atsha204cmd", "serial-number"], stdout=subprocess.PIPE)
    if process.wait() == 0:
        sn = process.stdout.read()[:-1]
    else:
        logging.critical("Atcha failed: sn")
        return
    api_url = "{}:{}".format(args.cert_api_hostname[0], args.cert_api_port[0])

    csr_path = get_crypto_name(args.certdir[0], sn, "csr")
    cert_path = get_crypto_name(args.certdir[0], sn, "pem")
    key_path = get_crypto_name(args.certdir[0], sn, "key")
    ca_path = args.ca_certs[0]

    if args.force_renew:
        clear_cert_dir(key_path, csr_path, cert_path)

    start_state_machine(key_path, csr_path, cert_path, ca_path, sn, api_url)


if __name__ == "__main__":
    main()
