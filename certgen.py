#!/usr/bin/env python

from OpenSSL import crypto, SSL
import os
import pwd
import subprocess
import sys
import urllib2
import ssl
import json
import argparse
import re
import time
import datetime


KEY_TYPE = crypto.TYPE_RSA
KEY_LEN = 4096
MAX_TIME_TO_EXPIRE = 30*24*60*60

def print_info(msg):
    if DEBUG:
        print('\033[94m' + msg + '\033[0m')
    return DEBUG
def print_debug(msg):
    if DEBUG:
        print('\033[93m' + msg + '\033[0m')
    return DEBUG


def hexa_match(string):
    """ Check whether the string contains only hexadecimal characters
    """
    return not re.compile(r'[^a-fA-f0-9]').search(string)

def serial(string):
    if len(string) != 16 or not hexa_match(string):
        raise argparse.ArgumentTypeError("Serial number must be 16 character "\
            "long hexadecimal number")
    return string

def prepare_arg_parser():
    parser = argparse.ArgumentParser(description='Certgen - client for '\
        'retrieving Turris:Sentinel certificates')
    parser.add_argument('--debug-sn', nargs=1, type=serial,
        help='emulate serial number for debug purposes. DEBUG-SN is a '\
        '16-digit hexadecimal number.')
    parser.add_argument('--certdir', nargs=1, help='path to Sentinel '\
        'certificate location', required=True)
    parser.add_argument('--auth-api-address', nargs=1, help='authentication '\
        'api address', required=True)
    parser.add_argument('--auth-api-port', nargs=1, help='authentication '\
        'api port', required=True)
    parser.add_argument('--debug', action='store_true', help='enable debug '\
        'printouts')
    parser.add_argument('--force-renew', action='store_true', help='remove '\
        'private key, generate a new one and ask Sentinel:Authenticator for'\
        ' a new certificate')
    return parser

def get_digest_debug(nonce):
    return nonce

def key_match(obj, key):
    obj_pubkey_str = crypto.dump_publickey(
        type=crypto.FILETYPE_PEM,
        pkey=obj.get_pubkey(),
    ).decode("utf-8")
    key_pubkey_str = crypto.dump_publickey(
        type=crypto.FILETYPE_PEM,
        pkey=key,
    ).decode("utf-8")
    return obj_pubkey_str == key_pubkey_str

def get_time(timestamp):
    time_str = timestamp.decode("utf-8")
    time = int(timestamp[0:4])
    time = time*364 + int(timestamp[4:])


class Certgen:
    def __init__(self, sn, cert_dir, digest_fnc, auth_address, auth_port):
        self.sn = sn
        self.cert_dir = cert_dir
        self.get_digest = digest_fnc
        self.auth_address = auth_address
        self.auth_port = auth_port
        self.set_state_init()

    def set_state_init(self):
        def get_crypto_name(ext):
            return str.join(
                '/', (self.cert_dir, str.join('.', (str(self.sn), ext)))
            )
        self.key_path = get_crypto_name("key")
        self.csr_path = get_crypto_name("csr")
        self.cert_path = get_crypto_name("pem")
        self.key = None
        self.csr = None
        self.cert = None
        self.sid = 0

        while True:
            print_debug("INIT state")
            if not self.key:
                if os.path.exists(self.key_path):
                    print_info("Private key file exists.")
                    try:
                        with open(self.key_path,"r") as key_file:
                            key = crypto.load_privatekey(
                                crypto.FILETYPE_PEM,
                                key_file.read()
                            )
                    except crypto.Error:
                        print_info("Private key is inconsistent, "
                            "generating a new one.")
                        self.clear_cert_dir()
                        self.generate_Pkey()
                        continue
                    if key.check():
                            self.key = key
                            print_info("Private key loaded.")
                    else:
                        print_info("Private key is inconsistent, "
                            "generating a new one.")
                        self.clear_cert_dir()
                        self.generate_Pkey()
                        continue

                else:
                    print_info("Private key file not found")
                    print_info("Private key: generating a new one.")
                    self.clear_cert_dir()
                    self.generate_Pkey()
                    continue

            if os.path.exists(self.cert_path):
                print_info("Certificate file exists.")
                try:
                    with open(self.cert_path,"r") as cert_file:
                        cert = crypto.load_certificate(
                            crypto.FILETYPE_PEM,
                            cert_file.read()
                        )
                except crypto.Error:
                    print_info("Certificate file broken. Re-certifying...")
                    os.remove(self.cert_path)
                    continue
                due_date = time.mktime(datetime.datetime.strptime(
                    cert.get_notAfter().decode("utf-8"),
                    "%Y%m%d%H%M%SZ",
                ).timetuple())
                now = time.time()
                if (due_date - now < MAX_TIME_TO_EXPIRE):
                    print_info("Certificate is about to expire. "
                        "Re-certifying..")
                    self.key = None
                    self.clear_cert_dir()
                    continue
                else:
                    print_info("Certificate not expired.")
                if key_match(cert, self.key):
                    self.cert = cert
                    print_info("Certificate loaded.")
                    break
                else:
                    print_info("Certificate public key does not match. "
                        "Re-certifying...")
                    os.remove(self.cert_path)
                    continue

            else:
                print_info("Certificate file does not exist. Re-certyfing.")
                if os.path.exists(self.csr_path):
                    print_info("CSR file exist.")
                    try:
                        with open(self.csr_path,"r") as csr_file:
                            csr = crypto.load_certificate_request(
                                crypto.FILETYPE_PEM,
                                csr_file.read()
                            )
                    except crypto.Error:
                        print_info("CSR file is inconsistent, "
                            "generating a new one.")
                        os.remove(self.csr_path)
                        self.generate_csr()
                        continue

                    if key_match(csr, self.key):
                        self.csr = csr
                        print_info("CSR loaded.")
                        while (not self.set_state_get()):
                            pass
                    else:
                        print_info("CSR public key does not match, "
                            "generating a new one.")
                        os.remove(self.csr_path)
                        self.generate_csr()
                        continue

                else:
                    print_info("CSR file not found. Generating a new one.")
                    self.generate_csr()
                    continue

    def set_state_get(self):
        print_debug("GET state")
        csr_str = crypto.dump_certificate_request(
            type=crypto.FILETYPE_PEM,
            req=self.csr
        ).decode("utf-8")
        req = {
            "api_version" : "0.1",
            "type" : "get_cert",
            "sn" : self.sn,
            "sid" : self.sid,
            "csr" : csr_str,
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
                print_info("Saving obtained certificate.")
                return True
            else:
                print_info("Obtained cert key does not match.")
                return False
        elif recv_json.get("status") == 'wait':
            print_info("Sleeping for {} seconds".format(recv_json['delay']))
            time.sleep(recv_json['delay'])
        elif recv_json.get("status") == 'error':
            print_info("Get Error.")
            return False
        elif recv_json.get("status") == 'fail':
            print_infog("Get Fail.")
            return False
        elif recv_json.get("status") == 'authenticate':
            self.sid = recv_json['sid']
            self.nonce = recv_json['nonce']
            self.set_state_auth()
        else:
            print_info("Get: Unknown error.")


    def set_state_auth(self):
        print_debug("AUTH state")
        self.digest = self.get_digest(self.nonce)
        req = {
            "api_version" : "0.1",
            "type" : "auth",
            "sn" : self.sn,
            "sid" : self.sid,
            "digest" : self.digest,
        }

        recv = self.send_request(req)
        recv_json = json.loads(recv.decode("utf-8"))
        if recv_json.get("status") == "accepted":
            print_info("Auth accepted, sleeping for {} sec.".format(
                recv_json['delay']
            ))
            time.sleep(recv_json['delay'])
        else:
            print_info("Auth: Unknown error.")

    def clear_cert_dir(self):
        """ Remove (if exist) private and public keys and certificate
        sifning request from Sentinel certificate directory.
        """
        print_info("Clearing certificate directory.")

        if os.path.exists(self.key_path):
            os.remove(self.key_path)
        if os.path.exists(self.csr_path):
            os.remove(self.csr_path)
        if os.path.exists(self.cert_path):
            os.remove(self.cert_path)


    def generate_Pkey(self):
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
        with open(self.cert_path, "w") as cert_file:
            cert_file.write(crypto.dump_certificate(
                type=crypto.FILETYPE_PEM,
                cert=cert
            ).decode("utf-8"))

    def send_request(self, req_json):
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
        #print(resp.geturl())
        #print(resp.info())
        #print(resp.getcode())

        return resp_json
parser = prepare_arg_parser()
args = parser.parse_args()
DEBUG = args.debug

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
        print("Atcha failed.")
        exit()

certgen = Certgen(sn, args.certdir[0], get_digest_debug, args.auth_api_address[0], args.auth_api_port[0])



