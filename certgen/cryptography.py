"""
Cryptography-related tasks for Sentinel:Certgen
"""

import datetime
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from . import MAX_TIME_TO_EXPIRE

ELLIPTIC_CURVE = ec.SECP256R1()

logger = logging.getLogger("certgen")


def clear_cert_dir(key_path, csr_path, cert_path):
    """
    Remove (if exist) private and public keys and certificate
    signing request from Sentinel certificate directory.
    """
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(csr_path):
        os.remove(csr_path)
    if os.path.exists(cert_path):
        os.remove(cert_path)


def cert_expired(cert, csr_path, cert_path):
    now = datetime.datetime.utcnow()
    if cert.not_valid_after < now:
        return True
    else:
        return False


def cert_to_expire(cert):
    now = datetime.datetime.utcnow()
    max_time_to_expire = datetime.timedelta(seconds=MAX_TIME_TO_EXPIRE)
    return cert.not_valid_after < (now + max_time_to_expire)


def extract_cert(cert_str, key):
    try:
        cert = x509.load_pem_x509_certificate(
                cert_str.encode("utf-8"),
                default_backend()
        )
    except ValueError:
        return None
    if key_match(cert, key):
        return cert
    else:
        return None


def generate_csr_file(csr_path, sn, key):
    csr = x509.CertificateSigningRequestBuilder(
            subject_name=x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, sn),
            ])
    )
    csr = csr.sign(key, hashes.SHA256(), default_backend())

    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def generate_priv_key_file(key_path):
    key = ec.generate_private_key(
            curve=ELLIPTIC_CURVE,
            backend=default_backend()
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


def key_match(obj, key):
    return obj.public_key().public_numbers() == key.public_key().public_numbers()


def load_or_remove_key(key_path):
    """
    Load the private key from a file or, if it is damaged, remove it from
    the filesystem.
    """
    try:
        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(
                    data=f.read(),
                    password=None,
                    backend=default_backend()
            )
        return key
    except (ValueError, AssertionError):
        logger.info("Private key is inconsistent. Removing...")
        os.remove(key_path)
        return None


def load_or_remove_cert(cert_path, key):
    """
    Load the certificate from a file or, if it is damaged, remove it from
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
    """
    Load the certificate from a file or, if it is damaged, remove it from
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


def save_cert(cert, cert_path):
    """
    Save received certificate to a file.
    """
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
