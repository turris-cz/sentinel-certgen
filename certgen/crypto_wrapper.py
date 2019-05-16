"""
Sentinel:Certgen functions to communicate with crypto-wrapper CLI tool
"""

import subprocess

from .exceptions import CertgenError


def get_sn():
    """ Return crypto-wrapper-based serial number.
    """
    process = subprocess.Popen(
            ["crypto-wrapper", "serial-number"],
            stdout=subprocess.PIPE
    )
    if process.wait() == 0:
        return process.stdout.read().decode("utf-8").rstrip("\n")
    else:
        raise CertgenError("crypto-wrapper failed: sn")


def get_signature(nonce):
    """ Return crypto-wrapper-based signature of nonce.
    """
    process = subprocess.Popen(
            ["crypto-wrapper", "sign"],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE
    )
    nonce = nonce.encode("utf-8")
    # the return value is a list
    signature = process.communicate(input=nonce)[0]
    signature = signature.decode("utf-8").rstrip("\n")

    return signature


def get_auth_type():
    """ Return crypto-wrapper-based authentication type.
    """
    process = subprocess.Popen(
            ["crypto-wrapper", "hw-type"],
            stdout=subprocess.PIPE
    )
    if process.wait() == 0:
        return process.stdout.read().decode("utf-8").rstrip("\n")
    else:
        raise CertgenError("crypto-wrapper failed: hw-type")
