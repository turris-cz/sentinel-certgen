"""
Sentinel:Certgen functions to communicate with crypto-wrapper CLI tool
"""

import subprocess

from .exceptions import CertgenError


MAX_OUTPUT_LEN = 5000


def _truncate(s, maxlen=MAX_OUTPUT_LEN):
    """Ořízne řetězec na maxlen znaků a označí oříznutí."""
    if len(s) > maxlen:
        return s[:maxlen] + "... [truncated]"
    return s

def _run_crypto_wrapper(args, input_data=None):
    """Spustí crypto-wrapper a vrátí jeho stdout jako dekódovaný řetězec."""
    try:
        result = subprocess.run(
                ["crypto-wrapper"] + args,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=CMD_TIMEOUT,
                check=True,
        )
    except FileNotFoundError:
        raise CertgenError("crypto-wrapper not found")
    except subprocess.TimeoutExpired as e:
        stderr = _truncate((e.stderr or b"").decode("utf-8", "replace").strip())
        raise CertgenError("crypto-wrapper timed out: ({}): {}".format(" ".join(args), stderr))
    except subprocess.CalledProcessError as e:
        stderr = _truncate(e.stderr.decode("utf-8", "replace").strip())
        raise CertgenError(
                "crypto-wrapper failed ({}): {}".format(" ".join(args), stderr)
        )
    return _truncate(result.stdout.decode("utf-8").rstrip("\n"))


def get_sn():
    """ Return crypto-wrapper-based serial number.
    """
    return _run_crypto_wrapper(["serial-number"])


def get_signature(nonce):
    """ Return crypto-wrapper-based signature of nonce.
    """
    return _run_crypto_wrapper(["sign"], input_data=nonce.encode("utf-8"))


def get_auth_type():
    """ Return crypto-wrapper-based authentication type.
    """
    return _run_crypto_wrapper(["hw-type"])
