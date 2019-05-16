"""
Sentinel:Certgen python package
"""

__version__ = '4.2'


DEFAULT_CERT_API_HOSTNAME = "sentinel.turris.cz"
DEFAULT_CERT_API_PORT = "443"
DEFAULT_CERTS_CERTDIR = "/etc/sentinel"
DEFAULT_MAILPASS_FILENAME = "/etc/sentinel/mailpass"

MQTT_KEY_FILE = "mqtt_key.pem"
MQTT_CERT_FILE = "mqtt_cert.pem"
MQTT_CSR_FILE = "mqtt_csr.pem"

API_VERSION = "v1"
RENEW_WAIT = 10
ERROR_WAIT = 10
DEFAULT_MAX_TRIES = 3

EXIT_RC_SETUP = 2
EXIT_RC_PERMISSION = 2
EXIT_RC_MAX_TRIES = 3

MAX_TIME_TO_EXPIRE = 30*24*60*60
