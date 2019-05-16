"""
MailpassMachine child class definition
"""

import logging
import os
import sys

from .statemachine import StateMachine

from . import EXIT_RC_PERMISSION
from .statemachine import STATE_INIT, STATE_GET, STATE_VALID, STATE_FAIL

MIN_MAILPASS_CHARS = 8

logger = logging.getLogger("certgen")


def secret_ok(secret):
    return (len(secret) >= MIN_MAILPASS_CHARS)


class MailpassMachine(StateMachine):
    def __init__(self, filename, ca_path, sn, api_url, flags, auth_type, ic):
        self.filename = filename
        super().__init__(ca_path, sn, api_url, flags, auth_type, ic)

    @property
    def ROUTE(self):
        """
        Get cert-api action route
        """
        return "mailpass"

    def action_spec_init(self):
        """
        Checks secret file existence and consistency of its content. Returns
        with STATE_GET when something fails and with STATE_VALID otherwise.
        """
        if not os.path.exists(self.filename):
            return STATE_GET

        try:
            with open(self.filename, "r") as f:
                secret = f.readline()
                if secret_ok(secret):
                    return STATE_VALID
            logger.info("Secret is not valid. Removing...")
        except (ValueError, AssertionError):
            logger.info("Secret is inconsistent. Removing...")
        except PermissionError:
            logger.critical(
                    "Can not read from file file '%s': permission denied",
                    self.filename
            )
            sys.exit(EXIT_RC_PERMISSION)
        try:
            os.remove(self.filename)
        except PermissionError:
            logger.critical(
                    "Can not remove file '%s': permission denied",
                    self.filename
            )
            sys.exit(EXIT_RC_PERMISSION)
        return STATE_GET

    def process_get_response(self, response):
        """
        Process data acquired from last get request and return the desired next
        state
        """
        if secret_ok(response.get("secret")):
            try:
                with open(self.filename, "w") as f:
                    f.write(response.get("secret"))
            except PermissionError:
                logger.critical(
                        "Can not write to file file '%s': permission denied",
                        self.filename
                )
                sys.exit(EXIT_RC_PERMISSION)
            return STATE_INIT
        logger.debug("Obtained secret is invalid")
        return STATE_FAIL
