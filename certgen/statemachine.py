"""
StateMachine parent class definition
"""

import json
import logging
import time

import requests

from .crypto_wrapper import get_signature
from .exceptions import CertgenError, CertgenRequestError

from . import DELAY_ERROR, DELAY_WAIT_DEFAULT, DELAY_WAIT_MIN, DELAY_WAIT_MAX
from . import API_VERSION, DEFAULT_MAX_TRIES, EXIT_RC_MAX_TRIES

# States used in the state machine
STATE_INIT = "INIT"
STATE_GET = "GET"
STATE_AUTH = "AUTH"
STATE_VALID = "VALID"
STATE_FAIL = "FAIL"

INIT_NONCE = None
INIT_SID = ""

logger = logging.getLogger("certgen")


class StateMachine:
    def __init__(self, sn, auth_type, flags, api_url, ca_path, insecure_conn):
        self.sn = sn
        self.auth_type = auth_type
        self.flags = flags
        self.api_url = api_url
        self.ca_path = ca_path
        self.use_tls = not insecure_conn

        # call delay setter with default value
        self.delay = None
        self.tries = 0
        self.max_tries = DEFAULT_MAX_TRIES

    @property
    def delay(self):
        return self._delay

    @delay.setter
    def delay(self, delay):
        if delay is None:
            self._delay = DELAY_WAIT_DEFAULT

        elif delay < DELAY_WAIT_MIN:
            logger.warning(
                    "Server sends low delay interval %s; Forcing to %s",
                    delay,
                    DELAY_WAIT_MIN
            )
            self._delay = DELAY_WAIT_MIN

        elif delay > DELAY_WAIT_MAX:
            logger.warning(
                    "Server sends high delay interval %s; Forced to %s",
                    delay,
                    DELAY_WAIT_MAX
            )
            self._delay = DELAY_WAIT_MAX

        else:
            self._delay = delay

    @property
    def ROUTE(self):
        """
        Get cert-api action route
        """
        raise NotImplementedError("ROUTE")

    def send_request(self, req_json):
        """
        Send http POST request.
        """
        url = "{}://{}/{}/{}".format(
                "https" if self.use_tls else "http",
                self.api_url,
                API_VERSION,
                self.ROUTE
        )
        headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
        }
        data = json.dumps(req_json).encode("utf8")

        try:
            response = requests.post(
                    url, headers=headers, data=data,
                    verify=self.ca_path
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            raise CertgenRequestError(
                    "Server returned HTTP error: {} {}".format(
                            response.status_code,
                            response.reason
                    )
            )

        except (json.decoder.JSONDecodeError, AttributeError,
                requests.exceptions.ConnectionError,
                requests.exceptions.SSLError) as e:
            raise CertgenRequestError("Sending request failed: {}".format(str(e)))

    def send_get(self):
        """
        Send http request in the GET state.
        """
        req = {
            "type": "get",
            "auth_type": self.auth_type,
            "sn": self.sn,
            "sid": self.sid,
            "flags": list(self.flags),
        }
        req.update(self.action_spec_params())
        return self.send_request(req)

    def send_auth(self, signature):
        """
        Send http request in the AUTH state.
        """
        req = {
            "type": "auth",
            "auth_type": self.auth_type,
            "sn": self.sn,
            "sid": self.sid,
            "signature": signature,
        }
        return self.send_request(req)

    def remove_flag_renew(self):
        if "renew" in self.flags:
            self.flags.remove("renew")

    def process_init(self):
        """
        Processing the initial state. In this state, private key and
        certificate or any other possible files are loaded and checked. If
        something in the process fails the corrupted, inconsistent or invalid
        files may be deleted. Depending on the overall result this state may
        continue with states:
            GET:    when no consistent data are present or some data are missing
            VALID:  when all the data are present and consistent
        """
        self.sid = INIT_SID
        # This section is handled by action-specific functions
        return self.action_spec_init()

    def process_get(self):
        """
        Processing the GET state. In this state the application tries to
        download and save new data from Cert-api server. This state may
        continue with three states:
            INIT:   when a valid data are downloaded and saved (init must check
                    consistency and validity once more)
            FAIL:   the received data are not valid or some other error
                    occurred
            AUTH:   when there is no valid data available without
                    authentication
            GET:    the certification process is still running, we have to wait
        """
        self.nonce = INIT_NONCE

        try:
            recv_json = self.send_get()
        except CertgenRequestError as e:
            logger.error(str(e))
            return STATE_FAIL

        if recv_json.get("status") == "ok":
            return self.process_get_response(recv_json)

        elif recv_json.get("status") == "wait":
            self.delay = recv_json.get("delay")
            logger.debug(
                    "Server requests to wait, sleeping for %s seconds",
                    self.delay
            )
            time.sleep(self.delay)
            return STATE_GET

        elif recv_json.get("status") == "error":
            logger.error(
                    "Get error: The server responded with message: %s",
                    recv_json.get("message")
            )
            return STATE_FAIL

        elif recv_json.get("status") == "fail":
            logger.error(
                    "Get fail: Server responded with message: %s",
                    recv_json.get("message")
            )
            return STATE_FAIL

        elif recv_json.get("status") == "authenticate":
            self.sid = recv_json.get("sid", INIT_SID)
            self.nonce = recv_json.get("nonce", INIT_NONCE)
            if (self.sid == INIT_SID):
                logger.error("Received 'sid' is invalid or missing")
                return STATE_FAIL
            if (self.nonce == INIT_NONCE):
                logger.error("Received 'nonce' is invalid or missing")
                return STATE_FAIL

            return STATE_AUTH

        else:
            logger.error("Get: Unknown status: %s", recv_json.get("status"))
            return STATE_FAIL

    def process_auth(self):
        """
        Processing the AUTH state. In this state the application authenticates
        to the Cert-api server. This state may continue with two states:
            GET:    authentication was successful, we can continue to download
                    the new data
            FAIL:   there was an error in the authentication process
        """
        # we do not save a signature to a member as we won't use it anymore
        try:
            signature = get_signature(self.nonce)
        except CertgenError as e:
            logger.error(str(e))
            return STATE_FAIL

        recv_json = self.send_auth(signature)

        if recv_json.get("status") == "accepted":
            self.remove_flag_renew()
            self.delay = recv_json.get("delay")
            logger.debug(
                    "Auth accepted, sleeping for %s sec",
                    self.delay
            )
            time.sleep(self.delay)
            return STATE_GET

        elif recv_json.get("status") == "error":
            logger.error(
                    "Auth error: Server responded with message: %s",
                    recv_json.get("message")
            )
            return STATE_FAIL

        elif recv_json.get("status") == "fail":
            logger.error(
                    "Auth fail: Server responded with message: '%s'",
                    recv_json.get("message")
            )
            return STATE_FAIL

        else:
            logger.error("Auth: Unknown status %s", recv_json.get("status"))
            return STATE_FAIL

    def action_spec_init(self):
        """
        Execute an action-specific processes at the beginning of the INIT state
        and return an appropriate next state name.
        """
        raise NotImplementedError("action_spec_init")

    def action_spec_params(self):
        """
        Return action-specific parameters for get request.
        """
        return {}

    def process_get_response(self, response):
        """
        Process data acquired from last get request and return the desired next
        state.
        """
        raise NotImplementedError("process_get_response")

    def start(self):
        state = STATE_INIT

        while True:
            # look for file with consistent and fully valid cert or secret
            if state == STATE_INIT:
                logger.debug("---> INIT state")
                state = self.process_init()

            # if there is no cert/secret in file, download & save it form Cert-api
            elif state == STATE_GET:
                logger.debug("---> GET state")
                state = self.process_get()

            # if the API requires authentication
            elif state == STATE_AUTH:
                logger.debug("---> AUTH state")
                state = self.process_auth()

            # final state
            elif state == STATE_VALID:
                logger.debug("---> VALID state")
                return 0

            # retry or exit
            elif state == STATE_FAIL:
                logger.debug("---> FAIL state")
                self.tries += 1
                if self.tries >= self.max_tries:
                    logger.error(
                            "Max tries (%d) have been reached, exiting",
                            self.max_tries
                    )
                    return EXIT_RC_MAX_TRIES
                logger.warning(
                        "Sleeping for %d seconds before retry (try number %d)",
                        DELAY_ERROR,
                        self.tries + 1
                )
                time.sleep(DELAY_ERROR)
                state = STATE_INIT

            else:
                logger.critical("Unknown next state %s", state)
                raise CertgenError("Unknown next state {}".format(state))
