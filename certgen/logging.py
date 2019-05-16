"""
Sentinel:Certgen logging setup
"""

import logging
import logging.handlers


def setup_logger(verbose):
    """
    Configure root logger to log INFO messages to syslog and WARNING (or DEBUG
    if verbose) to console
    """
    logger_level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger()
    logger.setLevel(logger_level)

    syslog_level = logging.INFO
    console_level = logging.DEBUG if verbose else logging.WARNING
    console_formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
            "%Y-%m-%d %H:%M:%S"
    )
    syslog_formatter = logging.Formatter(
            "sentinel: %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
            "%Y-%m-%d %H:%M:%S"
    )

    syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
    syslog_handler.setFormatter(syslog_formatter)
    syslog_handler.setLevel(syslog_level)
    logger.addHandler(syslog_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(console_level)
    logger.addHandler(console_handler)
