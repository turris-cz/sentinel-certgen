"""
Hooks implementation for Sentinel:Certgen
"""

import logging
import os
import subprocess
import sys

logger = logging.getLogger("certgen")


def run_hooks(directory_path):
    return_flag = True

    for filename in os.listdir(directory_path):
        path = os.path.join(directory_path, filename)

        # execute the hook if it is readable and executable regular file
        if (os.path.isfile(path)
                and os.access(path, os.R_OK)
                and os.access(path, os.X_OK)):
            logger.info("Executing hook %s", filename)
            process = subprocess.Popen([path])
            rc = process.wait()

            if rc != 0:
                return_flag = False
                logger.error("Hook %s failed with return code %d", filename, rc)

    return return_flag
