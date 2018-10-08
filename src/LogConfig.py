import os
import sys
import logging
from logging import handlers


class SetupLogging(object):
    def __init__(self,
                 _log_file,
                 _max_byte=None,
                 _backup_count=None):
        """

        :param _log_file:
        :param _max_byte:
        :param _backup_count:
        """

        self._log_file = _log_file
        self._max_byte = _max_byte
        self._backup_count = _backup_count

        if self._max_byte is None:
            self._max_byte = (1048576*5)
        if self._backup_count is None:
            self._backup_count = 7

    def k8s_setup_logger(self):
        log = logging.getLogger('Python Keycloak Client')
        log.setLevel(logging.DEBUG)
        format = logging.Formatter("[%(asctime)s]: %(name)s - %(levelname)s - %(message)s",
                                   datefmt="%Y-%m-%d %H:%M:%S")
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(format)
        log.addHandler(ch)

        fh = handlers.RotatingFileHandler(self._log_file,
                                          maxBytes=self._max_byte,
                                          backupCount=self._backup_count)
        fh.setFormatter(format)
        log.addHandler(fh)
        return log


logger_instance = SetupLogging(os.path.join(os.getcwd(), './logs/python-keycloak-client.log'))
logger = logger_instance.k8s_setup_logger()
