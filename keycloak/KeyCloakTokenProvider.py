import requests
from utils.FileUtils import FileUtils


# import logging
# >>> REQUESTS DEBUGGING <<<
# try:
#     import http.client as http_client
# except ImportError:
#     # Python 2
#     import httplib as http_client
# http_client.HTTPConnection.debuglevel = 1
#
# # You must initialize logging, otherwise you'll not see debug output.
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

__author__ = "Ivan Stefko / Zoom International"
__email__ = "ivan.stefko@zoomint.com"


class KeyCloakTokenProvider:
    """
    The KeyCloakAdmin class is used for proceed admin operation like create realm using admin-cli client and
    generate Keycloak Authentication Token.
    """

    def __init__(self):
        self.config = FileUtils.open_ini_file('./keycloak/conf/config.ini')
        self.data_payload = FileUtils.open_ini_file('./keycloak/conf/data-payload.ini')
        self.verify_tls = self.config.getboolean('DEFAULT', 'VERIFY_TLS')

    def get_keycloak_token(self):
        """
        Gets keycloak token object consist of access_token, refresh_token ... . The credentials for request are loaded
        from external config file.

        :return: Keycloak authentication token (access_token, refresh_token, expiration... )
        """
        url = self.config.get('ADMIN', 'URL_AUTH_TOKEN').format(hostname=self.data_payload.get('DEFAULT', 'HOSTNAME'))

        client_id = self.config.get('ADMIN', 'CLIENT_ID')
        username = self.config.get('ADMIN', 'USERNAME')
        password = self.config.get('ADMIN', 'PASSWORD')
        grant_type = self.config.get('ADMIN', 'GRANT_TYPE')

        try:
            res = requests.post(
                            url,
                            data={
                                'client_id': client_id,
                                'username': username,
                                'password': password,
                                'grant_type': grant_type
                                },
                            verify=self.verify_tls
                            )

        except requests.HTTPError as e:
            print("Unable to make auth token request. Exception {}".format(e))

        return res

    def get_access_token(self):
        """
        Gets keycloak access token from keycloak token object

        :return: Keycloak access_token
        """
        return self.get_keycloak_token().json()['access_token']


