import requests
import json


class KeyCloakAdmin:
    def __init__(self):
        self.config = self.__open_json_file__('./conf/config.json')
        self.verify_tls = self.config['VERIFY_TLS']

    def get_keycloak_token(self):
        """
        Gets Keyclaok token object consist of access_token, refresh_token ... . The credentials for request are loaded
        from external config file.

        :return: Keycloak authentication token (access_token, refresh_token, expiration... )
        """
        url = self.config['AUTH_API']['URL_AUTH_TOKEN']
        client_id = self.config['ADMIN']['CLIENT_ID']
        username = self.config['ADMIN']['USERNAME']
        password = self.config['ADMIN']['PASSWORD']
        grant_type = self.config['ADMIN']['GRANT_TYPE']

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
        Gets Keyclaok access token from Keyclaok token object

        :return: Keycloak access_token
        """
        return self.get_keycloak_token().json()['access_token']

    def __open_json_file__(self, filename):
        """
        Private method used for loading data from external file.

        :filename: the path with filename to be loaded
        :return: loaded file in json form
        """
        with open(filename, 'r') as f:
            return json.load(f)

    def create_realm(self):
        """
        Private method used for loading data from external file.

        :filename: the path with filename to be loaded
        :return: loaded file in json form
        """
        realm_data = self.__open_json_file__('./data/realm-data.json')
        url = self.config['AUTH_API']['REALMS']

        try:
            header = {'Authorization': 'Bearer ' + self.get_access_token()}
            res = requests.post(
                    url=url,
                    json=realm_data,
                    headers=header,
                    verify=self.verify_tls
                    )

        except requests.HTTPError as e:
            print ("Unable to create realm {}".format(e))

        if res.status_code == requests.codes.created:
            print("Realm '{}' has been successfully created!".format(realm_data['realm']))
        else:
            print("Unable to create realm '{}'. The error status_code: {} with desc: {}".format(realm_data['realm'], res.status_code, res.content))

        return res


# keycloak = KeyCloakAdmin()
# keycloak.create_realm()

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
