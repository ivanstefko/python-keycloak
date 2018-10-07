from src.KeyCloakAdmin import KeyCloakAdmin
from utils.FIleUtils import FileUtils
from src.RequestType import RequestType
import abc
import json
import requests

NONE = '_none_'
EMPTY_LIST = '[]'

data_payload = FileUtils.open_ini_file('./conf/data-payload.ini')
config = FileUtils.open_ini_file('./conf/config.ini')

class BaseRequest(object):
    __metaclass__ = abc.ABCMeta

    admin = KeyCloakAdmin()

    @abc.abstractmethod
    def get_url(self):
        """Abstract method gets the Keyclaok REST API request url."""

    @abc.abstractmethod
    def get_data(self):
        """Abstract method gets the POST data for Keycloak request."""

    @abc.abstractmethod
    def get_messages(self):
        """Abstract method gets success/error messages used for logging."""

    def proceed(self):
        token = self.admin.get_access_token()
        verify_tls = config.getboolean('DEFAULT', 'VERIFY_TLS')

        try:
            header = {'Authorization': 'Bearer ' + token}
            res = requests.post(
                    url=self.get_url(),
                    json=self.get_data(),
                    headers=header,
                    verify=verify_tls
                    )

        except requests.HTTPError as e:
            print ("Unable to finish the request {}".format(e))

        if res.status_code == requests.codes.created:
            print(self.get_messages()['success'])
        else:
            print(self.get_messages()['error'])
            print("Request finished with status code {} and reason {}.".format(res.status_code, res.content))


class RoleRequest(BaseRequest):

    def __init__(self):
        print(">>> RoleRequst")


class ClientRequest(BaseRequest):

    def __init__(self):
        self.data = FileUtils.open_json_file("./data/client-data-template.json")

    def get_data(self):
        self.data['id'] = data_payload.get('CLIENT', 'UUID') or NONE
        self.data['clientId'] = data_payload.get('CLIENT', 'NAME') or NONE
        self.data['redirectUris'] = data_payload.get('CLIENT', 'REDIRECT_URIS').split(',') or EMPTY_LIST
        self.data['webOrigins'] = data_payload.get('CLIENT', 'WEB_ORIGINS').split(',') or EMPTY_LIST
        return self.data

    def get_url(self):
        return config.get('REST_API', 'CLIENT_URL').format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'),
                                                           realmname=data_payload.get('REALM', 'NAME'))

    def get_messages(self):
        return {
                "success": "The client '{}' has been successfully created.".format(self.data['clientId']),
                "error": "Unable to create '{}' client with id '{}'.".format(self.data['clientId'], self.data['id'])
                }


class KeyCloakRequestFactory:

    def __init__(self):
        pass

    def create_request(self, request_type):

        # check whether passed request type is coming from RequestTYpe Enum
        if not isinstance(request_type, RequestType):
            raise TypeError('request_type must be an instance of RequestType Enum')

        # creates instance of request object on the fly according to Enum value
        # cond.: Enum value must match with Class name!!
        return globals()[request_type.value]()


factory = KeyCloakRequestFactory()
factory.create_request(RequestType.NEW_CLIENT).proceed()
