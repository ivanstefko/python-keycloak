from src.KeyCloakAdmin import KeyCloakAdmin
from utils.FIleUtils import FileUtils
from src.RequestType import RequestType

import requests

NONE = '_none_'
EMPTY_LIST = '[]'

data_paylaod = FileUtils.open_ini_file('./conf/data-payload.ini')
config = FileUtils.open_ini_file('./conf/config.ini')


class BaseRequest(object):

    admin = KeyCloakAdmin()

    data = ""
    url = ""

    def proceed(self):

        token = self.admin.get_access_token()
        verify_tls = config.getboolean('DEFAULT', 'VERIFY_TLS')

        try:
            header = {'Authorization': 'Bearer ' + token}
            res = requests.post(
                    url=self.url,
                    json=self.data,
                    headers=header,
                    verify=verify_tls
                    )

        except requests.HTTPError as e:
            print ("Unable to create realm {}".format(e))


class RoleRequest(BaseRequest):

    def __init__(self):
        print(">>> RoleRequst")


class ClientRequest(BaseRequest):

    def __init__(self):
        data = FileUtils.open_json_file("./data/client-data-template.json")

        data['id'] = data_paylaod.get('CLIENT', 'UUID') or NONE
        data['clientId'] = data_paylaod.get('CLIENT', 'NAME') or NONE
        data['redirectUris'] = data_paylaod.get('CLIENT', 'REDIRECT_URIS').split(',') or EMPTY_LIST
        data['webOrigins'] = data_paylaod.get('CLIENT', 'WEB_ORIGINS').split(',') or EMPTY_LIST

        url = config.get('REST_API', 'CLIENT_URL').format(hostname=data_paylaod.get('DEFAULT', 'HOSTNAME'),
                                                          realmname=data_paylaod.get('REALM', 'NAME'))

        BaseRequest.url = url
        BaseRequest.data = data


class KeyCloakRequestFactory:

    def __init__(self):
        pass

    def create_request(self, request_type):

        if not isinstance(request_type, RequestType):
            raise TypeError('request_type must be an instance of RequestType Enum')

        # creates instance of request object according to Enum value
        # cond.: Enum value must match with Class name!!
        return globals()[request_type.value]()



factory = KeyCloakRequestFactory()
factory.create_request(RequestType.NEW_CLIENT).proceed()

# ClientRequest().proceed()
