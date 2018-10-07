from src.KeyCloakTokenProvider import KeyCloakTokenProvider
from src.RequestType import RequestType
from utils.FileUtils import FileUtils

import abc
import json
import requests
import ast

NONE = '_none_'
EMPTY_LIST = '[]'

data_payload = FileUtils.open_ini_file('./conf/data-payload.ini')
config = FileUtils.open_ini_file('./conf/config.ini')


class BaseRequest(object):
    __metaclass__ = abc.ABCMeta

    token_provider = KeyCloakTokenProvider()

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
        token = self.token_provider.get_access_token()
        verify_tls = config.getboolean('DEFAULT', 'VERIFY_TLS')

        # print(json.dumps(self.get_data(), indent=4))

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


class CreateRealmRequest(BaseRequest):

    def __init__(self):
        self.data = FileUtils.open_json_file('./data/realm-data-template.json')

    def get_url(self):
        """ {hostname}/auth/admin/realms """
        return config.get('REST_API', 'REALM_URL').format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'))

    def get_data(self):
        self.data['id'] = data_payload.get('REALM', 'ID') or NONE
        self.data['realm'] = data_payload.get('REALM', 'NAME') or NONE
        return self.data

    def get_messages(self):
        return {
            "success": "Realm '{}' has been successfully created.".format(self.data['realm']),
            "error": "Unable to create realm '{}'.".format(self.data['realm'])
        }


class ClientRoleRequest(BaseRequest):

    def __init__(self):
        self.data = FileUtils.open_json_file("./data/client-role-data-template.json")

    def get_url(self):
        """ {{hostname}}/auth/admin/realms/{{realm_name}}/clients/{{client_uuid}}/roles """
        return config.get('REST_API', 'CLIENT_ROLE_URL').format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'),
                                                                realm_name=data_payload.get('REALM', 'NAME'),
                                                                client_uuid=data_payload.get('CLIENT', 'UUID'))

    def get_data(self):
        self.data['name'] = data_payload.get('CLIENT_ROLE', 'NAME') or NONE
        return self.data

    def get_messages(self):
        return {
            "success": "The client role '{}' has been successfully added for client '{}'.".format(
                self.data['name'],
                data_payload.get('CLIENT', 'NAME')
            ),
            "error": "Unable to add client role '{}' to client '{}'.".format(
                self.data['name'],
                data_payload.get('CLIENT', 'NAME')
            )
        }


class CreateClientRequest(BaseRequest):

    def __init__(self):
        self.data = FileUtils.open_json_file("./data/client-data-template.json")

    def get_data(self):
        self.data['id'] = data_payload.get('CLIENT', 'UUID') or NONE
        self.data['clientId'] = data_payload.get('CLIENT', 'NAME') or NONE
        self.data['redirectUris'] = ast.literal_eval(data_payload.get('CLIENT', 'REDIRECT_URIS')) or EMPTY_LIST
        self.data['webOrigins'] = ast.literal_eval(data_payload.get('CLIENT', 'WEB_ORIGINS')) or EMPTY_LIST
        return self.data

    def get_url(self):
        """ {hostname}/auth/admin/realms/{realm_name}/clients """
        return config.get('REST_API', 'CLIENT_URL').format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'),
                                                           realm_name=data_payload.get('REALM', 'NAME'))

    def get_messages(self):
        return {
                "success": "The client '{}' has been successfully created.".format(self.data['clientId']),
                "error": "Unable to create '{}' client with id '{}'.".format(self.data['clientId'], self.data['id'])
                }


class LdapFullSyncRequest(BaseRequest):

    def get_url(self):
        """ LDAP_SYNC_USERS_URL = {hostname}/auth/admin/realms/{realm_name}/user-storage/{ldap_provider_id}/sync?action=triggerFullSync """
        return config.get('REST_API', 'LDAP_SYNC_USERS_URL')\
            .format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'),
                    realm_name=data_payload.get('REALM', 'NAME'),
                    ldap_provider_id=data_payload.get('LDAP_PROVIDER', 'ID'))

    def get_data(self):
        """ data not required for this request """
        pass

    def get_messages(self):
        pass


class MetricsEventListenerRequest(BaseRequest):

    def __init__(self):
        pass

    def get_url(self):
        """ {hostname}/auth/admin/realms/{realm_name}/events/config """
        return config.get('REST_API', 'METRICS_LISTENER_URL').format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'),
                                                                     realm_name=data_payload.get('REALM', 'NAME'))

    def get_data(self):
        pass

    def get_messages(self):
        pass


class LdapProviderRequest(BaseRequest):

    def __init__(self):
        self.data = FileUtils.open_json_file("./data/ldap-provider-data-template.json")

    def get_url(self):
        """ {hostname}/auth/admin/realms/{realm_name}/components """
        return config.get('REST_API', 'LDAP_PROVIDER_URL').format(hostname=data_payload.get('DEFAULT', 'HOSTNAME'),
                                                                  realm_name=data_payload.get('REALM', 'NAME'))

    def get_data(self):
        self.data['id'] = data_payload.get('LDAP_PROVIDER', 'ID') or NONE
        self.data['name'] = data_payload.get('LDAP_PROVIDER', 'NAME') or NONE
        self.data['parentId'] = data_payload.get('REALM', 'NAME') or NONE
        self.data['config']['fullSyncPeriod'] = [data_payload.get('LDAP_PROVIDER', 'FULL_SYNC_PERIOD')]
        self.data['config']['usersDn'] = [data_payload.get('LDAP_PROVIDER', 'USER_DN')]
        self.data['config']['enabled'] = [data_payload.get('LDAP_PROVIDER', 'ENABLED')]
        self.data['config']['importEnabled'] = [data_payload.get('LDAP_PROVIDER', 'IMPORT_ENABLED')]
        self.data['config']['bindCredential'] = [data_payload.get('LDAP_PROVIDER', 'BIND_CREDENTIAL')]
        self.data['config']['bindDn'] = [data_payload.get('LDAP_PROVIDER', 'BIND_DN')]
        self.data['config']['connectionUrl'] = [data_payload.get('LDAP_PROVIDER', 'CONNECTION_URL')]
        self.data['config']['userObjectClasses'] = [data_payload.get('LDAP_PROVIDER', 'USER_OBJ_CLASS')]
        return self.data

    def get_messages(self):
        return {
                "success": "LDAP Provider '{}' has been successfully created.".format(self.data['name']),
                "error": "Unable to create LDAP Provider '{}'.".format(self.data['name'])
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


print (globals())

# factory = KeyCloakRequestFactory()
#
# factory.create_request(RequestType.CREATE_REALM).proceed()
# factory.create_request(RequestType.CREATE_CLIENT).proceed()
# factory.create_request(RequestType.ADD_CLIENT_ROLE).proceed()
# factory.create_request(RequestType.ADD_LDAP_PROVIDER).proceed()
# factory.create_request(RequestType.LDAP_FULL_SYNC).proceed()

