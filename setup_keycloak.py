from keycloak.RequestType import RequestType
from keycloak.KeyCloakRequestFactory import KeyCloakRequestFactory


if __name__ == '__main__':
    # let's create factory and do some magic
    factory = KeyCloakRequestFactory()

    factory.create_request(RequestType.CREATE_REALM).proceed()
    factory.create_request(RequestType.CREATE_CLIENT).proceed()
    factory.create_request(RequestType.ADD_CLIENT_ROLE).proceed()
    factory.create_request(RequestType.ADD_LDAP_PROVIDER).proceed()
    factory.create_request(RequestType.LDAP_FULL_SYNC).proceed()
    factory.create_request(RequestType.ADD_METRICS_EVENT_LISTENER).proceed()

