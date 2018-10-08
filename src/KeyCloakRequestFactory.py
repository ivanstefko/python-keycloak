from src.RequestType import RequestType


class KeyCloakRequestFactory:

    def __init__(self):
        pass

    def create_request(self, request_type):

        # check whether passed request type is coming from RequestTYpe Enum
        if not isinstance(request_type, RequestType):
            raise TypeError('request_type must be an instance of RequestType Enum')

        # creates instance of request object on the fly according to Enum value
        # cond.: Enum value must match with Class name!!
        return request_type.value()


factory = KeyCloakRequestFactory()

if __name__ == '__main__':
    factory.create_request(RequestType.CREATE_REALM).proceed()
    factory.create_request(RequestType.CREATE_CLIENT).proceed()
    factory.create_request(RequestType.ADD_CLIENT_ROLE).proceed()
    factory.create_request(RequestType.ADD_LDAP_PROVIDER).proceed()
    factory.create_request(RequestType.LDAP_FULL_SYNC).proceed()
    factory.create_request(RequestType.ADD_METRICS_EVENT_LISTENER).proceed()

