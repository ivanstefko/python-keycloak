from keycloak.RequestType import RequestType

__author__ = "Ivan Stefko / Zoom International"
__email__ = "ivan.stefko@zoomint.com"


class KeyCloakRequestFactory:
    """
    Factory pattern for KeyCloak requests according to passed request type. If you want
    to add new request please follow steps in README.md file.
    """

    def __init__(self):
        pass

    def create_request(self, request_type):

        # check whether passed request type is coming from RequestTYpe Enum
        if not isinstance(request_type, RequestType):
            raise TypeError('request_type must be an instance of RequestType Enum')

        # creates instance of request object on the fly according to Enum value
        # cond.: Enum value must match with Class name!!
        return request_type.value()


