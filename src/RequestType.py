from enum import Enum
from src.KeyCloakRequestProvider import *

__author__ = "Ivan Stefko / Zoom International"
__email__ = "ivan.stefko@zoomint.com"


class RequestType(Enum):
    """
    This enumeration defined possible requests type for KeyCloak REST API requests.
    It's used as argument request type in KeyClaokRequestFactory class.
    """

    CREATE_REALM = CreateRealmRequest
    CREATE_CLIENT = CreateClientRequest
    ADD_CLIENT_ROLE = ClientRoleRequest
    ADD_LDAP_PROVIDER = LdapProviderRequest
    LDAP_FULL_SYNC = LdapFullSyncRequest
    ADD_METRICS_EVENT_LISTENER = MetricsEventListenerRequest

