from enum import Enum


class RequestType(Enum):

    CREATE_REALM = "CreateRealmRequest"
    CREATE_CLIENT = "CreateClientRequest"
    ADD_CLIENT_ROLE = "ClientRoleRequest"
    ADD_LDAP_PROVIDER = "LdapProviderRequest"
    LDAP_FULL_SYNC = "LdapFullSyncRequest"
    ADD_METRICS_EVENT_LISTENER = "MetricsEventListenerRequest"

