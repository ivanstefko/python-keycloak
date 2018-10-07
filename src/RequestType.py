from enum import Enum
from aenum import MultiValueEnum


class RequestType(MultiValueEnum):

    CREATE_CLIENT = "ClientRequest"
    ADD_CLIENT_ROLE = "ClientRoleRequest"
    ADD_LDAP_PROVIDER = "LdapProviderRequest"
    LDAP_FULL_SYNC = "LdapFullSyncRequest"

