from enum import Enum
from aenum import MultiValueEnum


class RequestType(MultiValueEnum):

    NEW_CLIENT = "ClientRequest"
    NEW_ROLE = "RoleRequest"
