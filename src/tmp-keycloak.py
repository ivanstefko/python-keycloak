from keycloak.realm import KeycloakRealm
import json

realm = KeycloakRealm(server_url='http://localhost:8180', realm_name='ZOOM')

oidc_client = realm.open_id_connect(client_id='the-best-app',
                                    client_secret='3cc3d3cd-009b-499e-88e4-e8865accb164',
                                    )

print(json.dumps(oidc_client.userinfo(oidc_client.client_credentials()['access_token']+'sd'), indent=4))
print("{}".format(json.dumps(oidc_client.client_credentials(), indent=4)))


admin_client = realm.admin
realm = realm.admin.realms.by_name('ZOOM')
# print("realm>> " + realm)
clients = realm.admin.realms.by_name('ZOOM').clients
print(clients.all())

