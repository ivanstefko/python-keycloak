import json


def open_json_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)

data = open_json_file('./data/test.json')
data['id'] = 'python-realm'
data['realm'] = 'python-realm'

# print(type(data))
print(json.dumps(data, indent=4))
# print(json.dumps(data).form(realm=realm))

# realm = {'id': 'newRealm', 'name': 'realmName'}
# print ('"realm": "{name}", "enabled": true, "id": "{id}"'.format(**realm))

