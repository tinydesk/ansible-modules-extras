#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: bitbucket_deployment_key
short_description: Manage Bitbucket deployment keys.
description:
    - Creates, removes, or updates Bitbucket deployment keys.
version_added: "2.3"
options:
  user:
    description:
      - Bitbucket username of a user that is an owner of the repository.
    required: true
  password:
    description:
      - Password of the bitbucket user. See ansible-vault for providing passwords without revealing them in plain text.
    required: true
  repository:
    description:
      - Name of the repository for which to add a deployment key. This is typically of the form: user/repo-name. 
    required: true
  name:
    description:
      - SSH key name.
    required: true
  pubkey:
    description:
      - SSH public key value. Required when C(state=present).
    required: false
    default: none
  state:
    description:
      - Whether to remove a key, ensure that it exists, or update its value.
    choices: ['present', 'absent']
    default: 'present'
    required: false
  force:
    description:
      - The default is C(yes), which will replace the existing remote key
        if it's different than C(pubkey). If C(no), the key will only be
        set if no key with the given C(name) exists.
    required: false
    choices: ['yes', 'no']
    default: 'yes'

author: Hannes Widmoser (@widmoser)
'''

RETURN = '''
deleted_keys:
    description: An array of key objects that were deleted. Only present on state=absent
    type: list
    returned: When state=absent
    sample: [{'pk': 0, 'key': 'BASE64 encoded key', 'label': 'Name of the key'}]
matching_keys:
    description: An array of keys matching the specified name. Only present on state=present
    type: list
    returned: When state=present
    sample: [{'pk': 0, 'key': 'BASE64 encoded key', 'label': 'Name of the key'}]
key:
    description: Metadata about the key just created. Only present on state=present
    type: dict
    returned: success
    sample: {'pk': 0, 'key': 'BASE64 encoded key', 'label': 'Name of the key'}
'''

EXAMPLES = '''
- name: Read SSH public key to authorize
  shell: cat /home/foo/.ssh/id_rsa.pub
  register: ssh_pub_key

- name: Authorize key with Bitbucket
  module: bitbucket_deployment_key
  name: Access Key for Some Machine
  user: '{{ bitbucket_username }}'
  password: '{{ bitbucket_password }}'
  repository: example/myrepo
  pubkey: '{{ ssh_pub_key.stdout }}'
'''

import sys  # noqa
import json
import re 
from urllib import urlencode

API_BASE = 'https://api.bitbucket.org/1.0/repositories/%s/deploy-keys'


class BitbucketSession:

    def __init__(self, module, user, password, repository):
        self.module = module
        self.user = user
        self.password = password
        self.repository = repository
        self.base = API_BASE % repository

    def request(self, method, url='', data=None):
        headers = {
            'Authorization': basic_auth_header(self.user, self.password)
        }
        response, info = fetch_url(
            self.module, self.base + url, method=method, data=data, headers=headers)
        if not (200 <= info['status'] < 400):
            self.module.fail_json(
                msg=(" failed to send request %s to %s: %s"
                     % (method, url, info['msg'])))
        return response.read()


def get_all_keys(session):
    return json.loads(session.request('GET'))

def get_key(session, pk):
    return json.loads(session.request('GET', '/' + pk))

def create_key(session, name, key, check_mode):
    if check_mode:
        from datetime import datetime
        now = datetime.utcnow()
        return {
            'pk': 0,
            'key': pubkey,
            'label': name
        }
    else:
        return json.loads(session.request('POST', data="%s" % urlencode({
            'key': key,
            'label': name    
        })))

def delete_key(session, pk):
    return session.request('DELETE', '/' + str(pk))

def delete_keys(session, to_delete, check_mode):
    if check_mode:
        return

    for key in to_delete:
        delete_key(session, key['pk'])

def ensure_key_present(session, name, pubkey, force, check_mode):
    matching_keys = [k for k in get_all_keys(session) if k['label'] == name]
    deleted_keys = []

    if matching_keys and force and matching_keys[0]['key'] != pubkey:
        delete_keys(session, matching_keys, check_mode=check_mode)
        (deleted_keys, matching_keys) = (matching_keys, [])

    if not matching_keys:
        key = create_key(session, name, pubkey, check_mode=check_mode)
    else:
        key = matching_keys[0]

    return {
        'changed': bool(deleted_keys or not matching_keys),
        'deleted_keys': deleted_keys,
        'matching_keys': matching_keys,
        'key': key
    }

def ensure_key_absent(session, name, check_mode):
    to_delete = [key for key in get_all_keys(session) if key['label'] == name]
    delete_keys(session, to_delete, check_mode=check_mode)

    return {
        'changed': bool(to_delete),
        'deleted_keys': to_delete
    }


def main():
    argument_spec = {
        'user': {'required': True, 'no_log': True},
        'password': {'required': True, 'no_log': True},
        'repository': {'required': True},
        'name': {'required': True},
        'pubkey': {},
        'state': {'choices': ['present', 'absent'], 'default': 'present'},
        'force': {'default': True, 'type': 'bool'},
    }
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    user = module.params['user']
    password = module.params['password']
    repository = module.params['repository']
    name = module.params['name']
    pubkey = module.params.get('pubkey')
    state = module.params['state']
    force = module.params['force']

    if pubkey == None and state == 'present':
        module.fail_json(msg='"pubkey" is required when state=present')

    session = BitbucketSession(module, user, password, repository)
    if state == 'present':
        result = ensure_key_present(session, name, pubkey, force=force,
                                    check_mode=module.check_mode)
    elif state == 'absent':
        result = ensure_key_absent(session, name, check_mode=module.check_mode)

    module.exit_json(**result)

from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.urls import *  # noqa

if __name__ == '__main__':
    main()