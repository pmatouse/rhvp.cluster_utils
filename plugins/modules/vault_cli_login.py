#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

DOCUMENTATION = r"""
module: vault_cli_login
short_description: Restore the stock Vault Pod's CLI session using stdin
description:
  - Uses the same Kubernetes API client as the stock Vault playbooks.
  - Sends the token over exec stdin and suppresses Vault output.
author: Validated Patterns contributors
version_added: "1.1.1"
extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
options:
  namespace:
    type: str
    required: true
    description: Namespace of the Vault server.
  pod:
    type: str
    required: true
    description: Vault server Pod using the stock token helper.
  token:
    type: str
    required: true
    description: Managed Vault bootstrap token.
"""
EXAMPLES = r"""
- name: Log in to an initialized Vault
  rhvp.cluster_utils.vault_cli_login:
    namespace: "{{ vault_ns }}"
    pod: "{{ vault_pod }}"
    token: "{{ root_token }}"
  no_log: true
"""
RETURN = ""

from copy import deepcopy
from time import monotonic

from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import AnsibleModule
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import get_api_client
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import AnsibleK8SModule
from kubernetes.client import CoreV1Api
from kubernetes.stream import stream


def login(api, namespace, pod, token):
    if not token or any(char.isspace() for char in token):
        raise ValueError("invalid token")
    container = api.read_namespaced_pod(pod, namespace).spec.containers[0].name
    # A single line terminates read even on Kubernetes versions without
    # websocket stdin half-close. The shell builtin feeds the Vault CLI a pipe.
    command = ["sh", "-ec", 'IFS= read -r token; printf "%s" "$token" | vault login -no-print -']
    connection = stream(
        api.connect_get_namespaced_pod_exec, pod, namespace,
        command=command, container=container, stdin=True, stdout=False,
        stderr=False, tty=False, _preload_content=False, _request_timeout=30,
    )
    try:
        connection.write_stdin(token + "\n")
        deadline = monotonic() + 60
        while connection.is_open() and monotonic() < deadline:
            connection.update(timeout=1)
        return not connection.is_open() and connection.returncode == 0
    finally:
        connection.close()


def main():
    spec = deepcopy(AUTH_ARG_SPEC)
    spec.update(namespace=dict(type="str", required=True), pod=dict(type="str", required=True),
                token=dict(type="str", required=True, no_log=True))
    module = AnsibleK8SModule(module_class=AnsibleModule, argument_spec=spec,
                              check_pyyaml=False, supports_check_mode=True)
    if module.check_mode:
        module.exit_json(changed=True)
    try:
        client = get_api_client(module).client.client
        if not client.configuration.host.startswith("https://") or not client.configuration.verify_ssl:
            module.fail_json(msg="Vault CLI login requires a verified Kubernetes API connection")
        ok = login(CoreV1Api(client), module.params["namespace"], module.params["pod"], module.params["token"])
    except Exception:
        # Transport and Vault exceptions can contain sensitive output.
        module.fail_json(msg="Unable to establish the Vault CLI session")
    if not ok:
        module.fail_json(msg="Vault CLI login failed")
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
