"""Exercise the stdin transport without a real credential or API server."""
from types import SimpleNamespace

import pytest

from ansible_collections.rhvp.cluster_utils.plugins.modules import vault_cli_login


@pytest.mark.parametrize("code,ok", [(0, True), (1, False)])
def test_login_sends_token_only_on_stdin(monkeypatch, code, ok):
    seen = {}

    class Connection:
        returncode = code

        def write_stdin(self, value):
            seen["stdin"] = value

        def is_open(self):
            return False

        def close(self):
            seen["closed"] = True

    def stream(*args, **options):
        seen.update(options)
        return Connection()

    monkeypatch.setattr(vault_cli_login, "stream", stream)
    api = SimpleNamespace(connect_get_namespaced_pod_exec=object(),
                          read_namespaced_pod=lambda *_: SimpleNamespace(
                              spec=SimpleNamespace(containers=[SimpleNamespace(name="vault")])))
    assert vault_cli_login.login(api, "fixture", "vault-0", "fixture-value") is ok
    assert seen["stdin"] == "fixture-value\n" and seen["closed"]
    assert all("fixture-value" not in arg for arg in seen["command"])
    assert seen["stdout"] is False and seen["stderr"] is False
    assert seen["container"] == "vault"


def test_multiline_input_is_rejected_before_opening_a_connection():
    with pytest.raises(ValueError):
        vault_cli_login.login(None, "fixture", "vault-0", "one\ntwo")
