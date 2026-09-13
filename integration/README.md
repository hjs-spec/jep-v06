# Local SDK/API interoperability checks

These checks start a temporary API on loopback with disposable state and a test bearer token. They do not deploy or call a live signing service.

`verify_workspace.py` checks the sibling API, SDKs, reference validators and packaged GitHub Action, including restart/replay behavior. Node and Go must be on PATH; install the API/Python validator dependencies and build the TypeScript validator and Action first.

`verify_packages.py` checks installed Python and JavaScript distribution artifacts, plus the sibling Go module (or an explicitly released Go version). Each SDK creates and verifies all J/D/T/V verbs, preserves conformance metadata and diagnostics, and roundtrips hashes. Python also verifies the JavaScript/Go events.

```sh
python integration/verify_packages.py \
  --workspace /path/to/hjs-spec \
  --python-wheel /path/to/jep_sdk_py-0.6.2-py3-none-any.whl \
  --javascript-tarball /path/to/hjs-spec-jep-sdk-js-0.6.2.tgz \
  --go-version v0.6.2
```

Omit `--go-version` when testing local unmerged changes. Wheel and tarball files must be trusted release artifacts or locally built packages. The separate `jep-agent-sdk/scripts/check_coexistence.py` checks the legacy/current Python namespaces and CLI commands in fresh environments, both installation orders and independent uninstalls.
