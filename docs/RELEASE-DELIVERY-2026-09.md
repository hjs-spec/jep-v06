# JEP implementation release delivery — 2026-09-13

## Delivered

The remaining implementation work is merged. GitHub releases exist in 17 repositories. The wire protocol remains version `1` / JEP-Core-0.6; implementation version 0.7 does not introduce a new wire protocol.

- Go: RFC 8785 hashes, detached JWS Ed25519, explicit actor-binding profiles, chain integrity and persistent acceptance replay checks. All 27 common manifest cases pass.
- API 0.7.2: PostgreSQL state shared across hosts; external file-keyring or Vault Transit signing; immutable public-key history through rotation; authenticated signing and nonce consumption; offline SQLite migration and explicit legacy verification.
- Authenticated cross-repository checks: 12 SDK J/D/T/V checks, 12 Python/TypeScript/Go verification checks, copied standalone Action execution, API restart and replay rejection, plus a real CLI request.
- Real PostgreSQL CI: two independent API processes, one winner among 16 concurrent acceptance requests, retained verification of old/new signatures after rotation.
- Downloaded GitHub artifacts were installed outside the source tree: Go binary, Python validator, Python SDK and npm tarball. `go install` of the validator and versioned Go SDK module download also passed.

## Available GitHub versions

| Repository | Version | Release |
|---|---|---|
| Agent-Blackbox | 0.2.0a2 | [Download](https://github.com/hjs-spec/Agent-Blackbox/releases/tag/v0.2.0a2) |
| cli | 0.6.1 | [Download](https://github.com/hjs-spec/cli/releases/tag/v0.6.1) |
| jep-agent-sdk | 1.0.1 | [Download](https://github.com/hjs-spec/jep-agent-sdk/releases/tag/v1.0.1) |
| jep-api | 0.7.2 | [Download](https://github.com/hjs-spec/jep-api/releases/tag/v0.7.2) |
| jep-authority-runtime | 0.1.1 | [Download](https://github.com/hjs-spec/jep-authority-runtime/releases/tag/v0.1.1) |
| jep-claude-replay | 0.1.1 | [Download](https://github.com/hjs-spec/jep-claude-replay/releases/tag/v0.1.1) |
| jep-github-action | 0.6.2 | [Download](https://github.com/hjs-spec/jep-github-action/releases/tag/v0.6.2) |
| jep-langgraph-adapter | 0.1.1 | [Download](https://github.com/hjs-spec/jep-langgraph-adapter/releases/tag/v0.1.1) |
| jep-lineage-explorer | 0.1.1 | [Download](https://github.com/hjs-spec/jep-lineage-explorer/releases/tag/v0.1.1) |
| jep-mcp-wrapper | 0.1.1 | [Download](https://github.com/hjs-spec/jep-mcp-wrapper/releases/tag/v0.1.1) |
| jep-openai-agents-middleware | 0.1.1 | [Download](https://github.com/hjs-spec/jep-openai-agents-middleware/releases/tag/v0.1.1) |
| jep-runtime | 0.1.1 | [Download](https://github.com/hjs-spec/jep-runtime/releases/tag/v0.1.1) |
| jep-v06 | 0.7.0 | [Download](https://github.com/hjs-spec/jep-v06/releases/tag/v0.7.0) |
| sdk-go | 0.6.1 | [Download](https://github.com/hjs-spec/sdk-go/releases/tag/v0.6.1) |
| sdk-js | 0.6.1 | [Download](https://github.com/hjs-spec/sdk-js/releases/tag/v0.6.1) |
| sdk-py | 0.6.1 | [Download](https://github.com/hjs-spec/sdk-py/releases/tag/v0.6.1) |
| shutup-mcp | 0.3.0a1 | [Download](https://github.com/hjs-spec/shutup-mcp/releases/tag/v0.3.0a1) |

API container: `ghcr.io/hjs-spec/jep-api:0.7.2`. Its build/push workflow passed. Anonymous GHCR access returned HTTP 401; public pull availability is not claimed. Use authorized package access or configure package visibility in GitHub. Existing package versions and tags were retained.

## PyPI delivery complete

All 13 Python distributions are published. Public PyPI wheel and source-distribution hashes match their GitHub release artifacts, and public pip wheel downloads passed. Failed PyPI jobs were retried after the owner configured their trusted publishers. Existing versions and GitHub release assets were retained.

| PyPI project | Published version | GitHub repository |
|---|---|---|
| [agent-blackbox-jep](https://pypi.org/project/agent-blackbox-jep/0.2.0a2/) | `0.2.0a2` | `Agent-Blackbox` |
| [jep-cli](https://pypi.org/project/jep-cli/0.6.1/) | `0.6.1` | `cli` |
| [jep-agent-sdk](https://pypi.org/project/jep-agent-sdk/1.0.1/) | `1.0.1` | `jep-agent-sdk` |
| [jep-authority-runtime](https://pypi.org/project/jep-authority-runtime/0.1.1/) | `0.1.1` | `jep-authority-runtime` |
| [jep-claude-replay](https://pypi.org/project/jep-claude-replay/0.1.1/) | `0.1.1` | `jep-claude-replay` |
| [jep-langgraph-adapter](https://pypi.org/project/jep-langgraph-adapter/0.1.1/) | `0.1.1` | `jep-langgraph-adapter` |
| [jep-lineage-explorer](https://pypi.org/project/jep-lineage-explorer/0.1.1/) | `0.1.1` | `jep-lineage-explorer` |
| [jep-mcp-wrapper](https://pypi.org/project/jep-mcp-wrapper/0.1.1/) | `0.1.1` | `jep-mcp-wrapper` |
| [jep-openai-agents-middleware](https://pypi.org/project/jep-openai-agents-middleware/0.1.1/) | `0.1.1` | `jep-openai-agents-middleware` |
| [jep-runtime](https://pypi.org/project/jep-runtime/0.1.1/) | `0.1.1` | `jep-runtime` |
| [jep-v06-conformance-seed](https://pypi.org/project/jep-v06-conformance-seed/0.7.0/) | `0.7.0` | `jep-v06` |
| [jep-sdk-py](https://pypi.org/project/jep-sdk-py/0.6.1/) | `0.6.1` | `sdk-py` |
| [shutup-mcp](https://pypi.org/project/shutup-mcp/0.3.0a1/) | `0.3.0a1` | `shutup-mcp` |

The Blackbox distribution uses the owner's available suffixed name `agent-blackbox-jep`; its Python import remains `agent_blackbox`.

## Pending external configuration

The remaining steps below were attempted and did not complete. Test CI passed; registry/deployment jobs report failures rather than concealing them.

| Target | Observed result | Required configuration |
|---|---|---|
| npm `@hjs-spec/jep-sdk-js` | Current recovery workflow reports `ENEEDAUTH` without credentials | Confirm ownership/publish rights for the npm scope and package. Configure GitHub trusted publishing for `hjs-spec/sdk-js`, workflow `registry.yml` (and `release.yml` for future automatic versions), or supply the supported repository secret `NPM_TOKEN` for initial publication. Then run `registry.yml`; it downloads the already released tarball. |
| HF Space `yuqiangJEP/jep-api` | `HF_TOKEN` authenticates and can read Space configuration metadata; the read-only check reports missing production mode, PostgreSQL URL, signing token and keyring | Provision those Space settings as described in DEPLOYMENT.md. Run `check-hf.yml`, then run `deploy.yml` at current `main` after configuration. |

The connected Hugging Face account was confirmed as `yuqiangJEP`. Its OAuth scopes include repository read and Jobs access, not repository writes; connecting it did not grant Space deployment permission. The owner separately configured `HF_TOKEN` in GitHub Actions, and [the read-only configuration check](https://github.com/hjs-spec/jep-api/actions/runs/34740151251) authenticated successfully. It stopped on missing settings without uploading or restarting. The public Space remains on API 0.6.0; no live upgrade is claimed.

Publisher configuration references: [PyPI pending projects](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/), [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

## Recovery configuration to enter

Initial retries returned PyPI `invalid-publisher`, npm `E404`, and missing HF_TOKEN. After the owner configured trusted publishers, all 13 PyPI distributions listed above were published successfully. The current npm recovery workflow reports `ENEEDAUTH` without credentials; npm setup is paused because the owner reports a login restriction. HF_TOKEN now authenticates, with the remaining Space configuration listed below. No npm publication or live HF deployment is claimed.

### PyPI future releases

No Python package setup remains for the versions above. Each project now has its configured GitHub trusted publisher: owner `hjs-spec`, the matching repository, workflow filename `release.yml`, and no environment. Keep that configuration for future versioned releases. Do not rerun complete release workflows for existing versions; they intentionally refuse to overwrite an existing GitHub release.

### npm

The account needs publish rights to the npm scope `@hjs-spec`. Configure trusted publishing for repository `hjs-spec/sdk-js`, workflows `registry.yml` and `release.yml`, empty environment, with direct **npm publish** allowed. If initial publication requires a token, the current workflows now accept the repository Actions secret `NPM_TOKEN` in the publish step. See the [exact recovery procedure](https://github.com/hjs-spec/sdk-js/blob/main/PUBLISHING.md). Use **Run workflow** on `registry.yml` at `main` after configuring the account so that the new credential handling is used.

### Hugging Face

`HF_TOKEN` is configured in [jep-api Actions secrets](https://github.com/hjs-spec/jep-api/settings/secrets/actions), and authenticated configuration reads passed. A new upload gate checks all required setting names before deployment; its 7 focused tests and the full API CI passed in [PR #5](https://github.com/hjs-spec/jep-api/pull/5). Secret contents and service connectivity still require startup/health validation. In the [Space settings](https://huggingface.co/spaces/yuqiangJEP/jep-api/settings), configure the four missing entries:

| Setting | Type | Required value |
|---|---|---|
| `JEP_DEPLOYMENT_MODE` | Variable | `production` |
| `JEP_DATABASE_URL` | Secret | Shared PostgreSQL connection URL |
| `JEP_KEYRING_JSON` | Secret | Existing external signing keyring, or use the documented Vault configuration |
| `JEP_SIGNING_TOKEN` | Secret | API Bearer token required for signing and nonce consumption |

Keyring generation, Vault alternatives and migration are documented in [API deployment instructions](https://github.com/hjs-spec/jep-api/blob/main/DEPLOYMENT.md). Configure these before deployment; a write token alone is insufficient for production startup. Run the read-only `check-hf.yml` workflow, then run `deploy.yml` at current `main` to use the new upload gate. Secrets belong in the account settings, never in commits or the chat.

## Compatibility limits

The legacy endpoint verifies historical sorted-JSON detached-JWS bytes against explicitly trusted retained public keys. It never upgrades a result to current baseline conformance or silently re-signs it. Existing JEP-04/Claude archive formats keep their own SDK/CLI verifiers. The old HF demo generated a fresh private key at each start; a historical key already lost cannot be reconstructed.

The API does not infer actor identity, authorization, business truth or legal conclusions from a valid signature. Vault integration has protocol-mock coverage; no user Vault endpoint was available for live service testing. PostgreSQL and external secret provisioning are deployment prerequisites, not resources created by the free HF Space.
