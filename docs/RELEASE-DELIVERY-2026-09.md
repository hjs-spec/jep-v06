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
| Agent-Blackbox | 0.2.0a1 | [Download](https://github.com/hjs-spec/Agent-Blackbox/releases/tag/v0.2.0a1) |
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

## Pending external configuration

These steps were attempted and did not complete. Test CI passed; registry/deployment jobs report failures rather than concealing them.

| Target | Observed result | Required configuration |
|---|---|---|
| PyPI (13 Python distributions) | OIDC exchange rejected with `invalid-publisher` | Configure a trusted/pending publisher for each declared package: GitHub owner `hjs-spec`, the matching repository, workflow `release.yml`, no GitHub environment. Then rerun only the failed PyPI jobs. |
| npm `@hjs-spec/jep-sdk-js` | Registry PUT rejected with `E404` after correcting the local tarball path | Confirm ownership/publish rights for the npm scope and package. Configure GitHub trusted publishing for `hjs-spec/sdk-js`, workflow `registry.yml` (and `release.yml` for future automatic versions). Then run `registry.yml`; it downloads the already released tarball. |
| HF Space `yuqiangJEP/jep-api` | Deployment stopped before upload: `HF_TOKEN` is not configured in GitHub Actions | Add a Space-write token as the jep-api repository Actions secret `HF_TOKEN`, then provision the Space PostgreSQL and external signing settings described in DEPLOYMENT.md. Rerun the deployment job. |

The connected Hugging Face account was confirmed as `yuqiangJEP`. Its OAuth scopes include repository read and Jobs access, not repository writes; connecting it did not grant Space deployment permission. The public Space still reports API 0.6.0. No live upgrade is claimed.

Publisher configuration references: [PyPI pending projects](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/), [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

## Compatibility limits

The legacy endpoint verifies historical sorted-JSON detached-JWS bytes against explicitly trusted retained public keys. It never upgrades a result to current baseline conformance or silently re-signs it. Existing JEP-04/Claude archive formats keep their own SDK/CLI verifiers. The old HF demo generated a fresh private key at each start; a historical key already lost cannot be reconstructed.

The API does not infer actor identity, authorization, business truth or legal conclusions from a valid signature. Vault integration has protocol-mock coverage; no user Vault endpoint was available for live service testing. PostgreSQL and external secret provisioning are deployment prerequisites, not resources created by the free HF Space.
