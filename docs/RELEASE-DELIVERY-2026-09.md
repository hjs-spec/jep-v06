# JEP implementation release delivery — 2026-09-13

## Delivered

The remaining implementation work is merged. GitHub releases exist in 17 repositories. The wire protocol remains version `1` / JEP-Core-0.6; implementation version 0.7 does not introduce a new wire protocol.

- Go: RFC 8785 hashes, detached JWS Ed25519, explicit actor-binding profiles, chain integrity and persistent acceptance replay checks. All 27 common manifest cases pass.
- API 0.7.3: PostgreSQL state shared across hosts; external file-keyring or Vault Transit signing; immutable public-key history through rotation; authenticated signing and nonce consumption; offline SQLite migration and explicit legacy verification.
- Authenticated cross-repository checks: 12 SDK J/D/T/V checks, 12 Python/TypeScript/Go verification checks, copied standalone Action execution, API restart and replay rejection, plus a real CLI request.
- Real PostgreSQL CI: two independent API processes, one winner among 16 concurrent acceptance requests, retained verification of old/new signatures after rotation.
- Downloaded GitHub artifacts were installed outside the source tree: Go binary, Python validator, Python SDK and npm tarball. `go install` of the validator and versioned Go SDK module download also passed.

## SDK/API conformance follow-up

The verification audit exposed missing result metadata, incompatible resolved JWK metadata being accepted, inconsistent diagnostics, and Python package/command collisions. The fixes are merged:

| Component | Fix | Mainline PR |
|---|---|---|
| API 0.7.3 | Complete `conformance_class`/diagnostics; check key type, curve, algorithm, identifier and usage; align errors to the core vectors | [#7](https://github.com/hjs-spec/jep-api/pull/7) |
| Python SDK 0.6.2 | Preserve conformance class and retain old-server and positional-constructor compatibility | [#3](https://github.com/hjs-spec/sdk-py/pull/3) |
| JavaScript SDK 0.6.2 | Update TypeScript result declarations; GitHub tarball released; automatic npm publication disabled | [#5](https://github.com/hjs-spec/sdk-js/pull/5) |
| Go SDK 0.6.2 | Preserve conformance class and diagnostics | [#3](https://github.com/hjs-spec/sdk-go/pull/3) |
| Legacy Agent SDK 2.0.0 | Use `jep_agent` imports and `jep-agent` command, avoiding current SDK/CLI collisions | [#3](https://github.com/hjs-spec/jep-agent-sdk/pull/3) |

API regression: all 26 official event vectors agree on validity, completed level, error code and every positive event hash; every response passes the result schema. The API CI also passed with real PostgreSQL. The API remains a Level 1 service; actor binding, full chain and policy validation are not newly claimed.

Installed-artifact checks cover each SDK creating/verifying J/D/T/V (12 events), 8 cross-SDK verifications and 12 hash comparisons. Legacy/current Python packages and the CLI were installed in both orders in fresh environments; installed files are disjoint, each SDK survives uninstalling the other, and legacy signatures still verify. The tests are reproducible with [the integration scripts](../integration/README.md) and the Agent SDK package-coexistence CI job.

Agent SDK 2.0 is an import/command migration, not a rewrite of historical signed events or a claim that its legacy format is JEP-Core-0.6. Existing 1.x shared environments should follow [MIGRATION-2.md](https://github.com/hjs-spec/jep-agent-sdk/blob/main/MIGRATION-2.md). Current clients retain their existing imports.

npm publication and live API deployment remain deferred. The 0.6.2 JavaScript release has a successful GitHub package job and a skipped npm job. No HF deployment or database provisioning was performed.

## Repository follow-up resolved — 2026-09-13

The follow-up found remaining command collisions, unsafe prototype defaults and outdated onboarding/architecture descriptions. The fixes below are merged; code PR CI and post-merge CI passed. The earlier audit covered 19 implementation/release repositories plus six additional onboarding/architecture/Sidecar repositories. This is a resolution of those concrete findings, not a claim that every repository implements every Core/HJS/JAC verification scope.

| Finding | Delivered correction | Merged PR |
|---|---|---|
| Runtime and E2E overwrite the standalone `jep` executable | Runtime 0.2.0 uses `jep-runtime`; E2E 0.2.0 uses `jep-e2e`. Added install-order, file-ownership and independent-uninstall gates | [runtime #5](https://github.com/hjs-spec/jep-runtime/pull/5), [E2E #3](https://github.com/hjs-spec/jep-e2e-demo/pull/3) |
| Sidecar approves without policy, accepts empty context and uses unstable key IDs | Explicit policy callback, default undetermined, request validation, public-key fingerprint IDs, trusted-key receipt verification and working package installation | [Sidecar #1](https://github.com/hjs-spec/aip-judgment-sidecar/pull/1) |
| Main onboarding uses historical unsigned mocks | Real Python SDK and loopback Core 0.6 API; signed event export and archival verification; explicit historical paths | [quickstart #2](https://github.com/hjs-spec/jep-quickstart/pull/2), [E2E #3](https://github.com/hjs-spec/jep-e2e-demo/pull/3) |
| Four broken organization SDK/CLI links | Correct repository targets and current local onboarding | [profile #1](https://github.com/hjs-spec/.github/pull/1) |
| Incorrect protocol expansions and layer claims | Judgment Event Protocol; HJS archive/privacy/receipt lifecycle; JAC declared dependencies; explicit runtime policy and Core Level 1 boundaries; five regenerated diagrams | [architecture #2](https://github.com/hjs-spec/jep-architecture/pull/2), [logging explanation #2](https://github.com/hjs-spec/jep-vs-logging/pull/2) |
| npm recovery instructions refer to 0.6.1 | Updated to 0.6.2 and explicitly paused; workflows and package version unchanged | [JS SDK #6](https://github.com/hjs-spec/sdk-js/pull/6) |
| Redundant LangGraph PR remains open | Closed without re-merging: PR #1 and the previously merged PR #2 commit have identical tree `683302205768f8b93ba09d391e3e6e8ef6bad9ef` | [LangGraph #1](https://github.com/hjs-spec/jep-langgraph-adapter/pull/1) |

Validation: 62 focused tests passed (Runtime 9, Sidecar 29, Quickstart 12, E2E 12). The Quickstart and E2E suites use an actual isolated API subprocess pinned to API commit `45082b3e9e9e81f35596311d6a686ae5fdae5427`. They exercise signatures, tampering, duplicate/invalid archives, expected demo ordering, repeatable archival verification, explicit legacy handling and documented examples. Five packages (`jep-sdk-py`, `jep-cli`, `jep-agent-sdk`, `jep-runtime`, `jep-e2e-demo`) passed both installation orders, disjoint file ownership and independent command uninstall checks. All four modified Python projects build wheel/source distributions and pass packaging checks.

Release gates passed for [Runtime](https://github.com/hjs-spec/jep-runtime/actions/runs/34744118101), [Sidecar](https://github.com/hjs-spec/aip-judgment-sidecar/actions/runs/34744120547) and [E2E](https://github.com/hjs-spec/jep-e2e-demo/actions/runs/34744121851). All three 0.2.0 tags target their merged commits. The six downloaded wheel/source artifacts match their GitHub SHA-256 digests; Runtime's two public PyPI hashes also match GitHub. Sidecar and E2E provide GitHub distributions only; this follow-up did not configure new PyPI publishers. Quickstart installs from its repository.

Fresh-environment checks using the downloaded release wheels passed: Runtime command loading, E2E signed J/D/T/V creation and replay through the local API, and Sidecar undetermined receipt signing/verification. The built Quickstart wheel also created and verified a real signed event. Published Python modules were compared byte-for-byte with the merged source.

The E2E historical archive is preserved byte-for-byte at `legacy/archive.jsonl` (SHA-256 `6431aac3266758aa7341a62158a0d7496f8cb5bc03c3a535ec4edf719af89bd8`). The Sidecar is an independent versioned receipt prototype using historical sorted ASCII JSON signatures, not a Core 0.6 event. Default demo verification reports Core Level 1 plus explicitly named local checks; it does not imply HJS/JAC conformance, identity binding, valid authority, external truth or completeness.

If an environment previously installed packages sharing `jep`, upgrade the old Runtime/E2E packages first, then reinstall `jep-cli==0.6.1` to restore command ownership. Keep `jep` for CLI, `jep-runtime` for Runtime, `jep-e2e` for this demo and `jep-agent` for the historical Agent SDK. See each package's migration notes before replaying old data.

npm publication, live API/Hugging Face deployment and external database provisioning remain paused. Frozen protocol/comparison baselines retain their original pins.

## Companion repositories resolved — 2026-09-13

The organization inventory has 32 repositories (31 public and one private,
including two archived historical repositories). The supplemental review of
seven repositories outside the earlier 25 found concrete issues in HJS, JAC
and the whitepaper entry page. These findings are now resolved:

| Repository | Delivered correction | Merged PR |
|---|---|---|
| HJS 0.5 companion | Core 0.6 detached JWS and canonical hashes via the released validator; missing-reference rejection; repeatable archival and persistent atomic acceptance replay checks; offline receipt schema validation; copied immutable archive snapshots; explicit legacy signature reader | [hjs-05 #2](https://github.com/hjs-spec/hjs-05/pull/2), [#3](https://github.com/hjs-spec/hjs-05/pull/3) |
| JAC 0.5 seed | RFC 8785 hashes; attach extensions before signing without mutating inputs; copied fragment exports; strict declaration/container/digest checks; declared-break handling; explicit historical hash verification and honest validation scope | [jac-agent-02 #1](https://github.com/hjs-spec/jac-agent-02/pull/1) |
| Whitepaper entry | Repaired current protocol/API/validator links, corrected the implementation label and aligned the README notice with the existing CC0 license | [whitepaper #1](https://github.com/hjs-spec/whitepaper/pull/1) |

Validation: HJS 46 tests and JAC 47 tests passed locally and in their PR CI;
both post-merge workflows also passed. HJS CI includes bidirectional signature
interoperability against the real API implementation pinned at
`45082b3e9e9e81f35596311d6a686ae5fdae5427`. The existing HJS/APS canonical
vectors still pass, and default discovery now includes the four previously
omitted archive tests. Immutability compares canonical bytes, including the
regression where Python conflates `1` with `true`. Local Gradio HTTP smoke
verified all three actions;
workflow syntax checks passed. Whitepaper changes affect only README.md;
target repositories and the reference-validator path were checked directly.

Verification scope remains explicit. HJS reports Core Level 1 with local
reference availability; its demo receipt store is in memory, and retention or
redaction metadata is not proof of enforcement. A receipt reports structure
and optional event-hash binding, not signature authenticity. JAC validates
extension declarations and can verify exported hash binding; it does not
resolve/authenticate parent objects, prove authority or establish complete
logging. Critical JAC extensions require a JAC-aware consumer, so rejection by
the current Core-only API is expected. Demo placeholders are not signed Core
events.

Historical signed bytes, HJS/APS fixtures, JAC example/report bytes and the
original whitepaper body and LICENSE are unchanged. The archived `jep-v0.4`
and `hjs-v04` repositories, research corpus and frozen comparison baseline
retain their historical contents and pins. No new release package, npm
publication, Hugging Face upload or live API deployment was performed in this
companion follow-up; the corrected source is available on main.

## Available GitHub versions

| Repository | Version | Release |
|---|---|---|
| aip-judgment-sidecar | 0.2.0 | [Download](https://github.com/hjs-spec/aip-judgment-sidecar/releases/tag/v0.2.0) |
| jep-e2e-demo | 0.2.0 | [Download](https://github.com/hjs-spec/jep-e2e-demo/releases/tag/v0.2.0) |
| Agent-Blackbox | 0.2.0a2 | [Download](https://github.com/hjs-spec/Agent-Blackbox/releases/tag/v0.2.0a2) |
| cli | 0.6.1 | [Download](https://github.com/hjs-spec/cli/releases/tag/v0.6.1) |
| jep-agent-sdk | 2.0.0 | [Download](https://github.com/hjs-spec/jep-agent-sdk/releases/tag/v2.0.0) |
| jep-api | 0.7.3 | [Download](https://github.com/hjs-spec/jep-api/releases/tag/v0.7.3) |
| jep-authority-runtime | 0.1.1 | [Download](https://github.com/hjs-spec/jep-authority-runtime/releases/tag/v0.1.1) |
| jep-claude-replay | 0.1.1 | [Download](https://github.com/hjs-spec/jep-claude-replay/releases/tag/v0.1.1) |
| jep-github-action | 0.6.2 | [Download](https://github.com/hjs-spec/jep-github-action/releases/tag/v0.6.2) |
| jep-langgraph-adapter | 0.1.1 | [Download](https://github.com/hjs-spec/jep-langgraph-adapter/releases/tag/v0.1.1) |
| jep-lineage-explorer | 0.1.1 | [Download](https://github.com/hjs-spec/jep-lineage-explorer/releases/tag/v0.1.1) |
| jep-mcp-wrapper | 0.1.1 | [Download](https://github.com/hjs-spec/jep-mcp-wrapper/releases/tag/v0.1.1) |
| jep-openai-agents-middleware | 0.1.1 | [Download](https://github.com/hjs-spec/jep-openai-agents-middleware/releases/tag/v0.1.1) |
| jep-runtime | 0.2.0 | [Download](https://github.com/hjs-spec/jep-runtime/releases/tag/v0.2.0) |
| jep-v06 | 0.7.0 | [Download](https://github.com/hjs-spec/jep-v06/releases/tag/v0.7.0) |
| sdk-go | 0.6.2 | [Download](https://github.com/hjs-spec/sdk-go/releases/tag/v0.6.2) |
| sdk-js | 0.6.2 | [Download](https://github.com/hjs-spec/sdk-js/releases/tag/v0.6.2) |
| sdk-py | 0.6.2 | [Download](https://github.com/hjs-spec/sdk-py/releases/tag/v0.6.2) |
| shutup-mcp | 0.3.0a1 | [Download](https://github.com/hjs-spec/shutup-mcp/releases/tag/v0.3.0a1) |

API container: `ghcr.io/hjs-spec/jep-api:0.7.3`. Its build/push workflow passed. Anonymous GHCR access returned HTTP 401; public pull availability is not claimed. Use authorized package access or configure package visibility in GitHub. Existing package versions and tags were retained.

## PyPI delivery complete

All 13 Python distributions are published. Public PyPI wheel and source-distribution hashes match their GitHub release artifacts, and public pip wheel downloads passed. Failed PyPI jobs were retried after the owner configured their trusted publishers. Existing versions and GitHub release assets were retained.

| PyPI project | Published version | GitHub repository |
|---|---|---|
| [agent-blackbox-jep](https://pypi.org/project/agent-blackbox-jep/0.2.0a2/) | `0.2.0a2` | `Agent-Blackbox` |
| [jep-cli](https://pypi.org/project/jep-cli/0.6.1/) | `0.6.1` | `cli` |
| [jep-agent-sdk](https://pypi.org/project/jep-agent-sdk/2.0.0/) | `2.0.0` | `jep-agent-sdk` |
| [jep-authority-runtime](https://pypi.org/project/jep-authority-runtime/0.1.1/) | `0.1.1` | `jep-authority-runtime` |
| [jep-claude-replay](https://pypi.org/project/jep-claude-replay/0.1.1/) | `0.1.1` | `jep-claude-replay` |
| [jep-langgraph-adapter](https://pypi.org/project/jep-langgraph-adapter/0.1.1/) | `0.1.1` | `jep-langgraph-adapter` |
| [jep-lineage-explorer](https://pypi.org/project/jep-lineage-explorer/0.1.1/) | `0.1.1` | `jep-lineage-explorer` |
| [jep-mcp-wrapper](https://pypi.org/project/jep-mcp-wrapper/0.1.1/) | `0.1.1` | `jep-mcp-wrapper` |
| [jep-openai-agents-middleware](https://pypi.org/project/jep-openai-agents-middleware/0.1.1/) | `0.1.1` | `jep-openai-agents-middleware` |
| [jep-runtime](https://pypi.org/project/jep-runtime/0.2.0/) | `0.2.0` | `jep-runtime` |
| [jep-v06-conformance-seed](https://pypi.org/project/jep-v06-conformance-seed/0.7.0/) | `0.7.0` | `jep-v06` |
| [jep-sdk-py](https://pypi.org/project/jep-sdk-py/0.6.2/) | `0.6.2` | `sdk-py` |
| [shutup-mcp](https://pypi.org/project/shutup-mcp/0.3.0a1/) | `0.3.0a1` | `shutup-mcp` |

The Blackbox distribution uses the owner's available suffixed name `agent-blackbox-jep`; its Python import remains `agent_blackbox`.

## Registry blocker and deferred API deployment

The owner has narrowed API delivery to the repository implementation aligned with JEP-Core-0.6. Live API deployment and external database provisioning are deferred. Implementation version `0.7.3` is a software version; the protocol profile remains `jep-core-0.6` with wire version `1`. npm publication remains paused by the owner; prior account errors are historical evidence. Historical workflow failures are retained as evidence.

| Target | Observed result | Next action |
|---|---|---|
| npm `@hjs-spec/jep-sdk-js` | Earlier recovery attempt reported `ENEEDAUTH` without credentials; publication remains paused | Confirm ownership/publish rights for the npm scope and package. Configure GitHub trusted publishing for `hjs-spec/sdk-js`, workflow `registry.yml` (or an explicitly opted-in `release.yml` dispatch), or supply the supported repository secret `NPM_TOKEN` for initial publication. Then run `registry.yml`; it downloads the already released tarball. |
| HF Space `yuqiangJEP/jep-api` | Repository code is updated for JEP-Core-0.6; live deployment is deferred by the owner | No deployment or database setup now. Configuration checks and deployment are manual-only workflows on `main`; code merges and implementation releases do not trigger them. |

The connected Hugging Face account was confirmed as `yuqiangJEP`. Its OAuth scopes include repository read and Jobs access, not repository writes; connecting it did not grant Space deployment permission. The owner separately configured `HF_TOKEN` in GitHub Actions, and [the read-only configuration check](https://github.com/hjs-spec/jep-api/actions/runs/34740151251) authenticated successfully. It stopped on missing settings without uploading or restarting. The public Space remains on API 0.6.0; no live upgrade is claimed.

Publisher configuration references: [PyPI pending projects](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/), [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

## Registry recovery and future deployment reference

Initial retries returned PyPI `invalid-publisher`, npm `E404`, and missing HF_TOKEN. After the owner configured trusted publishers, all 13 PyPI distributions listed above were published successfully. An earlier npm recovery attempt reported `ENEEDAUTH` without credentials; npm setup is paused because the owner reports a login restriction. HF_TOKEN now authenticates; the Space configuration below is retained only for a future deployment requested by the owner. No npm publication or live HF deployment is claimed.

### PyPI future releases

No Python package setup remains for the versions above. Each project now has its configured GitHub trusted publisher: owner `hjs-spec`, the matching repository, workflow filename `release.yml`, and no environment. Keep that configuration for future versioned releases. Do not rerun complete release workflows for existing versions; they intentionally refuse to overwrite an existing GitHub release.

### npm

The account needs publish rights to the npm scope `@hjs-spec`. Configure trusted publishing for repository `hjs-spec/sdk-js`, workflows `registry.yml` and `release.yml`, empty environment, with direct **npm publish** allowed. If initial publication requires a token, the current workflows now accept the repository Actions secret `NPM_TOKEN` in the publish step. See the [exact recovery procedure](https://github.com/hjs-spec/sdk-js/blob/main/PUBLISHING.md). Only after the owner explicitly resumes publication, use **Run workflow** on `registry.yml` at `main` after configuring the account so that the new credential handling is used.

### Hugging Face (deferred)

`HF_TOKEN` is configured in [jep-api Actions secrets](https://github.com/hjs-spec/jep-api/settings/secrets/actions), and authenticated configuration reads passed. A new upload gate checks all required setting names before deployment; its 7 focused tests and the full API CI passed in [PR #5](https://github.com/hjs-spec/jep-api/pull/5). [PR #6](https://github.com/hjs-spec/jep-api/pull/6) makes configuration checks and deployment manual-only to honor the owner's code-only delivery scope. Secret contents and service connectivity still require startup/health validation. The following four [Space settings](https://huggingface.co/spaces/yuqiangJEP/jep-api/settings) are needed only when deployment resumes:

| Setting | Type | Required value |
|---|---|---|
| `JEP_DEPLOYMENT_MODE` | Variable | `production` |
| `JEP_DATABASE_URL` | Secret | Shared PostgreSQL connection URL |
| `JEP_KEYRING_JSON` | Secret | Existing external signing keyring, or use the documented Vault configuration |
| `JEP_SIGNING_TOKEN` | Secret | API Bearer token required for signing and nonce consumption |

Keyring generation, Vault alternatives and migration are documented in [API deployment instructions](https://github.com/hjs-spec/jep-api/blob/main/DEPLOYMENT.md). When the owner resumes deployment, configure these first, manually run the read-only `check-hf.yml` workflow, then manually run `deploy.yml` at current `main`. Secrets belong in the account settings, never in commits or the chat.

## Compatibility limits

The legacy endpoint verifies historical sorted-JSON detached-JWS bytes against explicitly trusted retained public keys. It never upgrades a result to current baseline conformance or silently re-signs it. Existing JEP-04/Claude archive formats keep their own SDK/CLI verifiers. The old HF demo generated a fresh private key at each start; a historical key already lost cannot be reconstructed.

The API does not infer actor identity, authorization, business truth or legal conclusions from a valid signature. Vault integration has protocol-mock coverage; no user Vault endpoint was available for live service testing. PostgreSQL and external secret provisioning are deployment prerequisites, not resources created by the free HF Space.
