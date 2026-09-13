# JEP ecosystem hardening — 2026-09-13

This pass continues the existing repair branches and adds repairs in the active runtime, adapter, viewer, CLI, and Action repositories. It covers 19 repositories. The changes are reviewable pull requests; no main-branch merge, deployment, or package publication is included.

## Review map

| Repository | Repair PR | Local validation |
|---|---|---|
| Agent-Blackbox | [#1](https://github.com/hjs-spec/Agent-Blackbox/pull/1) | 11 Python |
| JEP-EU-AI-Act-Mapping-Notes | [#1](https://github.com/hjs-spec/JEP-EU-AI-Act-Mapping-Notes/pull/1) | 15 Python |
| cli | [#1](https://github.com/hjs-spec/cli/pull/1) | 9 Python |
| jep-agent-sdk | [#1](https://github.com/hjs-spec/jep-agent-sdk/pull/1) | 23 Python + Ruff/Black |
| jep-api | [#1](https://github.com/hjs-spec/jep-api/pull/1) | 22 Python |
| jep-authority-runtime | [#2](https://github.com/hjs-spec/jep-authority-runtime/pull/2) | 8 Python |
| jep-claude-replay | [#2](https://github.com/hjs-spec/jep-claude-replay/pull/2) | 29 Python |
| jep-github-action | [#1](https://github.com/hjs-spec/jep-github-action/pull/1) | 5 Node + standalone bundle |
| jep-langgraph-adapter | [#3](https://github.com/hjs-spec/jep-langgraph-adapter/pull/3) | 8 Python |
| jep-lineage-explorer | [#2](https://github.com/hjs-spec/jep-lineage-explorer/pull/2) | 6 Python |
| jep-mcp-wrapper | [#2](https://github.com/hjs-spec/jep-mcp-wrapper/pull/2) | 9 Python |
| jep-openai-agents-middleware | [#2](https://github.com/hjs-spec/jep-openai-agents-middleware/pull/2) | 8 Python, including real offline Runner |
| jep-replay-visualizer | [#2](https://github.com/hjs-spec/jep-replay-visualizer/pull/2) | 8 Node |
| jep-runtime | [#3](https://github.com/hjs-spec/jep-runtime/pull/3) | 9 Python |
| jep-v06 | [#1](https://github.com/hjs-spec/jep-v06/pull/1) | 34 Python + 27 manifest vectors + 24 TS vectors + Go |
| sdk-go | [#1](https://github.com/hjs-spec/sdk-go/pull/1) | Go race suite |
| sdk-js | [#1](https://github.com/hjs-spec/sdk-js/pull/1) | 8 Node |
| sdk-py | [#1](https://github.com/hjs-spec/sdk-py/pull/1) | 10 Python |
| shutup-mcp | [#1](https://github.com/hjs-spec/shutup-mcp/pull/1) | 14 Python |

## Verification evidence

- 215 Python tests passed across the affected Python repositories, including the real OpenAI Agents SDK 0.22.2 Runner with a local model and tracing disabled.
- 21 Node unit tests passed across the JavaScript SDK, replay visualizer, and GitHub Action.
- Python manifest: 27/27 cases, checking validity, precise error code, completed level, and selected event hashes.
- TypeScript: 8 valid and 16 invalid conformance vectors plus persistent acceptance replay checks.
- Go SDK race tests and the explicitly syntax-only Go validator suite passed.
- `integration/verify_workspace.py`: 12 SDK J/D/T/V checks and 8 Python/TypeScript validator checks passed. A copied standalone Action bundle called the real local API. After restarting that API, existing signatures still verified and a previously consumed nonce was rejected.

The source schemas in this repository, jep-api, and jep-github-action are identical. Each repository's HARDENING.md records their shared SHA-256. GitHub CI statuses are attached to the individual PR heads; local evidence does not stand in for their live status.

## Behavior changes

Signed event serialization preserves member presence and types. RFC 8785 is used by current wire producers/verifiers, while historical archive formats retain explicitly named compatibility boundaries. Malformed signatures, weak public-key forgeries, unsupported critical extensions, stale inputs, and replay attempts fail closed.

The API has durable local signing/replay/event state. Execution adapters record failures and cancellation, await asynchronous work, preserve input snapshots, and only claim verification when a verifier actually ran. Authority checks enforce actor continuity, expiry, declared ancestry, scope narrowing, and revocation. Replay viewers expose observed/unknown authority and do not claim cryptographic verification.

## Compatibility and deployment boundaries

- The API's default SQLite state directory must persist across restarts and be shared by same-host workers. Multiple hosts need a shared transactional store and deployment-specific key management. The signing API does not authenticate a caller's claimed who identity.
- The stricter current creation schema rejects empty/null claims and malformed sha256 digests. Transport SDKs may still preserve historical values without asserting their conformance.
- Local/legacy runtime envelopes are not silently migrated into the detached-JWS wire format. Agent Blackbox's legacy signature canonicalization requires explicit opt-in.
- Mock profiles and visualization projections do not implement production IAM, legal judgments, or external truth checks.
- The standalone validator's shared replay-cache lock fails closed if busy or left by a crash. Remove a stale lock only after confirming its owner is gone; do not reset the cache during the active freshness window.

Review the conformance/API/SDK/Action changes together. Runtime adapter and viewer PRs are independently reviewable. Keep the existing repair history and merge only after the relevant checks and review are complete.
