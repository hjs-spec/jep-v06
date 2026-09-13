# Conformance and interoperability follow-up

The conformance repair now incorporates current main and the Binding/01 note. The completed one-shot alignment dispatcher is retired.

Python and TypeScript reject non-canonical base64url and identity-key forgeries. Ed25519 verification uses PyNaCl/libsodium and strict noble-curves verification respectively, with OpenSSL retained for normal key/signature operations. Sources: https://pynacl.readthedocs.io/en/latest/signing/ and the pinned @noble/curves 1.9.7 source.

Python, TypeScript and Go share an exclusive directory-lock convention around replay-cache reload/check/replace. Concurrent acceptance can succeed only once. A busy or stale `.consume-lock` causes a closed failure; retry a busy verifier. After a crashed process, remove a stale lock only after confirming no verifier owns it. Never delete the replay cache while its freshness window is active. Cache paths must identify the same local file; multi-host deployments need a shared transactional store.

The manifest includes exact negative cases for signature encoding and weak keys. The schema permits empty optional ext_crit arrays while enforcing 64 hexadecimal digits for sha256. TypeScript dependencies are locked and CI uses npm ci. Go now passes the same 27-case manifest and implements cryptographic, explicit local actor-binding, chain and acceptance checks. Its `syntax` command is the explicit Level-0-only path.

`integration/verify_workspace.py` checks sibling SDK/API J/D/T/V transport, Python/TypeScript event hashes, the standalone Action bundle, and persistent API restart/replay behavior. It needs pytest/API dependencies, node, go, and a built TypeScript validator and GitHub Action. Run `python integration/verify_workspace.py --workspace /path/to/hjs-spec` after checking out the corresponding repair branches. Archives in other repositories retain their explicitly local/legacy formats; they do not acquire JEP-Core conformance by name.

Shared event schema SHA-256: `5d0527c1649bd49f0de632e660eff46096522ea76a49eb7104ac83522614059f`.
