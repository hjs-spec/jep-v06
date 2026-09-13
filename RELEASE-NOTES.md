# Release 0.7.0

Includes the reviewed September 2026 integrity, replay, persistence, async-lifecycle and compatibility repairs applicable to this repository. Wire/profile versions are unchanged unless explicitly described in the repository hardening notes.

See HARDENING.md for supported verification scopes and migration boundaries. Registry publication and service deployment are reported by their workflows; a source merge alone is not a published package.

Adds independent Go RFC 8785 / Ed25519 / actor-profile / chain / acceptance verification; shared replay-cache protocol with Python and TypeScript. Go syntax-only checks are now an explicit `syntax` command. The Python wheel now installs the real validator and `jep-validate` entry point.
