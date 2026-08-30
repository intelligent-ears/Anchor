# Anchor

**This is a prototype / proof of concept, not production software.** It
has not been security-reviewed, its predicate types are not standardized
anywhere, and it should not be relied on to gate real tool approvals yet.
See [Known limitations](#known-limitations-its-a-prototype) below.

Anchor is a CLI for detecting "rug pull" attacks on MCP (Model Context
Protocol) tools — the scenario where a client approves a tool's schema
once, and the tool's operator later silently changes that schema
(widening permissions, adding an exfiltration field, rewording the
description to something dangerous) without the client noticing.

**Anchor proves provenance, not safety.** It answers one narrow question:
*"was this exact schema published by this exact identity, at this time,
and is that on the public record?"* It does not — and is not meant to —
judge whether a schema's contents are safe. That's a separate problem.

> [!WARNING]
> **`anchor sign`, `anchor rotate-identity`, and `scripts/e2e_test.sh` all
> submit a real attestation to the live, public Rekor transparency log**
> (`rekor.sigstore.dev`), under whatever OIDC identity you authenticate as
> when prompted. This is not a sandbox or dry run — it's the same
> production infrastructure `cosign` and every other Sigstore-based tool
> uses. Transparency logs are append-only by design: **once submitted, an
> entry is permanent and public, and cannot be edited or deleted.** Know
> which account you're logging in with before you run these commands.
> `anchor verify` is read-only and safe to run freely.

## How it works

1. **Canonicalize.** Before hashing, a schema is transformed into its
   [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
   canonical form: sorted object keys, minimal whitespace, no cosmetic
   noise. This means re-ordering keys or adding a trailing newline never
   registers as a "change" — only a real difference in the JSON value
   does. (`internal/canon`)

2. **Attest.** Anchor builds a standard
   [in-toto v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
   — `subject` = the tool's canonical schema hash, `predicateType` = one of
   Anchor's two custom predicate types, `predicate` = the provenance
   details (publisher identity, schema version, previous hash, timestamp).
   (`internal/predicate`)

3. **Sign, keylessly.** That Statement is handed to `cosign` for
   [Sigstore's keyless flow](https://docs.sigstore.dev/cosign/signing/overview/):
   you authenticate with an OIDC identity (Google/GitHub/Microsoft/etc.),
   Fulcio issues a short-lived certificate binding that identity to a
   throwaway key, and the signed attestation is submitted to **Rekor**,
   Sigstore's public append-only transparency log. Anchor doesn't
   reimplement any of this cryptography — it shells out to `cosign` and
   focuses its own Go code on statement construction and trust logic.
   (`internal/signer`)

4. **Verify.** Given a live schema file, Anchor canonicalizes and hashes
   it, then checks that hash against what's on record for that tool:
   - hash unattested anywhere → **BLOCKED**, likely rug pull.
   - hash attested, but by a *different* identity than last approved, and
     no rotation record bridges them → **FLAGGED**, likely rug pull via
     identity switch.
   - hash attested by the *same* identity as before → **OK**, and any
     content diff is shown for human review (attested ≠ silently
     rubber-stamped).

5. **Handle legitimate identity rotation.** A publisher can hand off to a
   new identity deliberately, by having their *current* identity sign a
   separate `identity-rotation` attestation naming the new one. Only then
   does `verify` treat an identity change as authorized instead of
   suspicious.

## Status

Live-tested end to end against the real, public Sigstore/Rekor
infrastructure (not mocked):

- ✅ `anchor sign` — produces a real Fulcio-issued certificate and a real
  Rekor transparency log entry.
- ✅ `anchor verify` on an unmodified, attested schema — prints `OK:
  schema matches latest attested revision.`
- ✅ `anchor verify` on a silently mutated, unsigned schema — prints
  `BLOCKED: unattested schema change detected` and exits non-zero. This
  is the core rug-pull-detection claim, and it's been confirmed working.
- ⚠️ `anchor rotate-identity` and the resulting "identity changed, but an
  attested rotation bridges it → OK" path are implemented and documented
  (see [Trying identity rotation](#trying-identity-rotation)) but have
  **not** been exercised against live infrastructure yet. Treat that path
  as unverified until someone runs it end to end.
- ⚠️ The "FLAGGED: publisher identity changed without an attested
  rotation" path (identity switch with *no* rotation record) is exercised
  by construction whenever the rotation path above hasn't been run first,
  but hasn't been deliberately live-tested as its own scenario either.

## Why a local `.anchor/` state directory, if Rekor is public?

Rekor's public search API supports lookup by artifact hash, by signer
email, or by log index — **not** by arbitrary custom fields like Anchor's
`toolId`. There's no way to ask the public log "give me every attestation
for tool X." So, like a real MCP client would, Anchor keeps a local,
append-only pointer index (`.anchor/log-index.json`) recording which Rekor
log entries belong to which tool, plus a trust-on-first-use cache of the
last known-good revision per tool (`.anchor/state.json`).

Critically, **the local files are never trusted blindly.** Every `verify`
re-fetches the relevant entry live from the public Rekor instance and
re-runs `cosign verify-blob-attestation` against the cached bundle before
using it for any trust decision — the local index is only ever a set of
pointers into a log that remains the actual source of truth. A tampered or
deleted `.anchor/` directory can make Anchor *less useful* (nothing to
compare against, or a forced fresh trust-on-first-use), but it can't
convince `verify` to accept something that was never actually
transparency-logged.

## Prerequisites

- **Go** ≥ 1.23
- **[cosign](https://docs.sigstore.dev/cosign/system_config/installation/)**
  on your `PATH` (Anchor shells out to it for all signing/verification
  cryptography)
- A browser (or a second device) to complete Sigstore's OIDC login when
  `anchor sign` / `anchor rotate-identity` prompt for it

Every `sign` and `rotate-identity` call submits a real attestation to the
**public production Rekor log** (rekor.sigstore.dev), tied to whatever
OIDC identity you authenticate as. That's permanent — transparency logs
don't support deletion — so know which account you're signing in with
before you run these commands.

## Commands

### `anchor sign --tool-id <id> --publisher-identity <id> --schema-version <v> <schema-file>`

(flags must come before the trailing `<schema-file>` argument — that's a
property of Go's stdlib `flag` package, not a design choice)

Canonicalizes and hashes the schema, builds the in-toto Statement, and
signs it via Sigstore's keyless flow (this is where you'll be prompted to
authenticate). `--publisher-identity` is the identity you're about to log
in as — Anchor cross-checks it against what the issued certificate
actually says, so a typo or logging in as the wrong account is caught
rather than silently trusted. On success it prints the Rekor UUID and log
index, and updates local state.

### `anchor verify --tool-id <id> <schema-file>`

Canonicalizes and hashes the live schema, then applies the logic described
above. Exits non-zero on `BLOCKED` or `FLAGGED` — wire this into an MCP
client's tool-approval path and an unattested or identity-switched change
fails closed instead of being silently accepted.

### `anchor rotate-identity --tool-id <id> --new-identity <id>`

Signs (with the tool's *current* known-good identity — you'll be prompted
to authenticate as that account specifically) an attestation authorizing
`--new-identity` to publish schema revisions for this tool going forward.
A subsequent `verify` that sees the schema now signed by the new identity
will treat that as an attested rotation rather than a red flag.

All three commands accept `--state-dir` (default `.anchor`) if you want to
manage more than one client's state, or point at a specific project.

## Running the end-to-end demo

`scripts/e2e_test.sh` signs the sample `send_email` tool schema
(`sample_tool_schema.json`), verifies it, then simulates a rug pull by
mutating the schema *without* signing the change, and verifies again to
show it gets blocked.

```sh
./scripts/e2e_test.sh you@example.com
```

Replace `you@example.com` with the identity you'll authenticate as during
the OIDC prompts (any Sigstore-supported OIDC provider — Google, GitHub,
Microsoft — works; it doesn't need to match your shell's notion of "you",
it just needs to match whichever account you log in with).

What you'll see:

1. **Sign** — a browser/device-code OIDC login prompt, then a Rekor UUID
   and log index printed on success.
2. **Verify (unmodified)** — `OK: schema matches latest attested
   revision.`
3. **Mutate** — the script silently adds a `bcc` field and tweaks the
   description, without calling `anchor sign`. This is the rug pull.
4. **Verify (mutated)** — `BLOCKED: unattested schema change detected`,
   and the script exits with an explicit "rug-pull correctly detected"
   message.

The whole thing runs in a temp directory (cleaned up on exit) with its own
throwaway `--state-dir`, so it won't touch anything in the repo.

### Trying identity rotation

*(Per [Status](#status): implemented and documented, not yet exercised
against live infrastructure — this walkthrough is untested as written.
If you run it, two more real Rekor entries get created.)*

To see the third path — an identity change that Anchor accepts because
it's attested — sign the same tool again with a *second* OIDC identity
after running `rotate-identity`:

```sh
BIN=$(mktemp -d)/anchor
go build -o "$BIN" ./cmd/anchor
STATE=$(mktemp -d)/.anchor
SCHEMA=$(mktemp -d)/send_email.json
cp sample_tool_schema.json "$SCHEMA"

$BIN sign --tool-id send_email \
  --publisher-identity old@example.com --schema-version 1.0.0 --state-dir "$STATE" "$SCHEMA"

# authenticate as old@example.com when prompted here:
$BIN rotate-identity --tool-id send_email \
  --new-identity new@example.com --state-dir "$STATE"

# authenticate as new@example.com when prompted here:
$BIN sign --tool-id send_email \
  --publisher-identity new@example.com --schema-version 1.0.1 --state-dir "$STATE" "$SCHEMA"

$BIN verify --tool-id send_email --state-dir "$STATE" "$SCHEMA"
# -> OK, and mentions the attested identity rotation
```

If you skip the `rotate-identity` step and just re-sign with a different
identity, the final `verify` will print `FLAGGED: publisher identity
changed without an attested rotation` and exit non-zero instead.

## Project layout

```
cmd/anchor/            CLI entry point and per-command flag handling
internal/canon/        RFC 8785 (JCS) canonicalization + SHA-256 hashing
internal/predicate/    in-toto v1 Statement + Anchor's two predicate types
internal/signer/       shells out to cosign; parses the returned bundle
internal/rekorapi/     read-only lookups against the public Rekor REST API
internal/state/        local .anchor/state.json + log-index.json
internal/diff/         human-readable diff between two schema revisions
internal/identity/     identity-string comparison (case-insensitive for email)
scripts/e2e_test.sh    the rug-pull demo described above
sample_tool_schema.json  the send_email fixture used by the demo
docs/                  design rationale, architecture walkthrough, related work
```

See [`docs/DESIGN.md`](docs/DESIGN.md) for the threat model and design
rationale, [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how a
`sign`/`verify` call flows through the packages above, and
[`docs/RELATED_WORK.md`](docs/RELATED_WORK.md) for how this compares to
ETDI.

## Known limitations (it's a prototype)

- No support for key-based (non-keyless) signing, custom Rekor/Fulcio
  instances, or offline/air-gapped verification.
- The local `log-index.json` grows unbounded; a real client would want
  pruning/pagination for tools with long histories.
- `previousSchemaHash` chaining is recorded but not currently enforced as
  a strict linear history during `verify` — a gap worth closing before
  this goes beyond prototype stage.
- `rotate-identity` is implemented and documented but not yet live-tested
  (see [Status](#status)).
- No security review has been done. Anchor's own predicate types
  (`https://anchor.dev/schema-manifest/v1`,
  `https://anchor.dev/identity-rotation/v1`) are project-local
  conventions, not registered or reviewed by anyone outside this repo.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
