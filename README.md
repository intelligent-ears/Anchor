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
- ✅ `anchor rotate-identity`, and the resulting "identity changed, but an
  attested rotation bridges it → OK" path, have been live-tested end to
  end against the real, public Sigstore/Rekor infrastructure (see
  [Trying identity rotation](#trying-identity-rotation)). `anchor verify`
  printed `OK: schema matches latest attested revision.` with an explicit
  `Publisher identity rotated: <old> -> <new> (attested rotation, Rekor
  index <n>)` line, rather than flagging the identity change as
  suspicious. This was the last unverified piece of Anchor — every
  documented code path has now been exercised live.
- ✅ Strict-linear `previousSchemaHash` enforcement: unit-tested (fork,
  gap, ordering, duplicates, rollback), and run live against this
  project's real `send_email_rotation_test` history, where it passes the
  genuine two-revision chain. The `FORKED` verdict itself hasn't been
  produced from real signed forks (that needs new, permanent Rekor
  entries).
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

*(Per [Status](#status): live-tested against the real Sigstore/Rekor
infrastructure. If you run this, two more real, permanent Rekor entries
get created — the rotation attestation and the re-signed schema.)*

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
```

> [!NOTE]
> `anchor sign` always fast-forwards *its own* `--state-dir`'s local
> known-good cache to whatever it just signed (that's how a publisher's
> own client stays in sync with its own latest revision). So running
> `verify --state-dir "$STATE"` immediately after the commands above,
> against that *same* `$STATE`, will just print the plain "OK: schema
> matches latest attested revision." — the known-good identity was
> already fast-forwarded to the new one by the second `sign` call, so
> there's no identity mismatch left for `verify` to reconcile.
>
> To actually see the rotation-acceptance branch fire, simulate a
> *second* client — e.g. an MCP client that trusted the tool at v1.0.0
> under the old identity and hasn't seen anything since — by pointing
> `verify` at a different `--state-dir` whose `state.json` still has
> `publisherIdentity` set to `old@example.com` (copy `$STATE/log-index.json`
> into it unchanged, so it still has pointers to the real Rekor entries):
>
> ```sh
> VERIFIER=$(mktemp -d)/.anchor
> mkdir -p "$VERIFIER"
> cp "$STATE/log-index.json" "$VERIFIER/log-index.json"
> cat > "$VERIFIER/state.json" <<EOF
> {"send_email": {"toolId": "send_email", "schemaHash": "<v1.0.0's sha256:... from the first sign's output>", "publisherIdentity": "old@example.com", "schemaVersion": "1.0.0", "updatedAt": "<its timestamp>"}}
> EOF
>
> $BIN verify --tool-id send_email --state-dir "$VERIFIER" "$SCHEMA"
> # -> OK, and mentions the attested identity rotation
> ```
>
> Every record `verify` uses here — the schema-manifest and the
> identity-rotation attestation — is still re-verified cryptographically
> and re-confirmed live on the public Rekor log; only the local
> "which revision did I previously trust" pointer is hand-constructed,
> exactly modeling what a second client's own `state.json` would contain.

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
- **Fixed:** `verify` now enforces
  `previousSchemaHash` as a strict linear history. If two different
  revisions claim the same predecessor, or a revision names a predecessor
  that isn't in the retrievable history, it prints `FORKED: divergent
  schema history detected` and exits non-zero. Still open: a fork is only
  visible if both branches are in the client's local index ; and the check re-verifies
  every cached revision with cosign, which is slow for long histories.
- **Still open, blocked by Rekor:** `anchor verify --bootstrap-from-identity
  <publisher>` searches Rekor by signer identity, but live testing showed
  public Rekor does not return the payload of DSSE entries (only a
  payload hash), so Anchor's predicate — `toolId`, `previousSchemaHash` —
  can't be read back from Rekor. The flag currently fails with an
  explanatory error instead of reconstructing history. Rekor *can* look
  up entries by schema hash (the subject digest is indexed) and by signer
  identity, so it can confirm "this hash was attested by this identity",
  but not chain or filter by tool. Closing this needs the signer's bundles
  distributed out-of-band (e.g. published beside the schema).
- No security review has been done. Anchor's own predicate types
  (`https://anchor.dev/schema-manifest/v1`,
  `https://anchor.dev/identity-rotation/v1`) are project-local
  conventions, not registered or reviewed by anyone outside this repo.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
