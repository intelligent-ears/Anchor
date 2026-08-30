# Architecture

## Packages

```
cmd/anchor/         CLI entry point and per-command flag handling
internal/canon/      RFC 8785 (JCS) canonicalization + SHA-256 hashing
internal/predicate/  in-toto v1 Statement construction, Anchor's two predicate types
internal/signer/     shells out to cosign; parses the returned Sigstore bundle
internal/rekorapi/   read-only lookups against the public Rekor REST API
internal/state/      local .anchor/state.json + log-index.json
internal/diff/       human-readable diff between two schema revisions
internal/identity/   identity-string comparison (case-insensitive for email)
```

Each package has one job, and the dependency direction is one-way:
`cmd/anchor` orchestrates all of them; none of the `internal/*` packages
import each other except `internal/state`, which imports
`internal/identity` for its rotation-bridge lookup. Nothing in
`internal/*` shells out to anything except `internal/signer`, which is
the only package that talks to `cosign`; nothing in `internal/*` talks to
the network except `internal/rekorapi`, which is the only package that
talks to Rekor directly. This is deliberate: it's what makes it possible
to state precisely (as `docs/DESIGN.md` does) which trust decisions are
made in Go and which are delegated to Sigstore's own tooling.

- **`internal/canon`** — turns raw schema JSON into RFC 8785 canonical
  bytes (via `github.com/gowebpki/jcs`) and hashes them. This is the only
  package that decides "what counts as the same schema."

- **`internal/predicate`** — defines the in-toto v1 `Statement` envelope
  and Anchor's two predicate payloads (`SchemaManifest`,
  `IdentityRotation`), and builds a `Statement` from a canonical hash plus
  provenance metadata. Produces JSON bytes; does no I/O and no signing.

- **`internal/signer`** — the only package that shells out to `cosign`.
  `AttestStatement` signs a `predicate.Statement` via
  `cosign attest-blob --statement ... --bundle ... --new-bundle-format`
  (Sigstore's keyless flow — OIDC login, Fulcio cert issuance, Rekor
  submission, all handled by `cosign` itself). `VerifyBundle` re-runs
  `cosign verify-blob-attestation` against a cached bundle. `ParseBundle`
  is pure Go (JSON + `crypto/x509`, no shelling out) that pulls the
  Rekor log index, the signer's identity, and the OIDC issuer out of a
  signed bundle for Anchor's own bookkeeping.

- **`internal/rekorapi`** — the only package that talks to Rekor
  directly, and only for read-only lookups by log index or UUID (the two
  keys the public Rekor search API actually supports — see
  `docs/DESIGN.md` for why that matters). Used both to confirm a
  freshly-signed entry is really public, and to re-confirm a cached
  entry is still there before trusting it.

- **`internal/state`** — the local `.anchor/state.json` (trust-on-first-use
  cache of each tool's last known-good hash/identity) and
  `.anchor/log-index.json` (append-only pointer index from toolId to
  Rekor entries, split into `schema-manifest` and `identity-rotation`
  records). Provides the lookup and rotation-bridge logic `verify` uses;
  holds no cryptographic trust of its own.

- **`internal/diff`** — flattens two JSON documents to dotted-path maps
  and diffs them, purely for human review output. Never influences the
  OK/BLOCKED/FLAGGED decision.

- **`internal/identity`** — one function, `Equal`, used everywhere two
  identity strings are compared (see `docs/DESIGN.md` for why this
  exists).

## `anchor sign` flow

```
schema-file.json
      │  os.ReadFile
      ▼
internal/canon.CanonicalizeAndHash
      │  canonical bytes, sha256 hash
      ▼
internal/state.Store.LatestSchemaManifest   (look up previousSchemaHash)
      ▼
internal/predicate.BuildSchemaManifestStatement
      │  in-toto v1 Statement JSON (subject = toolId+hash, predicate = provenance)
      ▼
internal/signer.AttestStatement
      │  shells to `cosign attest-blob --statement ... --bundle ...`
      │  (interactive OIDC login happens here; cosign talks to Fulcio + Rekor)
      ▼
internal/signer.ParseBundle
      │  logIndex, signer identity (from the Fulcio cert), OIDC issuer
      ▼
[cross-check: does the cert identity match --publisher-identity?]
      │  mismatch -> error, local state NOT updated (attestation is still public)
      ▼
internal/rekorapi.GetByLogIndex
      │  live confirmation + the canonical Rekor UUID
      ▼
internal/state.Store.AppendLog + KnownGood update, Save()
```

## `anchor verify` flow

```
live schema-file.json
      │  os.ReadFile
      ▼
internal/canon.CanonicalizeAndHash            → liveHash
      ▼
internal/state.Store.FindByHash(toolID, liveHash)
      │
      ├─ not found ───────────────────────────────► BLOCKED (unattested change)
      │
      ▼ found: `matched` record
internal/signer.VerifyBundle(matched.BundlePath, matched.CanonicalPath)
      │  re-verifies signature + cert chain against the exact canonical
      │  blob that was originally signed (not the live file's raw bytes —
      │  see docs/DESIGN.md on canonicalization)
      ▼
internal/rekorapi.GetByUUID(matched.RekorUUID)
      │  live re-confirmation the entry is still on the public log
      ▼
[no local KnownGood yet?] ─────────────────────────► OK (trust-on-first-use)
      │
      ▼ compare matched.PublisherIdentity to KnownGood.PublisherIdentity
        via internal/identity.Equal
      │
      ├─ same identity, same hash ─────────────────► OK (no change)
      ├─ same identity, different hash ────────────► OK (routine update)
      │                                               + internal/diff.Compute
      │                                                 against the previous
      │                                                 KnownGood revision
      │
      ▼ different identity
internal/state.Store.HasRotationBridge(toolID, old, new)
      │
      ├─ bridge found → re-verify the rotation record too ──► OK (rotated)
      └─ no bridge ──────────────────────────────────────────► FLAGGED
```

In every branch that ends in `OK`, `internal/state.Store` is updated to
the newly-confirmed hash/identity before `verify` returns — so the next
call has the right baseline. In `BLOCKED` and `FLAGGED`, it deliberately
is not.
