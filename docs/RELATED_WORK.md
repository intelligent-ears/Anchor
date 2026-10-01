# Related work: Anchor vs. ETDI, and OpenSSF Model Signing

ETDI (Enhanced Tool Definition Interface) — another proposal in the MCP
ecosystem for addressing rug-pull-style tool tampering — takes a
**point-to-point signature verification** approach: a
tool definition is signed, and a client verifies that signature directly
against the signer's key or credential at the moment it checks. If the
signature is valid, the tool is trusted.

Anchor's core difference is the addition of a **public, append-only
transparency log** (Rekor) as a required part of the trust chain, rather
than signature verification alone:

- **Point-to-point verification proves "this signature is valid for this
  content," but not "this is the only thing this identity has ever
  signed" or "when this was signed."** A valid key holder — including one
  whose key has been compromised, or one whose environment has been
  compromised — can produce a second, differently-signed version of a
  tool and there's no external record showing that happened, when it
  happened, or that an earlier version ever existed. Nothing outside the
  signer and the verifying client observes the act of signing.

- **A transparency log makes that act of signing itself an observable,
  permanent, independently-auditable event.** Every schema revision
  Anchor attests to is a public Rekor entry, with a timestamp and an
  identity, that anyone — not just the client performing verification —
  can go look at. This is what makes **silent forking** detectable:
  where "silent forking" specifically means an attacker signs a
  different version of a tool with a validly-obtained credential, but
  that alternate version and its signing were never made publicly
  visible. Point-to-point verification alone cannot distinguish that
  from a legitimate update, because both produce "a valid signature over
  new content." Anchor can, in principle, distinguish them, because the
  question changes from "is this signed?" to "is this signed *and on the
  public record*?" — and a client (or a third-party auditor) can compare
  what's on the public log against what any given client was actually
  shown.

- This is also what lets Anchor's identity-rotation handling (see
  `docs/DESIGN.md`) work the way it does: the rotation itself is a public,
  attested event, not just a fact a client is asked to trust locally.

**This is a complement to ETDI's approach, not a replacement for it.**
Signature verification is still the mechanism that establishes *who*
signed something and that the content hasn't been altered in transit —
Anchor doesn't reimplement that, it shells out to Sigstore/`cosign` for
exactly that cryptography (see `docs/ARCHITECTURE.md`). What Anchor adds
is the requirement that the signing act itself be logged somewhere public
and append-only, so that trust doesn't rest solely on "the client I
happened to be talking to said this signature checked out" — it can be
independently corroborated against a log nobody involved in the
transaction controls. A system could reasonably combine both: ETDI-style
point-to-point verification as the fast path, backed by a transparency
log (Anchor's approach, or a similar one) as the audit trail that makes
silent forking detectable after the fact.

---

# OpenSSF Model Signing (OMS)

OpenSSF's Model Signing spec
([github.com/ossf/model-signing-spec](https://github.com/ossf/model-signing-spec))
addresses provenance for AI artifacts from a different angle than ETDI.
OMS takes a **manifest of related files** — model weights, config,
tokenizer, dataset — and wraps it as an **in-toto Statement**, which is
then signed and stored in the **Sigstore Bundle Format**. It also allows
optional "Embedded Metadata" predicates for carrying additional claims
alongside the manifest.

Anchor independently arrived at the same underlying mechanism: a
Sigstore Bundle Format wrapping an in-toto Statement. That convergence is
useful validation. It suggests this is becoming the standard community
pattern for AI-supply-chain provenance, rather than a one-off design
choice specific to Anchor.

The main difference is the shape of the subject being attested:

- **OMS is built for multi-file bundles.** A model is a set of files that
  must be treated as one unit, so the manifest and its predicate type
  exist to bind them together.
- **Anchor's subject is a single tool schema file.** That is a simpler,
  single-artifact case. Anchor therefore does not adopt OMS's predicate
  type directly: forcing a manifest-of-files shape onto a single schema
  attestation would add complexity that doesn't map to what is actually
  being attested.

**As with ETDI, this is complementary precedent, not a competing or
redundant effort.** OMS and Anchor sit on the same Sigstore/in-toto
foundation and differ only in what they attest to — a multi-file model
bundle versus a single MCP tool schema — so tooling and conventions
developed around one are likely to carry over to the other.
