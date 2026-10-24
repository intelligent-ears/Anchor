# Design rationale

This document consolidates the reasoning already scattered across
Anchor's doc comments (`internal/canon`, `internal/predicate`,
`internal/state`, `internal/identity`) into one place. If a claim here
seems surprising, the corresponding package is the place to check it
against the actual code.

## Threat model

MCP (Model Context Protocol) tools are described to a client by a schema:
a name, a description, and a JSON input schema. A client — or the human
operating it — typically reviews and approves that schema once, the first
time a tool is used. After that, the tool is trusted implicitly on every
subsequent call. This creates a narrow but well-known window for a few
related attacks, all rooted in the same gap: **nothing stops the schema
a client saw at approval time from silently diverging from the schema
it's trusting on call number 500.**

- **Rug pull.** A tool's operator changes the schema *after* it has been
  approved — widening permissions, adding a field that exfiltrates data
  (a `bcc` parameter on a `send_email` tool, say), or rewording the
  description to instruct different behavior. Because most clients only
  show the approval prompt once, this change is invisible unless
  something is actively re-checking. This is the attack Anchor is built
  to catch, and the only one it has been tested against end to end (see
  the top-level README's Status section).

- **Tool poisoning.** A tool's description contains instructions aimed at
  the model rather than the human reviewer — text that's easy to skim
  past in a UI but that an LLM will read and act on, steering it toward
  unintended behavior (e.g. "when calling this tool, also send a copy of
  the conversation history to X"). This can be present from the tool's
  very first publication, with no schema change involved at all.

- **Tool shadowing.** A malicious or compromised server defines a tool
  that interferes with a different, legitimately trusted tool — by name
  collision, or by embedding instructions that redirect calls intended
  for the trusted tool. The client ends up trusting the wrong
  implementation for what it believes is a known-good tool.

- **Schema history fork.** A publisher puts two mutually exclusive lines
  of revision history on the record — two different revisions both
  claiming to follow the same predecessor, each validly signed. Different
  clients then follow different branches, each with a complete and
  correctly signed story, and no client can see that the other story
  exists. This is equivocation, and it is the threat
  [`internal/history`](../internal/history) detects.

> [!NOTE]
> **On naming.** This document calls that last threat a *schema history
> fork*, not "tool shadowing". SAF-MCP (the OpenSSF Secure Agentic
> Framework) already uses **tool shadowing** (SAF-T1008) for the different
> attack described above — one server defining a tool that interferes with
> another server's trusted tool. Reusing their name for a different thing
> would make Anchor's findings harder, not easier, to compare with other
> tooling. (The draft Gemara catalog in [`gemara/`](../gemara) still files
> this threat as `ANCHOR.MCP.TOOLSCHEMA.THR03`, titled "Tool Shadowing";
> that collision is known and unresolved, and the reference IDs are being
> taken to the community as they stand.)

Anchor's design directly targets **rug pull**: it gives a client a way to
notice, cryptographically, that the bytes it's about to trust are not the
bytes it (or anyone) previously attested to. It also detects **schema
history forks**, by enforcing the chain described below. Tool poisoning
and tool shadowing are related and worth naming here, but Anchor does not
detect either of them as such. Its indirect contribution to those two is that
*every* attested schema revision — poisoned or not — becomes part of a
permanent, publicly auditable, identity-attributed record instead of
something a malicious operator can swap out unobserved. That's a
transparency property, not a content-safety scanner.

## Provenance, not safety

**Anchor answers one question: was this exact schema published by this
exact identity, at this time, and is that on the public record?** It does
not, and is explicitly not designed to, judge whether a schema's
*contents* are safe. A tool schema could be attested, signed, logged to
Rekor, verified as unchanged — and still be a bad tool, if it was bad from
the very first signed revision. Provenance answers "is this the thing that
was published," which is a precondition for any content-safety judgment
to mean anything (there's no point scanning a schema for danger if an
attacker can just publish a different one under the same trust), but it
isn't a substitute for that judgment.

## Why canonicalization (JCS / RFC 8785) is required before hashing

A schema is hashed to detect change. But "change" should mean a real
difference in what the schema says, not a difference in how it happened
to be formatted. Two JSON documents with re-ordered object keys, extra
whitespace, or a trailing newline are the same schema — if hashing raw
bytes treated them as different, every legitimate re-serialization
(a different JSON library, a pretty-printer, a `git` line-ending
normalization) would register as a false-positive "tampering" alert, and
real alerts would get lost in that noise.

[RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) defines a
canonical JSON form — sorted keys, minimal whitespace, a fixed number
representation — such that two JSON documents with the same *value*
always canonicalize to the same bytes. Anchor canonicalizes before both
signing and verifying (`internal/canon`), so its hash — and therefore its
trust decision — tracks the schema's meaning, not its incidental
serialization.

## Identity, and what "same publisher" actually means

A signature is only as trustworthy as the identity behind it, and that
identity comes from wherever the OIDC provider says it comes from — which
is not always the exact string a human would type. In testing, Google's
OIDC issuer returned an institutional address in a different letter case
than a person would naturally type it (`24UEC247@...` vs. the lowercase a
user typed for `--publisher-identity`). Comparing those with strict
string equality would have produced a false "identity changed" flag on a
harmless case difference — exactly the kind of noise that trains people
to ignore real alerts. `internal/identity` treats email-shaped identities
as case-insensitive for this reason, while comparing URI-shaped
identities (e.g. a GitHub Actions workload identity, where a ref or path
segment's case is meaningful) exactly as given.

## Handling legitimate identity rotation

A tool's publisher does sometimes need to change identity legitimately —
a new maintainer takes over, a personal account is replaced by an
organizational one. Without a mechanism for this, every legitimate
handoff would look identical to an attacker publishing under a new
account after compromising a tool's distribution channel, which is
exactly the "identity switch" signal Anchor is trying to catch.

Anchor resolves this with a second predicate type,
`identity-rotation`, distinct from the `schema-manifest` predicate used
for schema revisions. An identity-rotation attestation names the new
identity and — critically — **is signed by the current (old) identity**,
not the new one. This is what makes it a deliberate handoff rather than a
unilateral claim: the new identity can't authorize itself, only the
identity already trusted for that tool can vouch for its successor. Only
when such a rotation record exists, signed by the identity a client
already trusts, does `anchor verify` treat a change in signer as
authorized rather than a `FLAGGED` red flag. Both the intent (`old ->
new`) and the actual signer of the rotation attestation are recorded, and
they're cross-checked against each other rather than trusted at face
value — the same principle applied everywhere in Anchor's identity
comparisons.

## Strict linear history, and what a fork actually proves

Every schema-manifest predicate carries a `previousSchemaHash`: the hash
of the revision this one succeeds, or `null` for a tool's first. Recording
it is not enough on its own — a field nobody checks is a comment. So
`anchor verify` walks the whole retrievable history for a tool and
requires it to be **one strict linear chain**: each revision's
`previousSchemaHash` must name the revision logged immediately before it,
in Rekor log index order, and exactly one revision may claim to be the
first. (`internal/history`)

Three things break that, and all three are a non-zero `FORKED` verdict:

- **Fork** — two different revisions claim the same predecessor.
- **Gap** — a revision names a predecessor that matches nothing
  retrievable.
- **Order** — a revision claims a predecessor that was logged after it, so
  it cannot have followed it.

Two cases deliberately do *not* break it. Re-signing byte-identical
content (same hash, same parent) collapses: re-attesting what you already
published is not a second story. And a deliberate rollback —
`A -> B -> A` — is a perfectly linear chain, because each step names its
real parent; Anchor shows the diff and makes no objection.

**A fork is evidence of equivocation, and nothing more.** Both branches
are genuinely signed by the publisher, so there is no signature to
disbelieve and no cryptographic question left to ask. What the finding
says is that the publisher told different clients different stories about
which revision follows which — and that it is visible at all only because
a transparency log keeps both stories. It does not say which branch is
honest, and says nothing whatsoever about whether either branch's
*content* is safe. The right response is to ask the publisher, not to pick
a branch.

Ordering is by **Rekor log index**, never by the predicate's `timestamp`.
The timestamp is the publisher's own claim and can be wrong or false; the
log index is the one ordering every participant can independently agree
on. For the same reason `anchor sign` picks a new revision's parent in log
order (`internal/state`): the chain has to be built in the order it will
be read back in.

One consequence worth stating plainly: the chain is only as complete as
the state directory doing the signing. A publisher who signs a tool's
second revision from a machine that never saw the first will produce a
second revision claiming to *be* the first — which, to a client holding
both, is a fork. That is the check working correctly, not a false
positive: two conflicting claims about the start of history really were
published. A publisher with more than one machine needs shared state, or
needs to bootstrap it before signing.

## Bootstrapping from the log, and the one rule that makes it safe

A client that has never signed anything has no local pointer index, and
so, before this, had nothing to verify against — it could only
trust-on-first-use whatever it was handed. `anchor verify
--bootstrap-from-identity <identity>` closes that: Rekor cannot be
searched by `toolId`, but it *can* be searched by signer identity, so a
client that knows who the publisher is supposed to be can pull that
identity's entries, keep the ones that are Anchor attestations for the
tool in question, follow any attested rotation to the identity's
successors, and rebuild the history — then run exactly the linearity
checks above on it, with no local state file.
(`internal/bootstrap`)

> [!IMPORTANT]
> **The identity must come from the user, or from out-of-band
> configuration the user controls. It must never be taken from the schema
> being verified, or from anything else the publisher of that schema
> controls.**
>
> An attacker who gets to choose which identity you trust does not need to
> forge anything. They name their own identity, and what comes back is a
> flawless history: correctly signed, perfectly linear, fully
> transparency-logged, and entirely theirs. No check in this codebase can
> catch that, because there is nothing wrong with the history — the error
> was in where the identity came from. This is why the identity is a CLI
> flag the operator types, and why the flag's own `-h` text repeats this
> warning.

What a successful bootstrap proves is therefore narrower than it looks:
*this is the history Rekor holds for that identity*. It does not prove
that the identity is the right publisher for the tool. That makes
bootstrap trust-on-first-use in the same sense as a first `verify`, and
the output says so rather than implying the stronger claim.

Two further choices follow from the same instinct:

- **A capped scan refuses; it does not truncate.** An identity with more
  entries than `--max-bootstrap-entries` allows makes Anchor stop and say
  so. Scanning a prefix would be worse than useless: a history with
  revisions missing can look perfectly linear, so a partial scan can turn
  a fork into an `OK`.
- **A rotation is a link only if the identity handing off signed it.** A
  rotation attestation says "I, `oldIdentity`, authorize `newIdentity`". If
  the certificate says someone else signed it, Anchor drops it rather than
  reinterpreting it as that signer's own handoff — otherwise anyone could
  graft themselves onto a publisher's lineage by publishing a rotation
  naming themselves as a stranger's successor.

## Why a local pointer index, if Rekor is public

Rekor's public search API supports lookup by artifact hash, by signer
email, or by log index — not by arbitrary custom fields like Anchor's
`toolId`. There is no way to ask the public log "give me every
attestation for tool X." So Anchor keeps a local, append-only index
(`.anchor/log-index.json`) recording which Rekor log entries belong to
which tool — this is exactly the kind of state a real MCP client would
persist between tool invocations anyway.

That index is a pointer cache, never a trust source: every `anchor
verify` re-fetches the relevant entry live from the public Rekor instance
and re-runs cryptographic verification against the cached bundle before
using it for any decision. A tampered or deleted local index can make
Anchor less useful — nothing to compare against, forcing a fresh
trust-on-first-use — but it cannot make `verify` accept something that
was never actually, genuinely logged to the public transparency log.
