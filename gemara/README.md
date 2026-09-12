# Gemara MCP Threat Catalog (Draft)

**Status: draft, pending Gemara community review — not merged or adopted anywhere.**

This directory contains a [Gemara](https://gemara.openssf.org) Layer 2 `ThreatCatalog`
(and its supporting `CapabilityCatalog`) documenting three security threats affecting
MCP (Model Context Protocol) tool schemas. It was authored per Hannah Braswell's
guidance (Gemara maintainer) as a candidate artifact to bring to a Gemara community
meeting for discussion — it has not been reviewed or accepted by the Gemara project.

## Files

- `mcp-threat-catalog.yaml` — the `ThreatCatalog` artifact (`#ThreatCatalog`), covering
  three threats to MCP tool schema trust: **Rug Pull**, **Tool Poisoning**, and
  **Tool Shadowing**.
- `mcp-tool-capabilities.yaml` — a companion `CapabilityCatalog` (`#CapabilityCatalog`)
  defining the single capability ("Tool Schema Publication & Discovery") that all three
  threats target, referenced from the threat catalog via `capabilities` mappings.

Both artifacts were built with the `gemara-artifact-authoring` skill (from the
`gemara-ai` Claude Code plugin) and validated against the Gemara CUE schema via the
`validate_gemara_artifact` MCP tool. They pass validation as of this writing.

To verify independently:

```bash
go install cuelang.org/go/cmd/cue@latest
cue vet -c -d '#ThreatCatalog' github.com/gemaraproj/gemara@v1 mcp-threat-catalog.yaml
cue vet -c -d '#CapabilityCatalog' github.com/gemaraproj/gemara@v1 mcp-tool-capabilities.yaml
```

## Why capability framing is "schema distribution," not "tool invocation"

All three threats concern the trustworthiness of a tool's *schema* over time — not the
act of invoking a tool. The underlying capability at risk is the mechanism by which an
MCP client discovers, approves, and continues to trust a tool's published schema across
its lifecycle. That's what `ANCHOR.MCP.TOOLSCHEMA.CAP01` (in `mcp-tool-capabilities.yaml`)
represents.

## Open question for the community meeting: inline control mapping

Hannah's guidance asked whether Anchor's mapped control — schema-signing plus
Rekor-based verification, which addresses all three threats below — could be
referenced inline within this ThreatCatalog, the way `controlcatalog.cue` associates
threats with controls.

Having read the live Gemara CUE schema (via `gemara-mcp`'s `gemara://schema/definitions`
resource) rather than guessing: **that association is structurally one-directional and
lives on the control side, not the threat side.**

- `#Threat` (used inside `#ThreatCatalog`) only carries `capabilities`, `vectors`, and
  `actors` mappings — there is no `controls` field on a threat.
- `#Control` (used inside `#ControlCatalog`) carries an optional `threats` field
  (`[#MultiEntryMapping, ...]`) that maps a control back to one or more Layer 2 threats.

In other words, a `ThreatCatalog` cannot inline-reference a control; only a
`ControlCatalog` entry can inline-reference threats. Making that mapping concrete would
require authoring an actual `ControlCatalog` entry for Anchor's schema-signing +
Rekor-based verification control, with a `threats` mapping (via `mapping-references`)
back to `ANCHOR.MCP.TOOLSCHEMA.THR01`–`THR03` in this catalog.

This is left undone deliberately — building that ControlCatalog entry is a separate
authoring exercise, and this catalog should not gain speculative content beyond the
three agreed-upon threats. Raising it here as the specific open question to bring to
the community meeting: should the control catalog entry be authored as a follow-up in
this repo, or does it belong upstream/elsewhere?

## Threats covered

1. **Rug Pull** (`ANCHOR.MCP.TOOLSCHEMA.THR01`) — a tool's schema or behavior silently
   changes after a client has already approved it, without any re-disclosure.
2. **Tool Poisoning** (`ANCHOR.MCP.TOOLSCHEMA.THR02`) — a malicious or compromised actor
   publishes a schema change that impersonates a legitimate update.
3. **Tool Shadowing** (`ANCHOR.MCP.TOOLSCHEMA.THR03`) — two divergent versions of a
   tool's schema circulate simultaneously with no way to determine which is
   authoritative.

See `mcp-threat-catalog.yaml` for full descriptions and exploitability rationale.
