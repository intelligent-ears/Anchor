package main

import (
	"strings"
	"testing"

	"anchor/internal/history"
)

func TestForkedReport(t *testing.T) {
	prev := "sha256:aaa"
	atts := []history.Attestation{
		{Kind: history.KindSchemaManifest, RekorLogIndex: 1, SchemaHash: "sha256:bbb", PreviousSchemaHash: &prev, Signer: "p@example.com"},
		{Kind: history.KindSchemaManifest, RekorLogIndex: 2, SchemaHash: "sha256:ccc", PreviousSchemaHash: &prev, Signer: "p@example.com"},
		{Kind: history.KindSchemaManifest, RekorLogIndex: 0, SchemaHash: "sha256:aaa", Signer: "p@example.com"},
	}
	problems := history.CheckLinear(atts)
	out := forkedReport("fresh_tool", problems)
	for _, want := range []string{"FORKED: divergent schema history detected", "fresh_tool", "sha256:bbb", "sha256:ccc"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}
