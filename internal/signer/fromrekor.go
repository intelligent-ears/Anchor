package signer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"

	"anchor/internal/rekorapi"
)

// BundleFromRekorEntry reassembles a Sigstore bundle (v0.3 JSON) from a
// "dsse" entry fetched off the public Rekor log, so that cosign can
// cryptographically verify an attestation this client never signed or
// cached: the signature, the Fulcio certificate chain, and the Rekor
// inclusion proof/SET.
//
// Nothing here is trusted on its own — the returned bundle is only a
// container for cosign to check. It also returns the decoded in-toto
// Statement, which the caller may only believe after cosign has verified
// the bundle (see VerifyBundleNoClaims).
//
// The entry must carry its attestation payload (Rekor stores it for
// in-toto/DSSE entries), be a keyless entry (certificate, not bare public
// key), and have a payload that matches the payloadHash Rekor logged.
func BundleFromRekorEntry(e rekorapi.Entry) (bundleJSON, statement []byte, err error) {
	bodyJSON, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("decode entry body: %w", err)
	}
	var body struct {
		Kind string `json:"kind"`
		Spec struct {
			PayloadHash struct {
				Value string `json:"value"`
			} `json:"payloadHash"`
			Signatures []struct {
				Signature string `json:"signature"`
				Verifier  string `json:"verifier"`
			} `json:"signatures"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(bodyJSON, &body); err != nil {
		return nil, nil, fmt.Errorf("parse entry body: %w", err)
	}
	if body.Kind != "dsse" {
		return nil, nil, fmt.Errorf("entry kind is %q, not dsse", body.Kind)
	}
	if len(body.Spec.Signatures) != 1 {
		return nil, nil, fmt.Errorf("expected exactly one DSSE signature, got %d", len(body.Spec.Signatures))
	}
	if e.Attestation == nil || e.Attestation.Data == "" {
		return nil, nil, fmt.Errorf("Rekor did not return the attestation payload for this entry")
	}
	if e.Verification == nil || e.Verification.InclusionProof == nil {
		return nil, nil, fmt.Errorf("Rekor did not return an inclusion proof for this entry")
	}

	statement, err = base64.StdEncoding.DecodeString(e.Attestation.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("decode attestation payload: %w", err)
	}
	sum := sha256.Sum256(statement)
	if hex.EncodeToString(sum[:]) != body.Spec.PayloadHash.Value {
		return nil, nil, fmt.Errorf("attestation payload does not match the payloadHash Rekor logged")
	}

	sig := body.Spec.Signatures[0]
	verifierPEM, err := base64.StdEncoding.DecodeString(sig.Verifier)
	if err != nil {
		return nil, nil, fmt.Errorf("decode verifier: %w", err)
	}
	block, _ := pem.Decode(verifierPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("entry was not signed with a certificate (not a keyless Sigstore entry)")
	}

	hexToB64 := func(h string) (string, error) {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}
	logID, err := hexToB64(e.LogID)
	if err != nil {
		return nil, nil, fmt.Errorf("decode logID: %w", err)
	}
	ip := e.Verification.InclusionProof
	rootHash, err := hexToB64(ip.RootHash)
	if err != nil {
		return nil, nil, fmt.Errorf("decode inclusion proof root hash: %w", err)
	}
	hashes := make([]string, 0, len(ip.Hashes))
	for _, h := range ip.Hashes {
		b, err := hexToB64(h)
		if err != nil {
			return nil, nil, fmt.Errorf("decode inclusion proof hash: %w", err)
		}
		hashes = append(hashes, b)
	}

	tlog := map[string]any{
		"logIndex":          strconv.FormatInt(e.LogIndex, 10),
		"logId":             map[string]string{"keyId": logID},
		"kindVersion":       map[string]string{"kind": "dsse", "version": "0.0.1"},
		"integratedTime":    strconv.FormatInt(e.IntegratedTime, 10),
		"canonicalizedBody": e.Body,
		"inclusionProof": map[string]any{
			"logIndex":   strconv.FormatInt(ip.LogIndex, 10),
			"rootHash":   rootHash,
			"treeSize":   strconv.FormatInt(ip.TreeSize, 10),
			"hashes":     hashes,
			"checkpoint": map[string]string{"envelope": ip.Checkpoint},
		},
	}
	if e.Verification.SignedEntryTimestamp != "" {
		tlog["inclusionPromise"] = map[string]string{"signedEntryTimestamp": e.Verification.SignedEntryTimestamp}
	}

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(block.Bytes)},
			"tlogEntries": []any{tlog},
		},
		"dsseEnvelope": map[string]any{
			"payload":     e.Attestation.Data,
			"payloadType": "application/vnd.in-toto+json",
			"signatures":  []map[string]string{{"sig": sig.Signature}},
		},
	}
	bundleJSON, err = json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return bundleJSON, statement, nil
}
