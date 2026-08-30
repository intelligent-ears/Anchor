// Package signer shells out to the `cosign` CLI to do the actual
// Sigstore keyless signing and verification (Fulcio cert issuance, Rekor
// submission, DSSE + cert-chain verification). Anchor does not reimplement
// any of that cryptography — Go code here is limited to invoking cosign,
// and to parsing the resulting Sigstore bundle JSON well enough to pull out
// the fields Anchor's own trust logic needs (log index, signer identity,
// OIDC issuer, the signed in-toto Statement).
package signer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// cosignPath locates the cosign binary. Anchor doesn't vendor or reimplement
// it — this is a thin wrapper, per the project's design goal of keeping the
// heavy cryptography in well-audited upstream tooling.
func cosignPath() (string, error) {
	p, err := exec.LookPath("cosign")
	if err != nil {
		return "", fmt.Errorf("cosign not found on PATH — install it from https://docs.sigstore.dev/cosign/system_config/installation/: %w", err)
	}
	return p, nil
}

// AttestStatement signs a pre-built in-toto Statement (see internal/predicate)
// using Sigstore's keyless flow and writes the resulting bundle (cert +
// signature + Rekor inclusion proof) to bundlePath. It shells out to:
//
//	cosign attest-blob --statement <statementPath> --bundle <bundlePath> --new-bundle-format --yes
//
// Using --statement hands cosign our fully-formed Statement to sign
// verbatim, rather than having cosign construct one around a blob argument
// — Anchor, not cosign, owns the in-toto statement construction, per the
// project's design goal.
//
// This triggers Sigstore's interactive (or device-code, in headless
// environments) OIDC login. stdin/stdout/stderr are wired to the parent
// process so the user can complete that login.
func AttestStatement(ctx context.Context, statementPath, bundlePath string) error {
	cosign, err := cosignPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, cosign, "attest-blob",
		"--statement", statementPath,
		"--bundle", bundlePath,
		"--new-bundle-format",
		"--yes",
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr // cosign's own status output; keep it off stdout so `anchor` can print clean results there
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign attest-blob failed: %w", err)
	}
	return nil
}

// VerifyBundle cryptographically re-verifies a cached bundle against the
// exact canonical blob it was originally signed over: valid signature,
// valid Fulcio cert chain, valid Rekor inclusion proof. It deliberately
// accepts any identity/issuer (Anchor does its own identity-provenance
// comparison in Go — see internal/verify) — this call only answers
// "is this a genuine, transparency-logged Sigstore attestation over this
// exact blob," not "do I trust the signer."
func VerifyBundle(ctx context.Context, bundlePath, blobPath, predicateType string) error {
	cosign, err := cosignPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, cosign, "verify-blob-attestation",
		"--bundle", bundlePath,
		"--certificate-identity-regexp", ".*",
		"--certificate-oidc-issuer-regexp", ".*",
		"--type", predicateType,
		blobPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify-blob-attestation failed (bundle may be forged, expired, or the blob doesn't match): %s", stderr.String())
	}
	return nil
}

// Info is what Anchor pulls out of a Sigstore bundle for its own
// bookkeeping and trust decisions.
type Info struct {
	LogIndex       int64
	Statement      []byte // decoded in-toto Statement JSON (the DSSE payload)
	SignerIdentity string // SAN (email or URI) from the Fulcio cert
	OIDCIssuer     string // Fulcio's embedded "issuer" cert extension
}

// sigstoreBundle mirrors the parts of the Sigstore bundle JSON format
// (https://github.com/sigstore/protobuf-specs, bundle/v1) that Anchor reads.
// protobuf's JSON mapping renders int64 fields as JSON strings, hence the
// string-typed LogIndex/IntegratedTime below.
type sigstoreBundle struct {
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		TlogEntries []struct {
			LogIndex string `json:"logIndex"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	DsseEnvelope *struct {
		Payload string `json:"payload"`
	} `json:"dsseEnvelope"`
}

// Fulcio embeds the OIDC issuer that authenticated the signer as a custom
// X.509 extension. Two OIDs have been used across Fulcio's history; check
// both.
var fulcioIssuerOIDs = []asn1.ObjectIdentifier{
	{1, 3, 6, 1, 4, 1, 57264, 1, 8}, // current
	{1, 3, 6, 1, 4, 1, 57264, 1, 1}, // legacy
}

// ParseBundle reads a cosign --new-bundle-format bundle file and extracts
// the fields Anchor's trust logic needs.
func ParseBundle(bundlePath string) (*Info, error) {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, err
	}
	var b sigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse bundle JSON: %w", err)
	}

	if len(b.VerificationMaterial.TlogEntries) == 0 {
		return nil, fmt.Errorf("bundle has no Rekor transparency log entry")
	}
	logIndex, err := strconv.ParseInt(b.VerificationMaterial.TlogEntries[0].LogIndex, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse logIndex: %w", err)
	}

	certDER, err := leafCertDER(&b)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	identity := certIdentity(cert)
	issuer := certIssuer(cert)

	if b.DsseEnvelope == nil {
		return nil, fmt.Errorf("bundle has no DSSE envelope")
	}
	statement, err := base64.StdEncoding.DecodeString(b.DsseEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	return &Info{
		LogIndex:       logIndex,
		Statement:      statement,
		SignerIdentity: identity,
		OIDCIssuer:     issuer,
	}, nil
}

func leafCertDER(b *sigstoreBundle) ([]byte, error) {
	vm := b.VerificationMaterial
	switch {
	case vm.Certificate != nil:
		return base64.StdEncoding.DecodeString(vm.Certificate.RawBytes)
	case vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) > 0:
		return base64.StdEncoding.DecodeString(vm.X509CertificateChain.Certificates[0].RawBytes)
	default:
		return nil, fmt.Errorf("bundle has no certificate in verificationMaterial")
	}
}

// certIdentity returns the signer's identity as embedded in the Fulcio
// cert's Subject Alternative Name: an email for OIDC email-based identities
// (Google/GitHub/Microsoft personal login), or a URI for workload
// identities (e.g. GitHub Actions).
func certIdentity(cert *x509.Certificate) string {
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	return ""
}

// certIssuer extracts Fulcio's "OIDC Issuer" extension from the cert.
func certIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		for _, oid := range fulcioIssuerOIDs {
			if !ext.Id.Equal(oid) {
				continue
			}
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
				return s
			}
			return string(ext.Value)
		}
	}
	return ""
}
