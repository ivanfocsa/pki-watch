package checker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestResultFromCertificateSeverity(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "soon.example"},
		Issuer:   pkix.Name{CommonName: "test-ca"},
		NotAfter: time.Now().Add(48 * time.Hour),
	}

	result := ResultFromCertificate("unit", cert, Thresholds{WarningDays: 30, CriticalDays: 7})

	if result.Severity != "critical" {
		t.Fatalf("expected critical, got %s", result.Severity)
	}
}

func TestCheckPEMFile(t *testing.T) {
	certPEM := selfSignedPEM(t, time.Now().Add(90*24*time.Hour))
	file, err := os.CreateTemp(t.TempDir(), "cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(certPEM); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	results := CheckPEMFile(file.Name(), Thresholds{WarningDays: 30, CriticalDays: 7})

	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0].Severity != "ok" {
		t.Fatalf("expected ok, got %s", results[0].Severity)
	}
}

func selfSignedPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unit.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"unit.example"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

