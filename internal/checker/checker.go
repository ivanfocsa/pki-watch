package checker

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type Thresholds struct {
	WarningDays  int
	CriticalDays int
}

type Result struct {
	Source        string    `json:"source"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	DNSNames      []string  `json:"dns_names"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	Severity      string    `json:"severity"`
	Error         string    `json:"error,omitempty"`
}

func CheckEndpoint(target string, thresholds Thresholds, timeout time.Duration) Result {
	address, serverName, err := normalizeTarget(target)
	if err != nil {
		return Result{Source: target, Severity: "critical", Error: err.Error()}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // Expiry monitoring must also work for private or self-signed PKI.
	})
	if err != nil {
		return Result{Source: target, Severity: "critical", Error: err.Error()}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Result{Source: target, Severity: "critical", Error: "no peer certificate returned"}
	}
	return ResultFromCertificate(target, certs[0], thresholds)
}

func CheckPEMFile(path string, thresholds Thresholds) []Result {
	content, err := os.ReadFile(path)
	if err != nil {
		return []Result{{Source: path, Severity: "critical", Error: err.Error()}}
	}

	var results []Result
	remaining := content
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			results = append(results, Result{Source: path, Severity: "critical", Error: err.Error()})
			continue
		}
		results = append(results, ResultFromCertificate(path, cert, thresholds))
	}
	if len(results) == 0 {
		return []Result{{Source: path, Severity: "critical", Error: "no certificate PEM block found"}}
	}
	return results
}

func ResultFromCertificate(source string, cert *x509.Certificate, thresholds Thresholds) Result {
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	return Result{
		Source:        source,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		DNSNames:      cert.DNSNames,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysRemaining: days,
		Severity:      severity(days, thresholds),
	}
}

func normalizeTarget(target string) (address string, serverName string, err error) {
	value := strings.TrimSpace(target)
	if value == "" {
		return "", "", fmt.Errorf("empty target")
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", "", err
		}
		value = parsed.Host
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		host = value
		port = "443"
	}
	if host == "" {
		return "", "", fmt.Errorf("target host is empty")
	}
	return net.JoinHostPort(host, port), host, nil
}

func severity(days int, thresholds Thresholds) string {
	if days <= thresholds.CriticalDays {
		return "critical"
	}
	if days <= thresholds.WarningDays {
		return "warning"
	}
	return "ok"
}

