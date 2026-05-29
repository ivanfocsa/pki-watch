package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ivanfocsa/pki-watch/internal/checker"
)

type Payload struct {
	Text string `json:"text"`
}

func BuildPayload(results []checker.Result) Payload {
	var lines []string
	for _, result := range results {
		if result.Severity == "ok" {
			continue
		}
		if result.Error != "" {
			lines = append(lines, fmt.Sprintf("- %s: %s (%s)", result.Source, result.Severity, result.Error))
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s: %s, expires in %d days (%s)", result.Source, result.Severity, result.DaysRemaining, result.NotAfter.Format("2006-01-02")))
	}
	if len(lines) == 0 {
		return Payload{Text: "pki-watch: all certificates are ok"}
	}
	return Payload{Text: "pki-watch alerts\n" + strings.Join(lines, "\n")}
}

func SendWebhook(webhookURL string, payload Payload, timeout time.Duration) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

