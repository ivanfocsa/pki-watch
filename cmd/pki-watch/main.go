package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ivanfocsa/pki-watch/internal/alert"
	"github.com/ivanfocsa/pki-watch/internal/checker"
	"github.com/ivanfocsa/pki-watch/internal/report"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprint([]string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	var targets multiFlag
	var files multiFlag
	var jsonOutput bool
	warn := flag.Int("warn", 30, "warning threshold in days")
	critical := flag.Int("critical", 7, "critical threshold in days")
	timeout := flag.Duration("timeout", 5*time.Second, "network timeout")
	webhook := flag.String("webhook", "", "optional Slack/Teams compatible webhook URL")
	flag.Var(&targets, "target", "TLS target, repeatable. Accepts host, host:port or HTTPS URL")
	flag.Var(&files, "file", "PEM file, repeatable")
	flag.BoolVar(&jsonOutput, "json", false, "write JSON output")
	flag.Parse()

	if len(targets) == 0 && len(files) == 0 {
		fmt.Fprintln(os.Stderr, "at least one -target or -file is required")
		flag.Usage()
		os.Exit(2)
	}

	thresholds := checker.Thresholds{WarningDays: *warn, CriticalDays: *critical}
	var results []checker.Result
	for _, target := range targets {
		results = append(results, checker.CheckEndpoint(target, thresholds, *timeout))
	}
	for _, file := range files {
		results = append(results, checker.CheckPEMFile(file, thresholds)...)
	}

	var err error
	if jsonOutput {
		err = report.WriteJSON(os.Stdout, results)
	} else {
		err = report.WriteTable(os.Stdout, results)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *webhook != "" {
		if err := alert.SendWebhook(*webhook, alert.BuildPayload(results), *timeout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	if hasCritical(results) {
		os.Exit(2)
	}
	if hasWarning(results) {
		os.Exit(1)
	}
}

func hasCritical(results []checker.Result) bool {
	for _, result := range results {
		if result.Severity == "critical" {
			return true
		}
	}
	return false
}

func hasWarning(results []checker.Result) bool {
	for _, result := range results {
		if result.Severity == "warning" {
			return true
		}
	}
	return false
}

