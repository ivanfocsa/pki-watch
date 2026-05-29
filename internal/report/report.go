package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/ivanfocsa/pki-watch/internal/checker"
)

func WriteJSON(w io.Writer, results []checker.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func WriteTable(w io.Writer, results []checker.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SOURCE\tSEVERITY\tDAYS\tEXPIRES\tSUBJECT"); err != nil {
		return err
	}
	for _, result := range results {
		expires := result.NotAfter.Format("2006-01-02")
		if result.Error != "" {
			expires = "n/a"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", result.Source, result.Severity, result.DaysRemaining, expires, result.Subject); err != nil {
			return err
		}
	}
	return tw.Flush()
}

