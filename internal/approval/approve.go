// Package approval implements the operator-controlled terminal workflow.
// There is no browser UI and no HTTP listener. Operators approve from a
// trusted terminal via `seqpass admin`; agents observe approval state via
// secret_status / ops.mine polling from within their harness.
package approval

import (
	"fmt"
	"strings"

	"github.com/secretbridge/secretbridge/internal/types"
)

// FormatUse renders an approval prompt for the trusted terminal.
// It never includes secret material, only references.
func FormatUse(ur *types.UseRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Operation ID: %s\n", ur.ID)
	fmt.Fprintf(&b, "Type: credential use\n")
	fmt.Fprintf(&b, "Secret ref: %s\n", ur.SecretRef)
	fmt.Fprintf(&b, "Operation: %s\n", ur.Operation)
	if ur.Target != "" {
		fmt.Fprintf(&b, "Target: %s\n", ur.Target)
	}
	if len(ur.Params) > 0 {
		fmt.Fprintf(&b, "Params: ")
		first := true
		for k, v := range ur.Params {
			if !first {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s=%s", k, v)
			first = false
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Requested by: %s\n", ur.RequestedBy)
	fmt.Fprintf(&b, "Status: %s\n", ur.Status)
	if !ur.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "Expires: %s\n", ur.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
	return b.String()
}

// FormatTransfer renders a transfer approval prompt.
func FormatTransfer(tr *types.TransferRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Operation ID: %s\n", tr.ID)
	fmt.Fprintf(&b, "Type: transfer\n")
	fmt.Fprintf(&b, "Secret ref: %s\n", tr.SecretRef)
	fmt.Fprintf(&b, "Destination: %s\n", tr.DestinationID)
	fmt.Fprintf(&b, "Requested by: %s\n", tr.RequestedBy)
	fmt.Fprintf(&b, "Status: %s\n", tr.Status)
	if !tr.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "Expires: %s\n", tr.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
	return b.String()
}
