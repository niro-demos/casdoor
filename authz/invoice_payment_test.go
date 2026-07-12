package authz

import (
	"os"
	"strings"
	"testing"
)

func TestInvoicePaymentIsNotAnonymousAPI(t *testing.T) {
	source, err := os.ReadFile("authz.go")
	if err != nil {
		t.Fatal(err)
	}

	const anonymousInvoiceRule = "p, *, *, POST, /api/invoice-payment, *, *"
	if strings.Contains(string(source), anonymousInvoiceRule) {
		t.Fatal("invoice-payment is reachable through the anonymous API allowlist")
	}
}
