package controllers

import (
	"os"
	"strings"
	"testing"
)

func TestInvoicePaymentRequiresOwnershipAuthorization(t *testing.T) {
	source, err := os.ReadFile("payment.go")
	if err != nil {
		t.Fatal(err)
	}

	invoiceHandler := strings.SplitN(string(source), "func (c *ApiController) InvoicePayment()", 2)
	if len(invoiceHandler) != 2 {
		t.Fatal("InvoicePayment handler not found")
	}

	body := invoiceHandler[1]
	if !strings.Contains(body, "authorizePaymentAccess") {
		t.Fatal("InvoicePayment does not enforce payment ownership before generating an invoice")
	}
}

func TestGetPaymentRetainsOwnershipAuthorization(t *testing.T) {
	source, err := os.ReadFile("payment.go")
	if err != nil {
		t.Fatal(err)
	}

	getHandler := strings.SplitN(string(source), "func (c *ApiController) GetPayment()", 2)
	if len(getHandler) != 2 || !strings.Contains(getHandler[1], "Forbidden") {
		t.Fatal("legitimate control failed: GetPayment no longer enforces payment ownership")
	}
}
