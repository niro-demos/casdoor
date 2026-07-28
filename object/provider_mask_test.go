package object

import (
	"encoding/json"
	"testing"
)

func TestMaskedPaymentProviderOmitsCredentialFields(t *testing.T) {
	provider := &Provider{
		Owner:         "admin",
		Name:          "provider-payment",
		DisplayName:   "Payment Provider",
		Category:      "Payment",
		Type:          "Dummy",
		ClientId:      "client-id",
		ClientSecret:  "client-secret",
		ClientId2:     "client-id-2",
		ClientSecret2: "client-secret-2",
		Cert:          "provider-cert",
		HttpHeaders:   map[string]string{"Authorization": "Bearer provider-token"},
	}

	raw, err := json.Marshal(GetMaskedProvider(provider, true))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"clientId", "clientId2", "cert", "httpHeaders"} {
		if value, ok := fields[field]; ok && value != "" && value != nil {
			t.Fatalf("masked payment provider exposes credential field %q: %s", field, raw)
		}
	}
	if fields["clientSecret"] != "***" || fields["clientSecret2"] != "***" {
		t.Fatalf("masked payment provider should retain placeholder secret markers: %s", raw)
	}
	if fields["name"] != provider.Name || fields["displayName"] != provider.DisplayName || fields["type"] != provider.Type {
		t.Fatalf("masked payment provider lost selection metadata: %s", raw)
	}
}
