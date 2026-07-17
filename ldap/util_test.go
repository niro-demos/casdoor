package ldap

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/lor00x/goldap/message"
	"github.com/xorm-io/builder"

	"github.com/casdoor/casdoor/object"
	"github.com/xorm-io/xorm"
)

func args(exp ...interface{}) []interface{} {
	return exp
}

func TestLdapFilterAsQuery(t *testing.T) {
	scenarios := []struct {
		description  string
		input        string
		expectedExpr string
		expectedArgs []interface{}
	}{
		{"Should be SQL for FilterAnd", "(&(mail=2)(email=1))", "email=? AND email=?", args("2", "1")},
		{"Should be SQL for FilterOr", "(|(mail=2)(email=1))", "email=? OR email=?", args("2", "1")},
		{"Should be SQL for FilterNot", "(!(mail=2))", "NOT email=?", args("2")},
		{"Should be SQL for FilterEqualityMatch", "(mail=2)", "email=?", args("2")},
		{"Should be SQL for FilterPresent", "(mail=*)", "email IS NOT NULL", nil},
		{"Should be SQL for FilterGreaterOrEqual", "(mail>=admin)", "email>=?", args("admin")},
		{"Should be SQL for FilterLessOrEqual", "(mail<=admin)", "email<=?", args("admin")},
		{"Should be SQL for FilterSubstrings", "(mail=admin*ex*c*m)", "email LIKE ?", args("admin%ex%c%m")},
		{"Should be SQL for country attribute c", "(c=US)", "region=?", args("US")},
		{"Should be SQL for country attribute co", "(co=United States)", "region=?", args("United States")},
	}

	for _, scenery := range scenarios {
		t.Run(scenery.description, func(t *testing.T) {
			searchRequest, err := buildLdapSearchRequest(scenery.input)
			if err != nil {
				assert.FailNow(t, "Unable to create searchRequest", err)
			}
			m, err := message.ReadLDAPMessage(message.NewBytes(0, searchRequest.Bytes()))
			if err != nil {
				assert.FailNow(t, "Unable to create searchRequest", err)
			}
			req := m.ProtocolOp().(message.SearchRequest)

			cond, err := buildUserFilterCondition(req.Filter())
			if err != nil {
				assert.FailNow(t, "Unable to build condition", err)
			}
			expr, args, err := builder.ToSQL(cond)
			if err != nil {
				assert.FailNow(t, "Unable to build sql", err)
			}

			assert.Equal(t, scenery.expectedExpr, expr)
			assert.Equal(t, scenery.expectedArgs, args)
		})
	}
}

// TestUserPasswordAttributeIsMaskedInLdapSearchResponse is the regression
// test for TC-B61201B0: the LDAP directory-search response must mask the
// userPassword attribute the same way every REST GetX handler masks
// user.Password to "***" (object.GetMaskedUser, object/user.go), instead of
// serializing the raw stored bcrypt hash onto the wire whenever a bound
// client (any org admin / global admin allowed to search at all) names
// "userPassword" in a SearchRequest's attribute-selection list.
func TestUserPasswordAttributeIsMaskedInLdapSearchResponse(t *testing.T) {
	user := seedLdapPasswordMaskingTestUser(t)

	pw := getAttribute("userPassword", user)

	if string(pw) == user.Password {
		t.Fatalf("userPassword attribute leaked the real stored password hash over LDAP: got %q", pw)
	}
	if s := string(pw); s != "" && s != "***" {
		t.Fatalf("userPassword attribute must be masked (\"***\") or omitted like every other secret field in this product, got %q", s)
	}

	// Positive control: a non-secret attribute for the same user must still
	// resolve correctly, proving a failure above is the masking invariant,
	// not a broken test environment.
	if cn := getAttribute("cn", user); string(cn) != user.Name {
		t.Fatalf("positive control failed: cn = %q, want %q (test setup broken, not the security fix)", cn, user.Name)
	}
}

// seedLdapPasswordMaskingTestUser seeds a throwaway sqlite-backed database
// with one organization and one user, then points the object package's
// shared ormer at it (the same env-vars-override-app.conf mechanism the
// Niro harness's own start.sh uses: driverName/dataSourceName/dbName are
// read by conf.GetConfigString, which checks the process environment
// before the tracked conf/app.conf). This is required because the LDAP
// "userPassword" attribute mapping resolves the user's organization via
// object.GetOrganizationByUser, which hits the database — on the pre-fix
// code that lookup is how the raw hash gets fetched; on the fixed code the
// attribute is masked before any such lookup would matter.
func seedLdapPasswordMaskingTestUser(t *testing.T) *object.User {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "ldap-masking-test.db") + "?cache=shared"

	seedEngine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("failed to open sqlite test engine: %v", err)
	}
	if err := seedEngine.Sync2(new(object.Organization), new(object.User)); err != nil {
		t.Fatalf("failed to sync test schema: %v", err)
	}

	org := &object.Organization{Owner: "admin", Name: "acme", PasswordType: "plain"}
	if _, err := seedEngine.Insert(org); err != nil {
		t.Fatalf("failed to seed test organization: %v", err)
	}

	user := &object.User{
		Owner:    "acme",
		Name:     "alice",
		Id:       "e42dccff-a695-4325-b904-05f855108c7f",
		Password: "{bcrypt}$2a$10$J0gU7mDl0IkHQioAS5ux4ugmJrDMrw7l1jOmPkQuSf0RctYK5vUpa",
	}
	if _, err := seedEngine.Insert(user); err != nil {
		t.Fatalf("failed to seed test user: %v", err)
	}
	if err := seedEngine.Close(); err != nil {
		t.Fatalf("failed to close seeding engine: %v", err)
	}

	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", dsn)
	t.Setenv("dbName", "")
	object.InitAdapter()

	return user
}

func buildLdapSearchRequest(filter string) (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))

	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchRequest, nil, "Search Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref Aliases"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	pkt.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
	// compile and encode filter
	filterPacket, err := goldap.CompileFilter(filter)
	if err != nil {
		return nil, err
	}
	pkt.AppendChild(filterPacket)
	// encode attributes
	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "*", "Attribute"))
	pkt.AppendChild(attributesPacket)

	packet.AppendChild(pkt)

	return packet, nil
}
