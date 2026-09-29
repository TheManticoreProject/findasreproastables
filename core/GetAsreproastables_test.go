package core

import (
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

func TestAccountsFromEntries(t *testing.T) {
	entries := []*goldap.Entry{
		goldap.NewEntry("CN=Alice,DC=example,DC=com", map[string][]string{"sAMAccountName": {"alice"}}),
		goldap.NewEntry("CN=Missing,DC=example,DC=com", nil),
	}
	got := accountsFromEntries(entries)
	if len(got) != 2 || got[0].DN != entries[0].DN || got[0].Username != "alice" || got[1].Username != "" {
		t.Fatalf("accountsFromEntries() = %+v", got)
	}
	if !strings.Contains(asreproastableQuery(), "userAccountControl:1.2.840.113556.1.4.803:=") {
		t.Fatalf("query does not test UAC preauthentication bit: %q", asreproastableQuery())
	}
}
