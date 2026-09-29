package core

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	goldap "github.com/go-ldap/ldap/v3"
)

// Account identifies an LDAP account that can be targeted by an AS-REQ.
type Account struct {
	DN       string
	Username string
}

func asreproastableQuery() string {
	return fmt.Sprintf("(&(|(objectClass=computer)(objectClass=person)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=%d))", ldap_attributes.UAF_DONT_REQ_PREAUTH)
}

func accountsFromEntries(entries []*goldap.Entry) []Account {
	accounts := make([]Account, 0, len(entries))
	for _, entry := range entries {
		accounts = append(accounts, Account{DN: entry.DN, Username: entry.GetAttributeValue("sAMAccountName")})
	}
	return accounts
}

// GetAsreproastableAccounts returns both the DN for display and the account
// name needed for the Kerberos request.
func GetAsreproastableAccounts(ldapSession *ldap.Session) ([]Account, error) {
	entries, err := ldapSession.QueryWholeSubtree("", asreproastableQuery(), []string{"sAMAccountName"})
	if err != nil {
		return nil, fmt.Errorf("error performing LDAP search: %w", err)
	}
	return accountsFromEntries(entries), nil
}

func GetAsreproastables(ldapSession ldap.Session) ([]string, error) {
	accounts, err := GetAsreproastableAccounts(&ldapSession)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(accounts))
	for _, account := range accounts {
		results = append(results, account.DN)
	}
	return results, nil
}
