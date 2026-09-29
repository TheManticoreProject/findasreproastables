package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/TheManticoreProject/FindAsreproastables/core"
	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
)

func TestRequestHashesWritesOnlyHashcatLines(t *testing.T) {
	accounts := []core.Account{{DN: "CN=alice,DC=example,DC=com", Username: "alice"}}
	var out, errOut bytes.Buffer
	called := false
	err := requestHashes(accounts, "example.com", "192.0.2.1", &out, &errOut,
		func(username, realm, kdc string) (*kerberos.ASREPRoastResult, error) {
			called = true
			if username != "alice" || realm != "example.com" || kdc != "192.0.2.1" {
				t.Fatalf("unexpected request args: %q %q %q", username, realm, kdc)
			}
			return &kerberos.ASREPRoastResult{
				Username: "alice", Realm: "EXAMPLE.COM", EncryptionType: 23,
				CipherText: []byte("0123456789abcdefdata"),
			}, nil
		})
	if err != nil || !called {
		t.Fatalf("requestHashes: called=%v err=%v", called, err)
	}
	want := "$krb5asrep$23$alice@EXAMPLE.COM:30313233343536373839616263646566$64617461\n"
	if out.String() != want || errOut.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestRequestHashesContinuesAfterFailures(t *testing.T) {
	accounts := []core.Account{
		{DN: "CN=missing", Username: ""},
		{DN: "CN=bad", Username: "bad"},
		{DN: "CN=aes", Username: "aes"},
		{DN: "CN=good", Username: "good"},
	}
	var out, errOut bytes.Buffer
	err := requestHashes(accounts, "example.com", "dc", &out, &errOut,
		func(username, realm, kdc string) (*kerberos.ASREPRoastResult, error) {
			if username == "bad" {
				return nil, errors.New("KDC denied request")
			}
			etype := 23
			if username == "aes" {
				etype = 18
			}
			return &kerberos.ASREPRoastResult{Username: username, Realm: "EXAMPLE.COM", EncryptionType: etype, CipherText: []byte("0123456789abcdefdata")}, nil
		})
	if err == nil || !strings.Contains(err.Error(), "3 of 4") {
		t.Fatalf("expected aggregate failure, got %v", err)
	}
	if !strings.Contains(errOut.String(), "missing sAMAccountName") || !strings.Contains(errOut.String(), "KDC denied request") || !strings.Contains(errOut.String(), "hashcat has no AS-REP mode") {
		t.Fatalf("missing diagnostics: %q", errOut.String())
	}
	if strings.Count(out.String(), "$krb5asrep$") != 1 || !strings.Contains(out.String(), "$good@EXAMPLE.COM:") {
		t.Fatalf("unexpected hash output: %q", out.String())
	}
}
