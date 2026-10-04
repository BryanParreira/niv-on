# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/BryanParreira/niv-on/security/advisories/new)
instead. You'll get an acknowledgement within a few days.

## How releases are protected

- macOS builds are signed with a Developer ID certificate and notarized by Apple.
- Every update package is signed; installed copies refuse updates that don't
  verify against the public key built into the app.
- Signing material is stored only in a protected GitHub environment that can be
  used exclusively by release tags. Pull requests and forks never have access.
- CI actions are pinned to exact commits and kept current by Dependabot.

## Scope

Niv.ON captures network traffic on the machine it runs on. Use it only on
networks you own or are authorized to assess.
