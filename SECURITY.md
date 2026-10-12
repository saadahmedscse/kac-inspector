# Security Policy

## Supported versions

Only the latest release receives fixes.

| Version | Supported |
|---|---|
| 1.x | Yes |

## What KAC Inspector does

Knowing what the program touches helps judge whether something is a vulnerability:

- It runs elevated (through UAC) so it can read the kernel module list, and enables
  `SeDebugPrivilege` in its own process token for that purpose only.
- It only **reads**: the kernel module list, the Service Control Manager's service
  configuration, and the file names in `%SystemRoot%\System32\drivers`.
- It never loads, stops, modifies or deletes a driver or service, writes no files, and makes
  no network connections.

Anything that makes it do more than that, such as running code it should not, writing to the
system, or being tricked by a crafted service entry or file name, is a security issue.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/saadahmedscse/kac-inspector/security/advisories/new).

Include the Windows version, the KAC Inspector version, and the steps to reproduce. You can
expect an acknowledgement within 7 days. Once a fix is released, the advisory is published
with credit to the reporter unless you prefer to stay anonymous.

## Antivirus warnings

The release binary is not code-signed. Because it requests administrator rights and queries
kernel drivers, some antivirus products may flag it heuristically. Every release lists the
SHA-256 of its executable, and you can always build it yourself from source with
`build.bat`.
