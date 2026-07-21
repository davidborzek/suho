# Security Policy

suho is a **privileged network daemon**: it runs with `CAP_NET_ADMIN`, reads the
Docker API, and programs the host's nftables ruleset. A bug can open holes or cut
connectivity for every container on the host, so security reports are taken
seriously.

## Supported versions

suho is pre-1.0. Only the latest release (and `main`) receive security fixes.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, affected version/commit, and a reproduction if possible.

You can expect an acknowledgement within a few days. Once a fix is available it
will be released and the advisory published with credit (unless you prefer to
remain anonymous).

## Scope

Especially relevant:

- Rules that fail to enforce a declared policy (silent allow), or that block
  traffic a policy permits.
- Ways to make suho program rules outside its own `inet suho` table.
- Privilege or Docker-socket handling issues.

Out of scope: misconfiguration by the operator, and the inherent trust in the
Docker API suho is pointed at.
