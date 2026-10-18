# Security policy

ControlledBurn runs on the firewall itself, so security problems in it are
taken seriously.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Report it
privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Include what you found, how to reproduce it, and
the plugin version shown in the page footer.

This is a spare-time project, so responses are best effort. You'll get an
acknowledgement, and fixes for real vulnerabilities take priority over
everything else.

## Scope

In scope: this plugin's code, meaning the API endpoints, the page and its
scripts, the configd action and `get_ruleset.py`, and the settings it
stores.

Out of scope: OPNsense itself, PHP and pf. Report those to the
[OPNsense project](https://opnsense.org/) instead.

## Supported versions

Only the latest version gets security fixes.

## Design notes

What the plugin does and doesn't do, security-wise (no outbound
connections, untrusted text is never rendered as markup, write limits), is
in the README's **Security and privacy** section. The audit is recorded in
`docs/PLAN.md` §3.14.
