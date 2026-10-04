# Security Policy

`ntp_usg` is time-synchronisation software. Bugs in it can move a machine's
clock, which in turn affects certificate validation, authentication tokens,
log integrity and replay protection across everything running on that
machine. We treat security reports accordingly.

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/192d-Wing/ntp_usg/security/advisories/new>

Include, where you can:

- the crate and version (or commit) affected;
- a description of the issue and its impact (what an attacker can do, from
  where: on-path, off-path, a malicious server, a malicious client);
- steps or a proof of concept to reproduce it;
- any suggested fix.

You will receive an acknowledgement within **5 business days**. We aim to
confirm or rule out the report within **14 days** of acknowledgement, and to
publish a fix for confirmed issues within **90 days** of the report, sooner
for anything actively exploitable. We will keep you informed of progress and
credit you in the advisory unless you ask us not to.

If you have not heard back within the acknowledgement window, open a public
issue that says only that you have sent a private report and are awaiting a
response, without details of the vulnerability.

## Supported versions

Security fixes are applied to the most recent release series. Older series
receive fixes at the maintainers' discretion.

| Version | Supported |
| ------- | --------- |
| 5.x     | Yes       |
| < 5.0   | No        |

## Scope

In scope:

- all crates in this repository (`ntp_usg-proto`, `ntp_usg-client`,
  `ntp_usg-server`, `ntp_usg-wasm`) and their examples;
- the Docker images built from this repository.

Particularly relevant classes of issue:

- anything that lets a remote peer panic, hang, or exhaust resources in the
  client or server (denial of service);
- anything that lets an off-path attacker influence the computed clock
  offset, including bypasses of origin-timestamp, NTS, NTPv5 cookie or
  Roughtime verification;
- memory-safety or soundness problems in `unsafe` code;
- key material being leaked, logged, or retained longer than necessary;
- deviations from RFC 5905, RFC 8915, RFC 9109, RFC 9769 or the NTPv5 and
  Roughtime drafts that weaken the protections those specifications provide.

Out of scope:

- vulnerabilities in upstream dependencies that are not exploitable through
  this project's use of them (report those upstream, but do tell us if the
  fix requires a change here);
- issues that require the attacker to already control the host running the
  software;
- the accuracy of time delivered by third-party public NTP servers.

## Disclosure

We follow coordinated disclosure. Once a fix is released we publish a GitHub
Security Advisory describing the issue, affected versions and the fix, and
request a CVE where appropriate. Fixed issues are also listed under
**Security** in [CHANGELOG.md](CHANGELOG.md).

## Hardening guidance for deployers

- Prefer NTS (`nts` feature) or NTPv5 over plain NTPv4 wherever the server
  supports it; plain NTPv4 has only origin-timestamp matching as an off-path
  defence.
- Configure more than one time source so the selection algorithm can reject
  a falseticker; a single source is trusted outright.
- Keep the default clock-step limit (`max_step_secs`) unless you have a
  specific reason to raise it.
- On servers, enable rate limiting and keep the NTS-KE connection limits at
  or below their defaults when exposed to the Internet.
