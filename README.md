# Sentinel Audit

**An authorized security-auditing framework.** Sentinel performs the reconnaissance
and configuration-audit work that sits at the start of every real penetration test
or blue-team review — host discovery, port scanning, service enumeration, TLS/certificate
inspection, HTTP security-header analysis, and DNS enumeration — and turns the results
into clean JSON / Markdown / HTML reports.

It ships as both a **command-line tool** and a **local desktop UI**, runs on **Linux and
Windows**, and uses **only the Python standard library** — no dependencies to install on a
locked-down audit laptop.

> ### ⚖️ Authorized use only
> Sentinel is a defensive and authorized-testing tool. It will **refuse to touch any target
> that is not listed in an engagement scope file you explicitly author** (see
> [Rules of engagement](#rules-of-engagement)). Scanning, probing, or enumerating systems
> you do not own or have **written permission** to test is illegal in most jurisdictions
> (e.g. the US Computer Fraud and Abuse Act, the UK Computer Misuse Act). You are
> responsible for operating within the law and your authorization.
>
> Sentinel deliberately does **not** include exploitation payloads, malware, or tooling
> designed to damage or gain unauthorized control of systems. It is a *measurement* tool.

---

## Why this exists

Most of a competent security assessment is not "popping shells" — it's methodical,
repeatable *measurement*: what hosts are alive, what's listening, how services are
configured, whether TLS is sound, whether web servers leak information or miss hardening
headers. Sentinel makes that phase fast, consistent, and reportable, with safety rails
that keep you inside your authorization.

## Features

**Network & host**

| Module | What it does |
| --- | --- |
| `discovery` | TCP-based host liveness sweep across a scope |
| `portscan` | Concurrent TCP connect scan with common / full / custom port sets |
| `services` | Banner grabbing + lightweight service & version fingerprinting |
| `sshaudit` | SSH identification string: protocol (flags SSH-1) and version posture |
| `tls` | Certificate chain & expiry, **per-version protocol enumeration**, weak-protocol flags |

**Web application & API**

| Module | What it does |
| --- | --- |
| `http` | Security headers (HSTS, CSP, X-Frame-Options…), server leakage, cookie flags |
| `webcrawl` | Bounded same-host spider: pages, forms, robots/sitemap/security.txt, mixed content |
| `exposure` | Exposed sensitive files (.git/.env/backups), directory listing, risky HTTP methods, broad CORS — with **soft-404 baselining** to avoid false positives |

**Domain / email**

| Module | What it does |
| --- | --- |
| `dns` | A/AAAA/MX/NS/TXT records, reverse DNS, common-subdomain enumeration |
| `emailsec` | Anti-spoofing posture: SPF, DMARC, DKIM selectors, MX |

All modules are **scope-gated** and emit structured `Finding` objects with a severity,
so the reporting layer can prioritize automatically. The web modules issue only
non-destructive `GET`/`OPTIONS` requests — Sentinel never submits payloads, fuzzes
inputs, or attempts brute-forcing or exploitation.

### Profiles

Instead of listing modules by hand, pick a bundle with `--profile`:

| Profile | Modules |
| --- | --- |
| `quick` | discovery, portscan, services |
| `default` | discovery, portscan, services, tls, http, dns |
| `web` | http, tls, exposure, webcrawl |
| `server` | discovery, portscan, services, tls, sshaudit |
| `email` | dns, emailsec |
| `full` | everything |

## Install

```bash
git clone <your-private-repo-url> sentinel-audit
cd sentinel-audit
python -m sentinel --help          # run straight from source, no install needed
# or, to get the `sentinel` command on your PATH:
pip install -e .
```

Optional extras (nicer YAML scopes, test runner):

```bash
pip install -e ".[yaml,dev]"
```

## Quick start

1. **Declare what you're allowed to test.** Copy the example scope and edit it:

   ```bash
   cp scopes/example.yaml scopes/my-engagement.yaml
   ```

   ```yaml
   engagement: "ACME internal review 2026-Q4"
   authorized_by: "jane.doe@acme.example — written authorization on file (ticket SEC-4821)"
   authorized_until: "2026-12-31"
   targets:
     - 127.0.0.1
     - 192.168.56.0/24
     - test.internal.acme.example
   exclude:
     - 192.168.56.1        # gateway — out of scope
   ```

2. **Run an audit:**

   ```bash
   # Full default audit of everything in scope, Markdown + JSON report:
   python -m sentinel run --scope scopes/my-engagement.yaml --out reports/

   # Just a port scan + service enumeration of one in-scope host:
   python -m sentinel run --scope scopes/my-engagement.yaml \
       --target 192.168.56.10 --modules portscan,services

   # Full web-app audit of an in-scope site (headers, TLS, exposure, crawl):
   python -m sentinel run --scope scopes/my-engagement.yaml \
       --target test.internal.acme.example --profile web --out reports/

   # Email anti-spoofing posture for a domain:
   python -m sentinel run --scope scopes/my-engagement.yaml \
       --target acme.example --profile email
   ```

3. **Or launch the desktop UI:**

   ```bash
   python -m sentinel gui      # opens a local web UI in your browser
   ```

## Rules of engagement

Every run requires a **scope file**. Before any module touches the network, Sentinel:

1. Parses the scope and validates it has an engagement name, an authorizer, and an expiry.
2. Refuses to run if `authorized_until` is in the past.
3. Resolves each requested target and checks it is inside an authorized CIDR/host entry
   **and** not in `exclude`. Out-of-scope targets are dropped with a logged reason —
   they are never probed.
4. Prints an authorization banner and records the scope metadata into the report, so every
   artifact is self-documenting about *what was authorized by whom*.

This mirrors how professional engagements define Rules of Engagement (RoE), and it means a
stray typo can't turn into an unauthorized scan of someone else's network.

## Architecture

```
sentinel/
├── __main__.py          # `python -m sentinel`
├── cli.py               # argument parsing, command dispatch
├── core/
│   ├── models.py        # Target, Finding, ModuleResult, AuditReport, Severity
│   ├── scope.py         # scope parsing + authorization enforcement
│   ├── engine.py        # orchestrates modules over in-scope targets
│   └── report.py        # JSON / Markdown / HTML renderers
├── modules/
│   ├── base.py          # AuditModule interface + registry
│   ├── _http.py         # shared non-destructive HTTP fetch helper
│   ├── discovery.py     portscan.py    services.py   sshaudit.py
│   ├── tls_audit.py     http_audit.py  webcrawl.py   exposure.py
│   └── dns_enum.py      emailsec.py
└── gui/
    └── app.py           # zero-dependency local web UI
```

Modules implement a tiny interface (`AuditModule.run(target, ctx) -> list[Finding]`) and
self-register, so adding a new check is a single file.

## Roadmap

- [ ] Packaged native binaries (PyInstaller for the CLI, Electron/Tauri wrapper for GUI)
- [ ] Pluggable integration with external scanners where authorized (import nmap XML, etc.)
- [ ] Credentialed configuration checks (SSH/WinRM) for hardening audits
- [ ] Diff mode: compare two audits to track remediation over time

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE). Provided for lawful, authorized security work only.
