# netpwn

L2/L3 MITM & network attack suite — ARP/DHCP/DNS/VLAN/spoof/port-knock/pcap, dry-run default, restore-on-exit.

> A companion to bettercap-class "swiss army knife" tooling, built to genuinely work
> over raw `AF_PACKET`/`AF_INET` sockets on localhost, with a strict offline-first
> safety posture. Anything touching a real interface requires `--iface` + `--yes` +
> membership in the lab allowlist.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

## Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

## Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

## Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

## Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

## No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

## Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

```bash
python3 -m pip install -e .
python3 -m netpwn --help
python3 -m netpwn --demo    # offline, exit 0
python3 -m unittest discover -s tests
```

## Modules

| Command    | Purpose                                                          | Live gate                          |
|------------|------------------------------------------------------------------|------------------------------------|
| `arp`      | build/parse ARP, spoof/restore demo, gratuitous, lo0 harness     | `--iface --yes` + allowlist        |
| `dhcp`     | BOOTP parse/build, starvation sim, rogue-offer demo              | `--dry-run` only offline           |
| `dns`      | query/response builder, spoof ID detection, rebinding demo       | — (offline fixtures)               |
| `vlan`     | 802.1Q single/double-tag build, anomaly detect                   | — (offline fixtures)               |
| `spoof`    | forged-src IP/ICMP, MAC sim (ioctl-gated), rDNS, ICMP sweep      | `--iface --yes` + allowlist (MAC)  |
| `knock`    | SYN knock sequence opens secret port on loopback                 | loopback only (ports 7000/8000/9000→9999) |
| `mitm`     | userspace interception pipeline, SQLite capture store            | loopback SO_REUSEPORT listener     |
| `sniff`    | own pcap reader, flow extraction, anomaly detection              | read-only file/offline              |
| `report`   | JSON + Markdown reports to `reports/`                            | —                                  |

## Safety model

- **Default is dry-run.** Subcommands build/print packets without touching the wire.
- **Lab allowlist** (`netpwn/lab_allowlist.conf`): only `lo`, RFC 5737 TEST-NETs
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and `127.0.0.0/8` by default.
  Override with `--lab-allowlist path`; any interface-level action failing the check
  raises `LiveActionBlocked` and exits non-zero.
- **Restore-on-exit**: MITM `stop()` closes the listener, joins the capture thread,
  and closes the SQLite store so nothing lingers.

## Examples

```bash
# offline fixture proof
python3 -m netpwn arp parse
python3 -m netpwn dns spoof-check
python3 -m netpwn dhcp starve --count 10
python3 -m netpwn vlan detect

# loopback integration (no root needed)
python3 -m netpwn knock e2e            # opens secret port, roundtrips secret
python3 -m netpwn mitm plan            # dry-run of the interception pipeline

# report
python3 -m netpwn report generate --data '{"summary":{"modules":9}}'
```

## Live Lab Test Plan

> **Own-airspace / own-net only.** `lab-*` SSIDs and RFC 5737 addresses only.
> NEVER against other people's devices or networks.

| # | Test | Command | Expected proof |
|---|------|---------|----------------|
| 1 | ARP spoof/restore on own lab iface | `sudo python3 -m netpwn arp spoof --iface lab0 --yes --live` | dry-run line replaced by real send; restore ARP sent after ~500ms; `arp -a` via `ip neigh` shows spoofed MAC then original |
| 2 | ARP cache poisoning harness | `sudo python3 -m netpwn arp cache` (implemented as loopback `harness`) | `roundtrip_ok: true` reported from real raw-socket send/recv |
| 3 | DHCP starvation sweep | `python3 -m netpwn dhcp starve --count 250 --dry-run` | 250 unique client MACs listed, `parsed_msg_type: DISCOVER` |
| 4 | Rogue-DHCP threat model | `python3 -m netpwn dhcp rogue` | printed offer destined to `192.0.2.50` with rogue IP gateway/DNS (offline) |
| 5 | DNS spoof detection | `python3 -m netpwn dns spoof-check` | replay valid, off-by-one ID flagged `ID mismatch` |
| 6 | DNS rebinding | `python3 -m netpwn dns rebind` | same tx_id, two different answer IPs (`rebound: true`) |
| 7 | Port knock (own host) | `python3 -m netpwn knock e2e` | `secret port accepted: ACCEPTED:127.0.0.1` |
| 8 | MITM pipeline dry-run | `python3 -m netpwn mitm plan` | 6 `[DRY-RUN]` steps printed |
| 9 | pcap analysis | `python3 -m netpwn sniff read --file lab_capture.pcap` | JSON packet count + flow tallies + anomalies |
| 10 | Passive monitoring | run on own lab net, then above | ARP conflict / DHCP starvation / DNS ID mismatch entries in `reports/` |

## Metrics

See [METRICS.md](METRICS.md) — every number is measured from the committed test suite.

## Development

```bash
python3 -m unittest discover -s tests
```

Python 3.9+ stdlib only. `scapy` is an optional extra (`pip install netpwn[scapy]`)
and is never required for correctness.