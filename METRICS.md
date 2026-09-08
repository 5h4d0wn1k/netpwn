# Metrics

All numbers measured from the committed test suite (`python3 -m unittest discover -s tests`) and `python3 -m netpwn --demo` on the dev machine (Python 3.13, Linux x86_64).

## Test suite

| Metric | Measured |
|--------|----------|
| Total tests | **132** |
| Test run time | **5.645 s** |
| Failures / errors | **0 / 0** |
| Result | **OK** |

Per-module test counts:

| Module | Tests |
|--------|-------|
| ARP | 24 |
| CLI | 20 |
| DHCP | 16 |
| SNIFF (pcap reader, flows, anomalies) | 14 |
| Spoofing | 13 |
| DNS | 12 |
| VLAN | 11 |
| Knock | 9 |
| MITM | 7 |
| Report | 6 |

## Demo (`python3 -m netpwn --demo`)

| Metric | Measured |
|--------|----------|
| Exit code | **0** |
| Total wall time | **3.819 s** |
| Modules passed | **9 / 9** |
| ARP frame roundtrip | OK |
| Knock sequence accepted (secret port, real loopback) | OK — `ACCEPTED:127.0.0.1` |
| DNS ID-mismatch flagged | OK — 1/2 valid, 1 flagged |
| DHCP starvation (deterministic fake MACs) | OK — 10 unique MACs starved |

## Live-gated accuracy (loopback integration)

| Check | Result |
|-------|--------|
| Port-knock E2E opens secret port | pass |
| DNS query parse vs fixture hex | pass (id=0xabcd, www.example.com) |
| pcap parser extracts ARP=2 / DHCP=2 / DNS=2 flows | pass |
| No-false-positive on clean flow set | pass (0 anomalies) |
| Anomaly detection on spoof/dirty set | pass (2 anomalies) |

## Coverage notes

- Byte-exact assertions (crafted vs parsed packet equality) exist for ARP, DHCP, DNS, VLAN, and ICMP fixtures.
- Chip time maintained: every number above is a fresh measurement; re-run `--demo` + tests after any change.