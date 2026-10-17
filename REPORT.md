# Pipeline output report

What `scripts/build_dataset.py` and the two analysis notebooks produce, and how to
read the numbers. Every figure below comes from the run recorded in
`data/processed/manifest.json` (generated 2026-10-17) and from the saved notebook
outputs.

> **Scope reminder.** Three days only — 2020-02-24, 2020-02-28, 2020-02-29 — from
> a dataset that spans ~10 months. These are descriptive counts for those three
> days, not trends. See the limitations in [README.md](README.md).

---

## 1. Did the pipeline run correctly?

Yes. The integrity checks in the manifest all pass:

| Check | Expected | Actual | Result |
|---|---:|---:|---|
| Events | 993,448 | 993,448 | ✅ match |
| Sessions | 186,015 | 186,015 | ✅ match |
| Session IDs unique across days | — | no overlaps | ✅ disjoint |

"Disjoint across days" matters because sessions are built one day at a time and
then concatenated. If a session had spanned midnight it would have been counted
twice; it didn't.

### Memory

| Day | As plain objects | As `category` dtype | Saving |
|---|---:|---:|---:|
| 2020-02-24 | 221.9 MB | 141.5 MB | −36% |
| 2020-02-28 | 309.4 MB | 195.0 MB | −37% |
| 2020-02-29 | 325.1 MB | 205.0 MB | −37% |

Peak process memory was **~1.1 GB**. Because days are processed one at a time and
the combined file is streamed in batches, peak memory is set by the largest single
day, not by the whole dataset — which is what lets the same script scale to the
full ~10 GB release.

---

## 2. What the pipeline writes

| Location | In git? | Contents |
|---|---|---|
| `data/raw/` | ignored | The original `cyberlab_*.json.gz` files, untouched |
| `data/interim/` | ignored — **sensitive** | `events_<day>.parquet`, `events.parquet` (all days), `sessions.parquet`. Full fidelity: plaintext passwords, attacker command text, hashed IPs |
| `data/processed/` | committed | Aggregated, redacted CSVs + `manifest.json` |

The notebooks read `data/interim/`; anything meant to be shared comes from
`data/processed/`.

### Redaction applied to `data/processed/`

- **Passwords:** only values tried **≥ 50 times** are published — **711 of 10,905**
  distinct passwords. No hashes are published, because a SHA-256 of a weak
  password is cracked instantly with a wordlist, which would leak the withheld
  tail.
- **Usernames:** same ≥ 50 threshold.
- **Attacker IPs / relay targets:** never published, not even hashed.
- **Attacker command text:** not published (needs `--publish-commands`).
  Credentials embedded in `echo … | passwd` / `chpasswd` commands are replaced
  with `[REDACTED]` even in the interim data.

---

## 3. Headline numbers (`session_summary.csv`)

| Metric | Value |
|---|---:|
| Sessions | 186,015 |
| Events | 993,448 |
| Events per session (mean) | 5.34 |
| Session duration (median) | 3.3 s |
| Sessions with a successful login | 6.69% |
| Sessions that requested a relay (direct-tcpip) | 1,155 |
| Distinct attackers (hashed source IPs) | 5,471 |

**How to read it:** the typical session is a bot that connects, tries a
credential or two, and leaves within a few seconds. Only about 1 in 15 sessions
gets in.

---

## 4. What attackers did (`event_summary.csv`)

| Event | Count | Share |
|---|---:|---:|
| `cowrie.login.failed` | 228,432 | 22.99% |
| `cowrie.session.connect` | 186,015 | 18.72% |
| `cowrie.session.closed` | 175,894 | 17.71% |
| `cowrie.client.version` | 167,785 | 16.89% |
| `cowrie.client.kex` | 158,544 | 15.96% |
| `cowrie.command.input` | 30,921 | 3.11% |
| `cowrie.log.closed` | 26,989 | 2.72% |
| `cowrie.login.success` | 12,449 | 1.25% |
| `cowrie.direct-tcpip.request` | 6,027 | 0.61% |
| `cowrie.client.fingerprint` | 392 | 0.04% |

- **Every session has a `connect`** (186,015 = number of sessions) — a useful sanity
  check.
- **~10,100 sessions have no `closed` event** (186,015 − 175,894). Likely sessions
  still open when a daily file was cut, or dropped connections; worth checking
  before using `duration` for those sessions.
- **Failed logins outnumber successes ~18 : 1.** This is the credential-guessing
  noise that dominates any SSH honeypot.
- **Commands (3.1%) and relay requests (0.6%)** are the rare, interesting
  post-login activity — the focus of `02_analysis.ipynb`.

---

## 5. Credentials

### Passwords (`password_frequency.csv`, 711 published values)

The top of the list is exactly the default/weak passwords you'd expect:
`123456` (4.71% of all attempts), `admin` (2.88%), `password` (1.96%),
`password123`, `123`, `1234`, `12345`, `qwerty`. An **empty password** is the 9th
most common (0.90%).

### Usernames (`username_frequency.csv`)

| Username | Share of attempts |
|---|---:|
| `root` | 58.94% |
| `admin` | 5.29% |
| `nproc` | 0.63% |
| `test`, `ubuntu`, `user`, `oracle`, `postgres`, `git`, … | < 0.5% each |

`root` alone is more than half of all attempts. Service-account names (`oracle`,
`postgres`, `mysql`, `git`, `ftpuser`) and device defaults (`pi`, `ubuntu`) make
up the long tail.

`nproc` appearing 1,516 times as **both** username and password is an oddity: it
is a Linux command, not a credential, which suggests a broken or misconfigured
bot sending command output where credentials should be.

---

## 6. Sensors (`sensor_summary.csv`)

| Sensor | Sessions | Login success | Median duration |
|---|---:|---:|---:|
| `ubuntu_basic_pool` | 155,874 | 5.25% | 3.6 s |
| `prod-ubuntu-ssh-k8s-local-4` | 8,049 | 13.12% | 2.5 s |
| `prod-ubuntu-ssh-k8s-local-3` | 7,940 | 13.83% | 3.0 s |
| `prod-ubuntu-ssh-k8s-local-1` | 7,794 | 13.72% | 3.1 s |
| `prod-ubuntu-ssh-k8s-local-2` | 6,358 | 16.36% | 3.1 s |

`ubuntu_basic_pool` receives **84%** of sessions but has a login success rate
**less than half** that of the four `k8s` nodes. That is most likely a difference
in honeypot configuration (which credentials each mode accepts), not a difference
in attackers — so **don't compare raw rates across the two groups** without
accounting for it.

---

## 7. SSH client fingerprints (`hassh_summary.csv`)

HASSH fingerprints the SSH client implementation from its key-exchange offer, so
it identifies the *tool*, not the attacker.

- 57 distinct fingerprints across the 158,543 sessions that completed key
  exchange.
- Among those sessions, the top **two** fingerprints cover **84.2%** and the top
  five cover **95.1%**.
- Note that `pct_of_sessions` in the CSV is out of *all* 186,015 sessions
  (47.21% and 24.55% for the top two), including the ~27,500 that never reached
  key exchange.

In other words, the traffic is dominated by a handful of mass-scanning tools.

---

## 8. Relay abuse — MITRE ATT&CK T1090 (`tcpip_port_summary.csv` + `02_analysis.ipynb`)

A `direct-tcpip.request` is an attacker asking the honeypot to **forward a
connection onward** — using it as a proxy so the traffic appears to come from the
honeypot.

### Ports requested

| Port | Requests | Share | Typical use |
|---|---:|---:|---|
| 80 | 5,494 | 91.16% | HTTP — web traffic, ad/click fraud, scraping |
| 25 | 522 | 8.66% | SMTP — sending spam |
| 443 | 10 | 0.17% | HTTPS |
| 587 | 1 | 0.02% | SMTP submission |

### Who relays, and how much

| Metric | Value |
|---|---:|
| Relay requests | 6,027 |
| Relay sessions | 1,155 (0.62% of sessions) |
| Relaying attackers | 60 (1.10% of attackers) |
| Distinct targets | 247 |
| Top 5 targets' share of requests | 49.0% |
| Top attacker's share of requests | 31.7% |
| Top 5 attackers' share | 86.6% |
| Relay sessions with a successful login | **100%** |
| Relay sessions that also ran commands | **0** |

**How to read it:**

- Relaying is **rare but highly concentrated**: 60 attackers, and five of them
  account for almost 87% of all relay requests. Half the requests go to just five
  destinations.
- **Every relay session logged in, and none ran a single command.** These clients
  are not exploring the box — they authenticate and immediately use it as a
  tunnel. That is a distinct behaviour from the attackers who log in and run
  commands (1,883 sessions, zero overlap).
- Relaying was steady across the three days (1,936 / 1,971 / 2,120 requests).

---

## 9. Caveats

- Three days, end of the collection period — no trends or seasonality.
- Two different honeypot configurations are mixed (Section 6).
- "Attackers" means distinct hashed source IPs. One actor can use many IPs, and
  NAT can put many actors behind one.
- `input` (command text) and `tcpip_target` are **parsed from the `message`
  field** — the source data has no such columns.

---

## 10. Reproducing these numbers

```bash
python scripts/build_dataset.py
```

Then open `analysis/01_explore.ipynb` and `analysis/02_analysis.ipynb` in VS Code
with the conda `base` kernel and **Run All**. The script exits with
`integrity checks passed.` if the event and session counts match the expected
values above.
