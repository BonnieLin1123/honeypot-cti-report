# SSH Honeypot CTI — CyberLab dataset analysis

A data-science and threat-intelligence study of real-world SSH attack behaviour,
built on the **CyberLab honeynet dataset**: Cowrie honeypot telemetry collected
from ~50 university and corporate nodes between May 2019 and February 2020.

**Status:** exploration in progress. Nothing here is a finding yet.

---

## Why this dataset

Running a live honeypot is a strong project, but the interesting part of
honeypot research is not the deployment — it is the *analysis*. Analysing a
large, real honeypot dataset lets the whole effort go into data work: parsing,
cleaning, feature engineering, statistics, and communication of results. It
also removes every operational risk of standing up an internet-facing box.

## Dataset

| | |
|---|---|
| **Name** | CyberLab honeynet dataset |
| **Record** | [Zenodo 3687527](https://zenodo.org/records/3687527) |
| **DOI** | 10.5281/zenodo.3687527 |
| **Authors** | Urban Sedlar, Matej Kren, Leon Štefanič Južnič, Mojca Volk |
| **Affiliation** | University of Ljubljana, Faculty of Electrical Engineering |
| **Published** | 2020-02-29 |
| **Honeypot** | Cowrie (1.6.0, upgraded to 2.0.2 on 2019-11-08) |
| **Full range** | May 2019 – Feb 2020, ~290 daily files, ~10 GB compressed |
| **Licence** | As stated on the Zenodo record — check before redistributing |

### Scope — what is actually analysed here

This repository analyses **3 days only**: **2020-02-24, 2020-02-28, 2020-02-29**
— **186,015 sessions and 993,448 events**, roughly 1.4 GB decompressed.

Four limitations are stated up front rather than buried, because they constrain
every conclusion:

1. **Three days is not the full range.** The dataset spans ~10 months; this
   sample covers three days at its very end. No seasonality or trend claim is
   supported.
2. **Mixed sensor configurations.** These three days are *not* a single
   experiment configuration. The `sensor` field splits them like this:

   | `sensor` | 2020-02-24 | 2020-02-28 | 2020-02-29 |
   |---|---:|---:|---:|
   | `ubuntu_basic_pool` | 89.05% | 81.06% | 80.36% |
   | `prod-ubuntu-ssh-k8s-local-1` | 2.52% | 4.63% | 5.50% |
   | `prod-ubuntu-ssh-k8s-local-2` | 2.43% | 4.43% | 3.75% |
   | `prod-ubuntu-ssh-k8s-local-3` | 4.05% | 4.83% | 4.53% |
   | `prod-ubuntu-ssh-k8s-local-4` | 1.95% | 5.04% | 5.86% |

   `ubuntu_basic_pool` is the high-interaction mode enabled when the fleet moved
   from Cowrie 1.6.0 to 2.0.2 on 2019-11-08, backed by a pool of real Linux
   instances. The four `prod-ubuntu-ssh-k8s-local-*` nodes are a separate
   configuration. **Any comparison across the two has to account for this
   split**, because the honeypot mode changes what an attacker can observe and
   do — so a difference in `eventid` mix between sensors is not automatically a
   difference in attacker behaviour.
3. **No pre-upgrade data.** All three days fall after 2019-11-08, so this sample
   cannot speak to Cowrie 1.6.0 behaviour at all.
4. **Node count varied.** "~50 nodes" is the peak of the experiment, not a
   constant. Five distinct `sensor` values appear in these three files alone.

### Citation

If this work is reused, cite the dataset rather than this repository:

> Sedlar, U., Kren, M., Štefanič Južnič, L., & Volk, M. (2020).
> *CyberLab honeynet dataset* [Data set]. Zenodo.
> https://doi.org/10.5281/zenodo.3687527

---

## Repository layout

```
honeypot-cti-report/
├── analysis/          # Jupyter notebooks
│   └── 01_explore.ipynb     # format, schema, event inventory
├── data/
│   ├── raw/           # Zenodo files as downloaded — GIT-IGNORED, never committed
│   └── processed/     # derived + sanitized outputs — to be created
├── .gitignore
├── LICENSE            # Apache-2.0, covers the code in this repo
└── README.md
```

`data/raw/` is ignored because it is large and because raw honeypot traffic
contains attacker-supplied data. Only *derived and sanitized* outputs are
committed.

---

## Safety and privacy rules

These are project constraints, not suggestions.

- **Never open, execute, or analyse attacker-uploaded files.** The `data` field
  in the logs can hold file contents. The loader in `01_explore.ipynb` drops
  this field by default so it cannot be read by accident.
- **Never commit raw logs**, private keys, or credentials.
- **Attacker IPs are already pseudonymized** by the dataset authors (SHA-256
  hashes). They stay hashed. Note that hashing an IPv4 is trivially reversible
  by brute force, so treat these as personal data under GDPR regardless.
- **`username` and `password` are plaintext** attacker-typed credentials — real
  passwords harvested from botnet credential lists. They must be redacted before
  anything is published.
- **Never run code retrieved from attacker infrastructure.** Hash only.

---

## Getting started

Requires Python 3.11+ and pandas. Jupyter is not yet installed:

```bash
# create an environment
python3 -m venv .venv && source .venv/bin/activate
pip install pandas jupyterlab

# then
jupyter lab
```

Open `analysis/01_explore.ipynb` and run all cells.

## Current notebooks

| Notebook | Purpose |
|---|---|
| `01_explore.ipynb` | Establish what the data is: format, compression, loading strategy, full field reference, event inventory |

---

## Roadmap

1. **Explore** — format, schema, event types. *(in progress)*
2. **Ingest all three days** — parse `timestamp` to real datetimes, clean the
   `b'...'` bytes artefact in `ssh_client_version`, handle empty
   `geolocation_data`, select a lean column set.
3. **Build a reproducible pipeline** — raw JSON to tidy tables in
   `data/processed/`, runnable end to end, no manual steps.
4. **Analyse** — credential-stuffing patterns and dictionary structure, HASSH
   clustering for malware families, session-duration and interaction-depth
   distribution, geographic origin, post-login command sequences.

   *Not* file-download indicators: `url`, `filename`, `outfile` and `destfile`
   are 100% null across all three days, so there are no attacker file downloads
   in this sample to analyse. `shasum` must not be used as a substitute — on
   these days it identifies session-log files rather than malware.
5. **Sanitize** — an automated redaction step so no plaintext credential can
   reach a public output.
6. **Report** — findings, charts, and limitations in a written CTI report.

Steps 4 and 6 are constrained by the three-day sample. Where the sample is too
thin to support a claim, the report will say so rather than overstate it.

---

## Licence

Code in this repository is licensed under **Apache-2.0** (see `LICENSE`). The
CyberLab dataset is **not** covered by this licence — see the Zenodo record for
its terms.