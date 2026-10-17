"""Build analysis-ready tables from raw CyberLab honeynet logs.

Two-stage architecture, with the sensitive stage kept out of git:

    data/raw/         (git-ignored)  compressed source, untouched
        |
        |  stage 1 - one day at a time: stream -> clean -> write parquet
        v
    data/interim/     (git-ignored)  FULL FIDELITY, STILL SENSITIVE
        |                             includes plaintext `password`,
        |                             attacker command text, hashed IPs
        |
        |  stage 2 - aggregate + redact
        v
    data/processed/   (committed)    aggregated and redacted only
                                     no plaintext passwords, no hashed IPs

Only stage 2 output may ever be committed. Stage 1 output is working data.

Memory strategy
---------------
Days are processed one at a time and each is written to disk before the next is
opened, so peak memory is bounded by the largest single day rather than by the
whole dataset. The combined file is then produced by streaming row groups from
the per-day files, which never materialises more than one batch at a time.

`category` dtype is a *RAM* optimisation, not a storage format - parquet already
dictionary-encodes. Per-day frames therefore have per-day category sets, so they
are converted back to plain values on write; otherwise the Arrow schemas would
not match and the files could not be streamed into one.

Derived fields
--------------
Two columns in this pipeline are *parsed*, not read, because the dataset has no
such fields:

  ``input``        cowrie.command.input events carry no `input` column. The
                   command text exists only inside `message`, behind a "CMD: "
                   prefix.
  ``tcpip_target`` cowrie.direct-tcpip.request events carry no target column.
                   The destination is only parseable out of `message`.

Attacker command text is untrusted and can contain arbitrary content, including
raw public IPs of malware servers. It is never published unless
``--publish-commands`` is passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import resource
import sys
import time
from collections import Counter
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from cowrie_io import day_from_name, iter_daily_files, iter_events

# --- parsing -----------------------------------------------------------------

CMD_PREFIX = "CMD: "
# "direct-tcp connection request to <sha256>:<port> from 127.0.0.1:1234"
TCPPIP_RE = re.compile(r"request to ([0-9a-f]{64}):(\d+)")
BYTES_LITERAL_RE = re.compile(r"^b'(.*)'$")

# Account-creation commands carry credentials as a quoted, newline-separated
# payload, e.g.  echo -e "user\npass\npass" | passwd  or  echo 'user:pass' | chpasswd
# 3,120 such commands appear in the sample. Group 2 is the opening quote and is
# backreferenced so the match ends on the *matching* quote.
COMMAND_CREDENTIAL_RE = re.compile(
    r"""(echo\s+(?:-e\s+)?)(["'])(?:\\.|(?!\2).)*\2(\s*\|\s*(?:ch)?passwd)""",
    re.IGNORECASE | re.DOTALL,
)
PASSWD_RE = re.compile(r"\b(?:ch)?passwd\b", re.IGNORECASE)


def password_digest(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def clean_client_version(value):
    """Strip the Python bytes-repr artefact: b'SSH-2.0-Go' -> SSH-2.0-Go."""
    if isinstance(value, str):
        match = BYTES_LITERAL_RE.match(value)
        if match:
            return match.group(1)
    return value


def extract_command(message: str):
    """Recover the command text. `input` does not exist as a field in this data.

    Only cowrie.command.input messages carry the "CMD: " prefix. Every other
    message returns None - falling back to the raw message would copy login
    attempts (plaintext passwords) and connection lines (hashed IPs) into
    `input`, and from there into the --publish-commands output.
    """
    if isinstance(message, str) and message.startswith(CMD_PREFIX):
        return message[len(CMD_PREFIX):]
    return None


def redact_command(command):
    """Redact credentials embedded in account-creation commands.

    Returns (redacted_command, embedded_credential). The boolean is kept so the
    behaviour stays analysable without the plaintext.
    """
    if not isinstance(command, str):
        return command, False
    redacted = COMMAND_CREDENTIAL_RE.sub(r'\1"[REDACTED]"\3', command)
    flagged = redacted != command or bool(PASSWD_RE.search(command))
    return redacted, flagged


def parse_tcpip(message: str):
    """(target_hash, port) from a direct-tcpip message, or (None, None)."""
    match = TCPPIP_RE.search(message or "")
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


# --- schema ------------------------------------------------------------------

INTERIM_COLUMNS = [
    # required by the spec
    "session_id", "src_ip_identifier", "dst_host_identifier", "sensor",
    "eventid", "timestamp", "username", "password", "hassh",
    "ssh_client_version", "input", "duration",
    # derived from direct-tcpip request messages (no such field exists)
    "tcpip_target", "tcpip_port",
    # additions
    "day", "geo_country", "geo_country_name", "embedded_credential",
]

CATEGORICAL = [
    "day", "eventid", "sensor", "ssh_client_version", "hassh",
    "geo_country", "geo_country_name", "embedded_credential",
]
STRINGY = [
    "session_id", "src_ip_identifier", "dst_host_identifier",
    "username", "password", "input", "tcpip_target",
]


def clean_event(event: dict, day: str) -> dict:
    message = event.get("message") or ""
    geo = event.get("geolocation_data") or {}
    target, port = parse_tcpip(message)
    command, embedded = redact_command(extract_command(message))

    return {
        "session_id": event.get("session_id"),
        "src_ip_identifier": event.get("src_ip_identifier"),
        "dst_host_identifier": event.get("dst_host_identifier"),
        "sensor": event.get("sensor"),
        "eventid": event.get("eventid"),
        "timestamp": event.get("timestamp"),
        "username": event.get("username"),
        "password": event.get("password"),
        "hassh": event.get("hassh"),
        "ssh_client_version": clean_client_version(event.get("ssh_client_version")),
        "input": command,
        "duration": event.get("duration"),
        "tcpip_target": target,
        "tcpip_port": port,
        "day": day,
        "geo_country": geo.get("country_code2"),
        "geo_country_name": geo.get("country_name"),
        "embedded_credential": embedded,
    }


# --- dtypes and memory -------------------------------------------------------

def apply_dtypes(frame: pd.DataFrame) -> pd.DataFrame:
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], format="ISO8601", utc=True)
    frame["duration"] = pd.to_numeric(frame["duration"], downcast="float")
    frame["tcpip_port"] = pd.to_numeric(frame["tcpip_port"]).astype("Int64")
    for column in CATEGORICAL:
        frame[column] = frame[column].astype("category")
    for column in STRINGY:
        frame[column] = frame[column].astype("string")
    return frame


def apply_categories(frame: pd.DataFrame) -> pd.DataFrame:
    """Re-apply categoricals after a concat, which silently degrades them."""
    for column in CATEGORICAL:
        if column in frame.columns:
            frame[column] = frame[column].astype("category")
    return frame


def for_storage(frame: pd.DataFrame) -> pd.DataFrame:
    """Convert categoricals back to plain values.

    Per-day frames have per-day category sets, so their Arrow schemas differ.
    Parquet dictionary-encodes on its own, so the RAM saving is not needed
    once the data is on disk.
    """
    out = frame.copy()
    for column in out.select_dtypes(include="category").columns:
        out[column] = out[column].astype(out[column].cat.categories.dtype)
    return out


def megabytes(frame: pd.DataFrame) -> float:
    return frame.memory_usage(deep=True).sum() / 1e6


def peak_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e6


# --- stage 1 -----------------------------------------------------------------

def build_day(path, out_path, limit_sessions=None) -> dict:
    day = day_from_name(path)
    started = time.perf_counter()

    records = []
    for event in iter_events(path, limit_sessions=limit_sessions):
        records.append(clean_event(event, day))

    frame = pd.DataFrame.from_records(records, columns=INTERIM_COLUMNS)
    del records
    before_mb = megabytes(frame)

    frame = apply_dtypes(frame)
    after_mb = megabytes(frame)

    for_storage(frame).to_parquet(out_path, index=False, compression="zstd")
    rows = len(frame)
    del frame

    return {
        "day": day, "rows": rows,
        "before_mb": before_mb, "after_mb": after_mb,
        "file_mb": out_path.stat().st_size / 1e6,
        "seconds": time.perf_counter() - started,
    }


def combine_day_files(day_files, out_path, batch_size=50_000) -> int:
    """Stream per-day parquet files into one, a batch at a time.

    Never holds more than `batch_size` rows in memory, which is what keeps the
    combined file affordable to produce.
    """
    writer = None
    rows = 0
    try:
        for day_file in day_files:
            parquet_file = pq.ParquetFile(day_file)
            for batch in parquet_file.iter_batches(batch_size=batch_size):
                table = pa.Table.from_batches([batch])
                if writer is None:
                    writer = pq.ParquetWriter(out_path, table.schema, compression="zstd")
                elif not table.schema.equals(writer.schema):
                    table = table.cast(writer.schema)
                writer.write_table(table)
                rows += batch.num_rows
    finally:
        if writer is not None:
            writer.close()
    return rows


# --- stage 3: sessions -------------------------------------------------------

def first_non_null(series):
    values = series.dropna()
    return values.iloc[0] if len(values) else pd.NA


def build_sessions(events: pd.DataFrame) -> pd.DataFrame:
    def count_event(name):
        return lambda s: (s == name).sum()

    sessions = events.groupby("session_id", observed=True, sort=False).agg(
        day=("day", "first"),
        sensor=("sensor", "first"),
        dst_host_identifier=("dst_host_identifier", "first"),
        src_ip_identifier=("src_ip_identifier", "first"),
        started_at=("timestamp", "min"),
        ended_at=("timestamp", "max"),
        n_events=("eventid", "size"),
        n_login_failed=("eventid", count_event("cowrie.login.failed")),
        n_login_success=("eventid", count_event("cowrie.login.success")),
        n_commands=("eventid", count_event("cowrie.command.input")),
        n_directtcpip=("eventid", count_event("cowrie.direct-tcpip.request")),
        ssh_client_version=("ssh_client_version", first_non_null),
        hassh=("hassh", first_non_null),
        geo_country=("geo_country", first_non_null),
    )

    closed = events[events["eventid"] == "cowrie.session.closed"]
    sessions["duration_seconds"] = closed.groupby(
        "session_id", observed=True)["duration"].max().reindex(sessions.index)

    targets = (events[events["tcpip_target"].notna()]
               .groupby("session_id", observed=True)["tcpip_target"].nunique())
    sessions["n_distinct_tcpip_targets"] = targets.reindex(sessions.index).fillna(0)

    sessions["has_login_success"] = sessions["n_login_success"] > 0
    return sessions.reset_index()


# --- stage 2: published tables ----------------------------------------------

def build_processed(interim, sessions, events_path, args):
    """Aggregated, redacted tables. No plaintext passwords, no hashed IPs."""
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = pd.read_parquet(events_path)
    totals = {}

    # Credential frequency, plaintext only at or above the threshold.
    logins = events[events["password"].notna()]
    counts = Counter()
    plain = {}
    for value in logins["password"]:
        digest = password_digest(value)
        counts[digest] += 1
        plain.setdefault(digest, value)

    # Publish only values attempted at or above the threshold, and drop the
    # SHA-256 column entirely. A hash of a weak password is recovered in
    # seconds with any wordlist, so publishing hashes alongside the frequency
    # would hand over precisely the withheld tail that the threshold exists to
    # protect.
    total_attempts = sum(counts.values())
    password_frequency = pd.DataFrame(
        [
            {
                "password": plain.get(digest, ""),
                "attempts": count,
                "pct_of_login_attempts": round(count / total_attempts * 100, 2),
            }
            for digest, count in counts.most_common()
            if count >= args.disclosure_threshold
        ],
        columns=["password", "attempts", "pct_of_login_attempts"],
    )
    password_frequency.to_csv(out / "password_frequency.csv", index=False)
    totals["password_frequency.csv"] = len(password_frequency)

    # Usernames are less sensitive than passwords, but the same disclosure
    # threshold is applied. Rare account names are the ones most likely to be
    # a real leaked credential rather than a generic default, so the tail is
    # withheld here too.
    username_total = int(events["username"].notna().sum())
    username = events[events["username"].notna()]["username"].value_counts()
    username = username[username >= args.disclosure_threshold]
    username.rename("attempts").to_frame().assign(
        pct=lambda d: (d["attempts"] / username_total * 100).round(2)
    ).to_csv(out / "username_frequency.csv")
    totals["username_frequency.csv"] = int(username.sum())

    eventid = events["eventid"].value_counts()
    eventid.rename("events").to_frame().assign(
        pct=lambda d: (d["events"] / len(events) * 100).round(2)
    ).to_csv(out / "event_summary.csv")
    totals["event_summary.csv"] = int(eventid.sum())

    sensor = sessions.groupby("sensor", observed=True).agg(
        sessions=("session_id", "size"),
        events=("n_events", "sum"),
        login_success_rate_pct=("has_login_success", lambda s: round(s.mean() * 100, 2)),
        median_duration_s=("duration_seconds", "median"),
    ).sort_values("events", ascending=False)
    sensor.to_csv(out / "sensor_summary.csv")
    totals["sensor_summary.csv"] = int(sensor["sessions"].sum())

    hassh = sessions.groupby("hassh", observed=True).agg(
        sessions=("session_id", "size"),
    ).sort_values("sessions", ascending=False)
    hassh["pct_of_sessions"] = (hassh["sessions"] / len(sessions) * 100).round(2)
    hassh.to_csv(out / "hassh_summary.csv")
    totals["hassh_summary.csv"] = int(hassh["sessions"].sum())

    # Relay targets are hashed IPs, so they are NOT published. Only the port
    # distribution and the concentration of the target set.
    tcpip = events[events["tcpip_port"].notna()]
    port = tcpip["tcpip_port"].value_counts()
    port.rename("requests").to_frame().assign(
        pct=lambda d: (d["requests"] / len(tcpip) * 100).round(2)
    ).to_csv(out / "tcpip_port_summary.csv")
    target_counts = tcpip["tcpip_target"].value_counts()
    totals["tcpip_port_summary.csv"] = len(tcpip)
    totals["_tcpip_distinct_targets"] = int(len(target_counts))
    totals["_tcpip_top5_share_pct"] = round(
        target_counts.head(5).sum() / len(tcpip) * 100, 2)

    summary = pd.DataFrame([{
        "sessions": len(sessions),
        "events": int(sessions["n_events"].sum()),
        "mean_events_per_session": round(sessions["n_events"].mean(), 2),
        "median_duration_s": sessions["duration_seconds"].median(),
        "login_success_rate_pct": round(sessions["has_login_success"].mean() * 100, 2),
        "sessions_with_relay": int((sessions["n_directtcpip"] > 0).sum()),
        "distinct_attackers": int(sessions["src_ip_identifier"].nunique()),
    }])
    summary.to_csv(out / "session_summary.csv", index=False)
    totals["session_summary.csv"] = len(sessions)

    # Attacker free text: untrusted, and may contain raw IPs. Off by default.
    if args.publish_commands:
        commands = events[events["input"].notna()]["input"].str.slice(0, 120)
        counts_cmd = commands.value_counts().rename("executions").to_frame()
        counts_cmd.to_csv(out / "command_summary.csv")
        totals["command_summary.csv"] = int(counts_cmd["executions"].sum())

    del events
    return totals, counts, plain, len(password_frequency)


# --- main --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--interim-dir", default="data/interim")
    parser.add_argument("--out-dir", default="data/processed")
    parser.add_argument(
        "--disclosure-threshold", type=int, default=50,
        help="Publish a value (password or username) in plaintext only if it "
             "was attempted at least this many times.")
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--limit-sessions", type=int, default=None)
    parser.add_argument("--publish-commands", action="store_true",
                        help="Publish attacker command text. Untrusted; off by default.")
    parser.add_argument("--expect-events", type=int, default=993_448)
    parser.add_argument("--expect-sessions", type=int, default=186_015)
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    interim = Path(args.interim_dir)
    processed = Path(args.out_dir)
    files = iter_daily_files(raw_dir)
    if not files:
        print(f"ERROR: no .json.gz files in {raw_dir}", file=sys.stderr)
        return 1
    interim.mkdir(parents=True, exist_ok=True)

    print(f"STAGE 1  raw -> interim  ({interim}/)   [git-ignored, SENSITIVE]\n")

    day_reports, day_files = [], []
    for path in files:
        out_path = interim / f"events_{day_from_name(path)}.parquet"
        report = build_day(path, out_path, limit_sessions=args.limit_sessions)
        day_files.append(out_path)
        day_reports.append(report)
        saved = (1 - report["after_mb"] / report["before_mb"]) * 100 if report["before_mb"] else 0
        print(f"  {report['day']}  {report['rows']:>8,} events"
              f"   object {report['before_mb']:>7,.0f} MB"
              f" -> category {report['after_mb']:>7,.0f} MB"
              f" (-{saved:4.1f}%)"
              f"   file {report['file_mb']:>6,.1f} MB"
              f"   {report['seconds']:5.1f}s")

    print(f"\n  memory after stage 1: {peak_mb():,.0f} MB peak")

    print(f"\nSTAGE 1b  combining {len(day_files)} day files by streaming row groups")
    combined = interim / "events.parquet"
    combined_rows = combine_day_files(day_files, combined, args.batch_size)
    print(f"  combined {combined_rows:,} rows"
          f"   {combined.stat().st_size / 1e6:,.1f} MB on disk"
          f"   {peak_mb():,.0f} MB peak memory")

    print(f"\nSTAGE 1c  sessions (per day, then concat)")
    frames = []
    for day_file in day_files:
        events = apply_categories(pd.read_parquet(day_file))
        frames.append(build_sessions(events))
        del events
    sessions = pd.concat(frames, ignore_index=True)
    del frames

    overlaps = int(sessions["session_id"].duplicated().sum())
    if overlaps:
        print(f"  WARNING: {overlaps:,} session_ids span multiple days; "
              f"per-day aggregation assumed they are disjoint.")
    else:
        print("  verified: session_ids are disjoint across days")

    sessions_path = interim / "sessions.parquet"
    for_storage(sessions).to_parquet(sessions_path, index=False, compression="zstd")
    print(f"  sessions {len(sessions):,}   {sessions_path.stat().st_size / 1e6:,.1f} MB"
          f"   {peak_mb():,.0f} MB peak")

    print(f"\nSTAGE 2  interim -> processed  ({processed}/)   [committed]")
    totals, pw_counts, _, pw_frequency_disclosed = build_processed(
        interim, sessions, combined, args)

    manifest = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_files": [f.name for f in files],
        "days": [r["day"] for r in day_reports],
        "events_rows": combined_rows,
        "sessions_rows": int(len(sessions)),
        "memory": {
            "per_day_object_mb": [round(r["before_mb"], 1) for r in day_reports],
            "per_day_category_mb": [round(r["after_mb"], 1) for r in day_reports],
            "peak_process_mb": round(peak_mb()),
        },
        "checks": {
            "expected_events": args.expect_events,
            "actual_events": combined_rows,
            "events_match": combined_rows == args.expect_events,
            "expected_sessions": args.expect_sessions,
            "actual_sessions": int(len(sessions)),
            "sessions_match": int(len(sessions)) == args.expect_sessions,
            "sessions_disjoint_across_days": overlaps == 0,
        },
        "redaction": {
            "password": f"only values attempted >= {args.disclosure_threshold} are "
                        f"published; the SHA-256 column is not published, because "
                        f"a hash of a weak password is wordlist-crackable",
            "username": f"same >= {args.disclosure_threshold} threshold applied",
            "distinct_passwords_seen": len(pw_counts),
            "distinct_passwords_published": int(pw_frequency_disclosed),
            "command_text": "credentials in echo|passwd and echo|chpasswd payloads "
                            "replaced with [REDACTED]; embedded_credential flag retained",
            "hashed_ips": "NOT published in data/processed",
            "attacker_command_text": ("published (redacted)" if args.publish_commands
                                      else "NOT published (pass --publish-commands)"),
        },
        "derived_fields": {
            "input": "parsed from message (no such field in the source data)",
            "tcpip_target": "parsed from message (no such field in the source data)",
        },
        "outputs": totals,
    }
    (processed / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print("\n" + "=" * 68)
    print(f"  events   {combined_rows:>10,}   expected {args.expect_events:>10,}")
    print(f"  sessions {len(sessions):>10,}   expected {args.expect_sessions:>10,}")
    print(f"  peak memory {peak_mb():,.0f} MB")
    print("=" * 68)

    failures = []
    if args.expect_events and combined_rows != args.expect_events:
        failures.append(f"events {combined_rows:,} != expected {args.expect_events:,}")
    if args.expect_sessions and len(sessions) != args.expect_sessions:
        failures.append(f"sessions {len(sessions):,} != expected {args.expect_sessions:,}")

    if failures:
        print("\nFAILED INTEGRITY CHECK:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("integrity checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())