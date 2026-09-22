# IOC Checker — Threat Intelligence Aggregator CLI

A single-command CLI tool for SOC analysts and threat hunters. Give it any
indicator of compromise (IP, domain, URL, or hash) and it queries multiple
threat intelligence providers concurrently, then rolls the results up into
one risk score and verdict.

```
python ioc_checker.py 8.8.8.8
```

## Providers

Providers are queried dynamically based on the detected IOC type — only
providers that actually support that type are queried and shown.

| Provider        | Env Variable              | Key required | Supported IOC Types                  |
|-----------------|----------------------------|--------------|----------------------------------------|
| VirusTotal (v3) | `VT_API_KEY`               | Yes          | IPv4, Domain, URL, MD5, SHA1, SHA256   |
| AlienVault OTX  | `OTX_API_KEY`               | Yes          | IPv4, Domain, URL, MD5, SHA1, SHA256   |
| ThreatFox       | `THREATFOX_API_KEY`         | Yes          | IPv4, Domain, URL, MD5, SHA1, SHA256   |
| AbuseIPDB       | `ABUSEIPDB_API_KEY`         | Yes          | IPv4 only                              |
| URLhaus         | `URLHAUS_API_KEY`           | No (public)  | URL only                               |
| MalwareBazaar   | `MALWAREBAZAAR_API_KEY`     | No (public)  | MD5, SHA1, SHA256                      |

Provider selection is driven entirely by each provider's own
`SUPPORTED_TYPES` declaration (see `providers/manager.py`) — there are no
hardcoded if/else chains deciding which provider runs for which IOC type.
To add a new provider: create `providers/<name>.py` implementing
`BaseProvider`, add its key to `config.py`, and register it in
`providers/manager.py`.

> Note: abuse.ch (URLhaus, MalwareBazaar, ThreatFox) now requires an
> Auth-Key for most endpoints, even ones historically documented as fully
> public. If you see `403 Forbidden` from these providers, add an
> abuse.ch Auth-Key to the relevant `.env` entry.

## Supported IOC Types

Type is auto-detected — you never specify it:

- IPv4
- Domain
- URL
- MD5 / SHA1 / SHA256 file hashes

## Installation

```bash
git clone <this-repo>
cd ioc_checker
pip install -r requirements.txt
cp .env.example .env
# then edit .env and add your API keys
```

## Usage

### Direct IOC lookup

```bash
python ioc_checker.py 8.8.8.8
python ioc_checker.py google.com
python ioc_checker.py https://evil.com/login
python ioc_checker.py 44d88612fea8a8f36de82e1278abb02f
```

Sample output includes:

1. ASCII banner + version
2. IOC info panel (value, detected type, length, timestamp)
3. Transient progress spinner while providers are queried concurrently
   (cleared automatically once scanning finishes)
4. Results table (per-provider verdict, confidence, and details)
5. Overall Assessment panel (risk score, sources queried/matched, recommendation)
6. API warnings section - only appears if one or more providers failed
   during this scan (replaces the old always-on API status table)
7. Footer (execution time, providers used)

### File reputation (`-f` / `--file`)

```bash
python ioc_checker.py -f malware.exe
```

Calculates the file's MD5, SHA1, and SHA256 locally, displays all three,
then runs the SHA256 through the normal hash lookup pipeline (identical
to passing that SHA256 directly on the command line). Only the SHA256 is
ever sent to a provider.

### Artifact analysis (`-a` / `--artifact`)

```bash
python ioc_checker.py -a capture.pcap
python ioc_checker.py -a network.log
python ioc_checker.py -a indicators.csv
python ioc_checker.py -a file.txt
```

A completely different feature from `-f/--file`: instead of hashing one
file, `-a/--artifact` extracts **every** IOC found *inside* the file
(IPv4, Domain, URL, MD5, SHA1, SHA256), then:

1. Normalizes and deduplicates them (case, trailing dots, leading zeros, etc.)
2. Counts how many times each one actually occurred
3. Filters out internal/private IPv4 addresses (never sent to external providers)
4. Looks up only the external IOCs, once each, against every provider that
   supports that IOC type
5. Classifies each one (`CLEAN` / `SUSPICIOUS` / `MALICIOUS` / `MALICIOUS (HIGH RISK)`)
   based on how many providers flagged it
6. Prints a summary panel, then a single sorted IOC report table (most
   interesting indicators first)

Supported artifact types: **TXT, LOG, CSV, PCAP, PCAPNG** (PCAP/PCAPNG are
detected by file signature, so they're recognized correctly even with the
wrong extension). Results are cached locally (`ioc_cache.db`, 6-hour TTL
by default - see `IOC_CACHE_DB_PATH` / `IOC_CACHE_TTL_SECONDS` in
`.env`), so re-analyzing the same artifact - or artifacts that share
IOCs - doesn't repeat API calls unnecessarily.

`-a/--artifact` is mutually exclusive with a positional IOC and with
`-f/--file` - use exactly one per run.

## API Health / Warnings

There is no longer a persistent "API Status" table shown on every run. If
every queried provider succeeds, nothing extra is printed. If a provider
fails (missing/invalid key, rate limit, timeout, unexpected response), a
compact `⚠ API WARNINGS` panel appears after the Overall Assessment,
listing only the providers that actually failed and why. Identical
failures are collapsed with an `(xN)` count, which matters most for
artifact analysis where the same provider issue (e.g. a missing key)
would otherwise repeat once per IOC.

## Risk Scoring

| Signal                        | Points |
|--------------------------------|--------|
| VirusTotal malicious            | +40    |
| VirusTotal suspicious            | +20    |
| AlienVault OTX has pulses        | +30    |
| ThreatFox has a match             | +30    |
| AbuseIPDB score ≥ 75              | +40    |
| AbuseIPDB score 25–74               | +20    |
| URLhaus URL online                  | +30    |
| URLhaus URL offline                   | +15    |
| MalwareBazaar has a match               | +30    |

| Score range | Overall Assessment |
|-------------|----------------------|
| 0–20        | CLEAN                |
| 21–50       | SUSPICIOUS           |
| 51–100      | HIGH RISK            |

## Project Layout

```
ioc_checker/
├── ioc_checker.py        # CLI entry point (direct IOC, -f/--file, -a/--artifact)
├── artifact_pipeline.py  # Orchestrates the full artifact analysis pipeline
├── lookup.py             # Shared provider-lookup wrapper + IOC-type -> method map
├── config.py             # .env / API key + cache settings
├── detector.py           # Single-IOC type detection
├── utils.py              # Logging + unified ProviderResult/Verdict types + file hashing
├── ui.py                 # Rich-based presentation layer (all output)
├── requirements.txt
├── requirements-dev.txt  # pytest (test-only, not needed to run the CLI)
├── .env.example
│
├── providers/
│   ├── __init__.py        # BaseProvider interface (+ SUPPORTED_TYPES)
│   ├── manager.py         # Provider registry / dynamic selection by IOC type
│   ├── virustotal.py
│   ├── otx.py
│   ├── threatfox.py
│   ├── abuseipdb.py
│   ├── urlhaus.py
│   └── malwarebazaar.py
│
├── artifacts/              # Artifact extraction (discovery only, no lookups)
│   ├── base.py              # RawIOC model + ArtifactExtractor interface
│   ├── detector.py          # Artifact type detection (signature + extension)
│   ├── _scan.py              # Shared regex-based IOC scanning core
│   ├── text.py                # .txt
│   ├── log.py                  # .log (reuses TextExtractor)
│   ├── csv_extractor.py         # .csv (schema-agnostic, scans every cell)
│   └── pcap.py                   # .pcap/.pcapng (via dpkt)
│
├── ioc/                    # Normalization, aggregation, classification
│   ├── models.py             # AggregatedIOC, IOCReportRow
│   ├── normalizer.py          # Canonicalization rules per IOC type
│   ├── aggregator.py           # Dedup + occurrence counting + internal IPv4 flagging
│   └── classifier.py            # Provider-hit-count -> classification tiers
│
├── cache/
│   └── cache.py            # SQLite TTL cache for provider lookup results
│
└── tests/
    ├── test_extraction.py
    ├── test_normalization.py
    ├── test_aggregation.py
    ├── test_classification.py
    ├── test_artifact_detector.py
    ├── test_csv_extractor.py
    └── test_cache.py
```

## Error Handling

If a provider fails (bad key, timeout, rate limit, unexpected response), its
row simply shows `ERROR` with a short reason — the scan continues for the
remaining providers and the tool never crashes.

For `-a/--artifact`: a missing file, an empty file, an unsupported artifact
type, or a corrupted/truncated PCAP all produce a clear error panel instead
of a traceback. A single malformed packet inside an otherwise-valid PCAP is
skipped, not fatal - the rest of the capture is still analyzed.

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Covers IOC extraction (IPv4/Domain/URL/MD5/SHA1/SHA256 - intentionally
excluding IPv6), normalization, deduplication/occurrence counting,
internal-IPv4 filtering, classification tiers, artifact type detection,
CSV extraction, and the SQLite cache's TTL behavior.

## Logging

All requests and errors are logged to `ioc_checker.log` in the working
directory.
