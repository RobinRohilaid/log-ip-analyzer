# Log IP Analyzer

A small Python command-line project from my TalTech scripting coursework. It extracts valid IPv4 addresses from a text log, counts repeated occurrences, and filters them by a configurable threshold.

## What it demonstrates

- Command-line arguments with `argparse`.
- Regular expressions followed by validation with `ipaddress`.
- Frequency counting with `collections.Counter`.
- An offline preview and optional HTTP API calls with error handling.
- JSON output when the online lookup mode is used.

## Run the offline example

Python 3 and the `requests` dependency are required to run the application. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe src/skript.py examples/auth.log --threshold 2 --dry-run
```

The example uses synthetic addresses. Expected result:

```text
Found 1 suspicious IP addresses (occurring >= 2 times).
[DRY-RUN] IP: 192.0.2.10 | Occurrences: 2
```

The word “suspicious” in the program means an address met the frequency threshold. It does not establish malicious activity.

## Arguments and output

| Argument | Meaning |
| --- | --- |
| `file_path` | UTF-8 log file to inspect |
| `--threshold N` | Minimum occurrence count, inclusive; default `5` |
| `--dry-run` | Skip external lookups and print results; no report file is written |

Without `--dry-run`, the script sends each selected address to `http://ip-api.com/json/<ip>` and writes `threat_report.json` in the current working directory. Report fields are `ip`, `count`, and `country`. Use the offline mode for sensitive logs: the optional lookup transmits addresses over HTTP.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The seven tests use temporary files and an HTTP stub. They check validation, duplicate counting, the threshold boundary, empty and missing input, default arguments, and the absence of report writes in offline mode. The test suite needs only the Python standard library and never contacts an external API.

## Scope and limitations

This is a coursework utility, not an intrusion detection system. It recognizes IPv4 addresses only, reads the complete input into memory, and treats frequency as a simple signal. Live API availability, rate limits, and country accuracy are outside the offline tests. The dependency is currently unpinned, as in the original coursework.

Author: Robin Rohilaid. See [ORIGIN.md](ORIGIN.md) for the coursework source and recorded AI assistance.
