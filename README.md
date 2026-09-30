# Mini SIEM: Security Log Monitoring Dashboard

A local learning project that parses uploaded text logs, stores events in SQLite,
and applies SQL and Python rules to display possible security incidents.

## What it implements

| Rule | Current threshold |
| --- | --- |
| Brute-force login | At least 5 failed logins from one IP against one username in a calendar-minute bucket |
| Password spraying | At least 6 failed logins involving at least 4 distinct usernames (or raw log lines when a username is missing) from one IP in a calendar minute |
| Suspicious IP | At least 8 events and a failure ratio of at least 70% across the stored events for an IP |
| High request rate | At least 30 parsed web-request events from an IP in a calendar minute |
| Simulated impossible travel | Successive successful logins for a username imply more than 900 km/h using illustrative region labels and fixed distances |

The travel rule is a demonstration: IP regions are guessed from the first IPv4
octet, not obtained from a geolocation database. It cannot establish real travel
or confirm an attack. All alerts need human review.

## Run locally

Use Python 3.10 or newer.

```bash
git clone https://github.com/Advaith-Ganesh/mini-siem-security-monitor.git
cd mini-siem-security-monitor
python -m venv .venv
```

Activate the environment:

- macOS / Linux: `source .venv/bin/activate`
- Windows PowerShell: `.venv\Scripts\Activate.ps1`

```bash
python -m pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000/**. The database is created on the first direct run.
Upload `sample_logs.txt` or use the dashboard's demo-data action. The seven-line
sample is useful for parsing but does not meet every detection threshold.

## Project structure

| File | Purpose |
| --- | --- |
| `app.py` | Flask routes, parsers, SQLite access, detection rules |
| `dashboard.html` | Jinja dashboard; Flask is configured to load it from the repository root |
| `schema.sql` | Events and alerts tables |
| `sample_logs.txt` | Small example upload |
| `requirements.txt` | Flask dependency |

## Limitations

- Minute buckets are fixed calendar minutes, not rolling windows; events across
  a minute boundary can evade the current thresholds.
- A missing or unrecognised timestamp falls back to ingestion time. Timezone
  offsets are not preserved.
- Geography and travel distances are illustrative, not actual geolocation.
- The parser uses broad text rules: `status=200`, `status=401`, and
  `status=403` are classified as login events, including on web-request lines.
  Consequently, the current demo's `GET ... status=200` lines do not exercise
  the high-request-rate rule.
- Re-uploading the same file inserts duplicate events.
- CI smoke-checks dashboard rendering and sample-log uploads. Detection rules
  do not yet have dedicated unit tests.
- The development server has debug mode enabled and a fixed demo session key.
  Seed/reset routes change data through GET requests; authentication and CSRF
  protection are absent. Run it locally with sample data.

## Next improvements

1. Add parser and detection tests, especially minute boundaries and HTTP logs.
2. Separate authentication logs from access logs before applying detection rules.
3. Replace simulated regions with a documented geolocation source or remove the travel rule.
4. Add rolling time windows and duplicate-ingestion handling.
5. Add authentication and protected POST actions before any public deployment.
