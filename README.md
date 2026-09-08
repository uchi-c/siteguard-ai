# SiteGuard AI

A free, AI-narrated website security scanner used as a lead magnet: a
prospect enters their URL, gets a real scan with a plain-English AI summary
and a graded report (A-F), then leaves their email for a "fix plan" — which
is your opening to sell remediation or ongoing monitoring work.

This is a working product, not a mockup. Every check is real and passive
(HTTP headers, TLS/certificate state, exposed sensitive files, cookie flags,
SPF/DMARC email-spoofing protection, mixed content, outdated JS libraries).
The AI layer (Claude) turns raw findings into a report a non-technical
business owner will actually read.

Every finding is labeled with the **OWASP Top 10 (2021)** category it maps
to, linked to OWASP's own page for that category -- SiteGuard's own
classification (OWASP doesn't publish a finding-to-category lookup table),
but grounded in the standard taxonomy rather than an invented one. The
scanner also passively fingerprints known **WAF/CDN** services (Cloudflare,
Akamai, Sucuri, Incapsula, CloudFront, Fastly) from the same response
headers it already fetches -- informational only, doesn't affect the grade.

The report page also doubles as an **outbound prospecting tool**: a "Draft
an outreach message" button turns the scan's top finding into a short,
copy-pasteable cold-outreach opener ("I ran a free security scan on
yourbusiness.com and noticed...") — useful when you're the one scanning a
prospect's site rather than waiting for them to find yours.

Every scan is saved and gets a **shareable link** (`/report/<id>`) shown on
the report page, so you can send someone the actual report instead of a
screenshot — e.g. as the "here's what a secure setup looks like" proof
mentioned below.

For working a whole prospect list at once, **`/batch`** (linked from the
homepage) takes up to 8 URLs, one per line, and scans them in the
background — each one gets a report link and a drafted outreach message,
shown as they finish on a page that polls for progress.

**`/admin`** is a password-gated view of every lead and recent scan, so you
don't have to download `leads.csv` off the server to see who's converted.
Set `ADMIN_PASSWORD` in `.env` to enable it — it's off (login fails
outright) until you do.

### Active vulnerability testing (`/admin/active-scan`) — off by default, read this first

Everything above is passive (a normal browser visit generates the same
traffic). This is not: it's a **gated, admin-only mode** that sends real,
non-destructive *detection* probes for seven vulnerability classes —
reflected XSS, error-based SQL injection, server-side template injection,
path traversal, OS command injection (a harmless `echo` only), open
redirect, and up to 3 well-known default-credential attempts against any
login form found. It does not extract, modify, or exfiltrate data beyond
the minimum needed to confirm each class exists (e.g. traversal reads
`/etc/passwd`/`win.ini` — standard non-sensitive confirmation files, never
`/etc/shadow` or anything requiring elevated access), but it is still
active testing, and **running it against a site you don't have explicit
authorization to test is a criminal offense in most jurisdictions** (e.g.
the US Computer Fraud and Abuse Act), regardless of intent.

Detection is discovery-then-probe: it crawls the target's homepage for GET
forms and same-origin links, prioritizing form inputs (a search box, a
filter) over incidental query-string links, and filtering out static-asset
links (`?ver=1.2.3` cache-busters on `.css`/`.js`/images/fonts) entirely —
those are never real inputs and would otherwise crowd out the handful of
parameters actually worth testing on a busy page.

That crawl is a plain regex parse of the raw HTML response, so it finds
nothing on a React/Vue/Next.js-style site whose real forms only exist after
client-side JS runs — a real gap, not a bug, first noticed scanning
[uruu.enterprises](https://uruu.enterprises) itself (0 forms, 0
query-string links in the raw HTML, even though the real signup form is
right there once the page renders). When the raw-HTML crawl finds nothing
at all, discovery falls back to rendering the page in headless Chromium
(`js_discovery.py`) before giving up. That fallback runs as its own
subprocess (`js_discovery_worker.py`), not a thread in the main app, so a
browser crash or timeout can't take the site down with it — any failure
there (Playwright/Chromium not installed, launch failure, timeout) just
means "found nothing," same as before this existed. Turn it off with
`ACTIVE_SCAN_JS_DISCOVERY=0` if headless Chromium turns out to be too much
for the host's memory budget on top of everything else already running.

With up to 6 checks run against every discovered input, a full run can take
a few minutes on a busy page -- too long to hold a single HTTP request open
(and past gunicorn's default worker timeout). Like `/batch`, it runs on a
background thread and redirects to a status page that polls for progress
and renders findings as soon as they're ready.

It's gated at every layer independently:
- **Off by default.** Set `ACTIVE_TESTING_ENABLED=1` to turn it on at all —
  the routes exist in code either way, but refuse to run without this.
- **Admin-only**, same login as `/admin`.
- **Per-target confirmation.** Before each run, you type the exact target
  hostname to confirm — a deliberate friction point, not just a checkbox.
- **Every run is logged** (target, hostname, timestamp) to an audit trail
  visible at `/admin/active-scan/audit`.

Use it only for engagements you're actually authorized for (a signed
pentest, or your own infrastructure) — not the same free-for-all as the
passive scanner and `/batch`.

### Payload classifier (`/admin/classify`)

A small trained ML model — TF-IDF character n-grams + logistic regression,
trained on ~233k labeled payloads from a
[public Kaggle dataset](https://www.kaggle.com/datasets/mreowie/web-application-attack-payload-dataset)
(`ml/train.py`) — classifies a pasted string as benign, SQL injection, XSS,
command injection, path traversal, or SSTI. ~99.7% accuracy on held-out
test data overall; weakest on command injection using less-common syntax
like `$(...)` or `&&` (see `ml/models/metrics.json` for the full
classification report). Unlike active-scan, this makes no network calls to
anything — it's pure local inference on text you paste in, so it's only
gated behind admin login, not the heavier active-testing gates.

The trained model (`ml/models/payload_classifier.joblib`, ~1MB) is
committed to the repo as a build artifact; the raw training data isn't
(12MB, Kaggle-licensed — re-fetch with `kaggle datasets download
mreowie/web-application-attack-payload-dataset --unzip -p ml/data` if you
want to retrain). Adds `scikit-learn`/`joblib` to `requirements.txt`,
which pulls in numpy/scipy transitively — real weight (~150MB installed)
for what was a lightweight app; worth knowing if Render's free-tier build
time or slug size ever becomes a constraint.

## Run it locally

```bash
pip install -r requirements.txt
cp .env.example .env        # optional: add your ANTHROPIC_API_KEY
python app.py
```

Open http://localhost:5000. Works with zero configuration — without an API
key it still produces a full graded report using the built-in rule-based
narrative; add `ANTHROPIC_API_KEY` (from console.anthropic.com) to switch on
the AI-written executive summary.

Leads (email + scanned site + grade) are appended to `leads.csv` in this
folder every time someone submits the "send me the fix plan" form. Every
scan itself is saved to `scans.db` (SQLite) so its shareable link keeps
working after the visitor leaves the page.

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

Covers the security-critical paths (SSRF guard, CSRF, admin auth, rate
limiting) plus the core logic (grading, the rule-based AI fallback, storage
round-trips, batch job handling). The scanner tests run against two real
local Flask servers spun up for the test session — `test_target.py` itself
(the known-bad fixture used for manual testing) and a small SPA-fallback
stand-in that regression-tests the false-positive fix — rather than mocking
HTTP, so they exercise the actual scan pipeline. No network access or API
key needed; everything that would call Claude is tested against the
rule-based fallback path.

## What each file does

- `scanner.py` — the actual scan logic. Passive only: normal HTTP(S)
  requests and a TLS handshake, nothing that requires authorization to run
  against a public site (same category as securityheaders.com or Mozilla
  Observatory). Still, only point it at sites you own or a client has
  explicitly asked you to check.
- `ai_narrative.py` — sends findings to Claude for the plain-English summary;
  falls back to a fully-functional templated narrative if no API key is set
  or the API call fails, so the product never breaks in front of a prospect.
- `app.py` — the Flask web app (form → scan → report → lead capture).
- `storage.py` — saves each scan to `scans.db` (SQLite) and looks it back
  up by ID for the `/report/<id>` shareable link.
- `batch.py` — runs a `/batch` job (multiple scans + outreach drafts) on a
  background thread so the request doesn't have to stay open for minutes;
  job state is in-memory only, so it resets on restart.
- `active_scan.py` — the gated active-testing probes (see above). Off by
  default; requires `ACTIVE_TESTING_ENABLED=1`, admin login, and a typed
  per-target confirmation even when on. Not passive -- read the section
  above before touching this.
- `active_scan_job.py` — runs an active scan on a background thread and
  tracks its progress in memory, the same pattern `batch.py` uses, so the
  request that kicks it off can return immediately instead of blocking for
  minutes.
- `js_discovery.py` / `js_discovery_worker.py` — active-scan's headless-
  Chromium discovery fallback for JS-rendered sites (see above). The worker
  does the actual rendering as its own subprocess; `js_discovery.py` just
  spawns it and turns any failure into "found nothing."
- `payload_classifier.py` — loads `ml/models/payload_classifier.joblib` and
  classifies pasted text for `/admin/classify`. Local inference only.
- `ml/train.py` — trains that model from `ml/data/clean_payloads.csv`
  (gitignored, fetch via Kaggle -- see above). Not run at request time.
- `templates/` — the actual page design.
- `test_target.py` — a deliberately broken local server, useful for
  demoing/testing without needing a real site. `python test_target.py` runs
  it on port 5055; not part of the product itself. Scan targets are
  validated to block private/internal addresses (so a visitor can't use the
  form to probe your own infrastructure), which also blocks localhost by
  default — set `SITEGUARD_ALLOW_PRIVATE_TARGETS=1` in `.env` to scan
  `test_target.py` locally.

## Deploying it so it has a real URL

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/uchi-c/siteguard-ai)

Free tiers that work fine for this (Flask + gunicorn, no database beyond the
CSV): **Render** (render.com — this repo includes a `render.yaml` blueprint,
so clicking the button above sets up the web service automatically) or
**Railway** (railway.app). Both have free/low-cost tiers sufficient for a
lead-gen tool at low volume. When Render prompts for env vars, set
`ANTHROPIC_API_KEY` (optional) — `SECRET_KEY` is auto-generated by the
blueprint. Never commit `.env`. Auto-deploy on push works once Render's
GitHub App has access to this repo (`github.com/settings/installations` →
Render → Configure → add the repo) — without that, pushes need a manual
deploy from the Render dashboard.

`leads.csv` and `scans.db` both live on the host's filesystem, which on a
free tier is ephemeral and can get wiped on redeploy — a shared scan link
sent out right before a redeploy could go stale. Once you have real volume,
swap `_log_lead()` in `app.py` and `storage.py` for a managed DB (Render's
free Postgres tier works). Small edit, not a rebuild.

## Using this as the actual side hustle (not just a demo)

This connects to the plan from earlier: your edge is that you run a real
cybersecurity company (Shadow Root) and can actually fix what this finds —
most people running "AI agency" playbooks are selling something they can't
deliver.

1. **Payments.** Set up Payoneer now (Zambia-supported, works with Upwork/
   Fiverr payouts) and a Wise multi-currency account for direct invoices
   outside those platforms. Don't wait until you have a client to sort this.
2. **The offer.** Free scan (this tool) → paid fixed-price remediation
   (patch the specific findings) → optional monthly retainer (rescan +
   monitor). Price the first remediation project, not an hourly rate — it's
   easier to sell "$150 to fix these 6 things" than "$25/hr, trust me."
3. **Distribution.** Deploy this, then send the *link* (not a cold pitch) to
   small business owners/agencies — "I ran a free security scan on your
   site, found a few things worth fixing, here's the report: [link]." That's
   a warmer opener than generic outreach because it leads with concrete,
   personalized proof of value instead of a claim.
4. **Proof.** Scan your own sites and Shadow Root's first, screenshot a
   clean "A" grade report, and use *that* in outreach as credibility — "here's
   what a secure setup looks like, here's what yours currently shows."

## Legal/ethical note

Every check here is passive (equivalent to a browser visiting a public page).
There's no port scanning, credential guessing, or exploitation. Still: run
it only against your own properties or sites you have explicit permission to
test, and say so plainly to anyone you send a report to.
