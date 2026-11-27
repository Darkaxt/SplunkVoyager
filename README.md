# SplunkVoyager

Investigation workbench for Splunk. It runs heavy searches without the Splunk web UI, through your own browser
session, and analyses the results on your computer:

- **Network analysis** ([Payload Analyzer](payload_analyzer/README.md)): give the base search for your web or
  WAF logs; Voyager exports the request groups window by window, merges them and classifies every decoded
  parameter as SQL injection, command execution, file access, SSRF, XSS or benign, with an offline HTML report.
- **Entity mapper**: search any value (an address, a callback host, an account, a URL, a leaked password)
  across all indexes, in every encoding it may appear in. A two-stage search counts where it occurs, pulls the
  raw events of the smaller sources, and builds an animated graph of how its relations appear over time.
- **Heavy-query export** underneath both: searches split into time windows, several running at once, each
  window retried on its own, resumable after a laptop sleep, a reboot or an expired session.

Findings from the network analysis (attack sources, callback hosts) go to the entity mapper with one click, and
both run in the background at the same time.

## Requirements

- Python 3.10 or later
- A browser with [Tampermonkey](https://www.tampermonkey.net/) (the BETA build reads HTTP-only cookies)
- Access to Splunk Web with your normal login (single sign-on works; Voyager never sees your password)

## Install and start

```
git clone https://github.com/<you>/<repo>.git
cd <repo>
python -m venv venv
venv\Scripts\activate            # Linux/macOS: source venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

Behind a corporate proxy, add `--proxy http://proxy:port` to the pip command.

`run.py` starts the web app on <http://localhost:8080>, opens it in your browser (`--no-browser` to skip) and
shows a terminal dashboard (`python run.py --help` for options). Then:

1. In **Settings**, add your Splunk instance: its Splunk Web URL (for example `https://splunk.example.com`), the
   locale shown in your Splunk URLs (`en-US`, `en-GB`...) and, optionally, the app your searches should run in.
   Add more instances if you work with several Splunks; one of them is the default.
2. On the same page, install the userscript. It is generated for your instances and runs only on them
   (reinstall it after adding one).
3. Open any Splunk page. The session appears in Voyager's header within 30 seconds.
4. Open **Investigations**, create one with a time range (and, with several instances, the Splunk to search),
   and start the analyses. On the **Query** page, the session of your default instance is preselected.

**Updates.** `run.py` checks GitHub when it starts and every 30 minutes, installs new versions with a
fast-forward `git pull` and restarts itself; running jobs are not interrupted. Settings → Updates switches this
to "only tell me" or off. Only a clean clone is updated (local edits to the app's files block it), and a version
that fails to start is rolled back and skipped. `--no-supervisor` runs the server without restarts.

For long runs, open one Splunk tab with `#voyager` at the end of its URL: it becomes the keep-alive tab and
reloads itself when Splunk ends the session, so the exports continue on their own. While an export runs, Voyager
also asks Windows not to go to sleep (closing the lid still does).

## Using the modules

**Network analysis.** Enter only the search part (`index=web sourcetype=access_combined site="shop.example"`).
Voyager appends the aggregation Payload Analyzer reads:

```
| eval req_bytes=coalesce(tonumber('cs_bytes'), tonumber('cs_B'), tonumber('bytes_out')),
       resp_bytes=coalesce(tonumber('sc_bytes'), tonumber('sc_B'), tonumber('bytes_in'))
| stats count min(_time) as et max(_time) as lt values(src) as src values(status) as status values(action) as action
  sum(req_bytes) as req_bytes count(req_bytes) as req_n sum(resp_bytes) as resp_bytes count(resp_bytes) as resp_n
  max(resp_bytes) as resp_max by site uri_path uri_query
```

The sizes are optional: the first size field present is used, and data without any of them gives a run without
sizes. Set other size fields under *request size* / *response size*, or `-` to leave sizes out.

If your fields are named differently, map them under *Field extraction and field names*; if they are not
extracted at all, add `rex`/`eval` lines there. *Show the SPL that will run* displays the exact query.
Times are converted to UTC locally, so the Splunk user time zone doesn't matter.

**Entity mapper.** One value per line. Each value is searched as given and in its URL-encoded, form-encoded
and double-encoded forms. Sources with more events than the pull limit are only counted; *Always pull sources
containing* forces a pull. In the graph, *Search it in Voyager* on any node adds that value to the same
investigation. When two searched values appear in the same event, they get a direct (dashed) link.

**Attack map.** *Open attack map* on a network run shows its source addresses and the sites they attacked:
arcs coloured by the furthest phase reached (or by attack type), an hourly view of attack types, playback with a
live feed, and per source / site / path / arc the payloads in order. Sites expand into their paths (click the +
or the *paths* switch). Levels (probing, enumeration, extraction, sustained) are rule-based, with the rules shown
in the page; they describe what the payloads show, not whether an attack succeeded.
When the export has sizes, arrow width follows the request bytes of the payloads in progress, and the packets
flowing back follow the response bytes of the extraction payloads in progress. The details show each payload's
average request and response size and its response against the median response of the same site + path. Sizes
come from the exact request groups of each payload; per-event bytes are its requests x its average size. Runs
exported before this change have no sizes: run the analysis again from Splunk to get them (*Re-analyse* reuses
the old export).
`python network_map.py analysis.json -o attack_map.html [--sanitize] [--requests requests.jsonl]` builds it by hand.

**Credentials in URLs.** The findings step also looks through every merged request (path and query string,
decoded as many times as needed) for `scheme://user:password@host`, `Basic <base64>` values, and password,
token or API-key parameters (not anti-CSRF, captcha, nonce or paging ones). It writes the full values to
`credentials.jsonl` in the run's folder and adds a *Credentials in URLs* section to the HTML report: kind, site
and path, parameter, user, secret, requests, status codes, sources (flagged when they are also attack sources),
first and last seen, and the request as evidence. Secrets are masked and stored encoded in the page; a click
decodes one value, another masks it again. The same secrets elsewhere in the report (Payload Analyzer's
payload tables, graph, focus results) are masked the same way; values shorter than 4 characters are only
masked in the credentials section. `findings.json` and the investigation page hold only masked values.

**Findings lists and the blocklist.** Each network run lists its attack sources and the callbacks / hosts found
inside payloads, ranked; the top 50 are shown, *Show all* lists every value. Values that are not indicators
(XML namespaces such as `www.w3.org` quoted in payloads, placeholders like `http://a`) are hidden by a global
blocklist, edited under *Settings* or with *Hide* on a row: domains with their subdomains, wildcards, addresses
and networks, exact values or regular expressions, plus a switch for single-label names. Nothing is deleted:
each list shows how many values are hidden and, on demand, which entry hides each one.

**After updating Payload Analyzer**, *Re-analyse* on a network run runs the analysis, report and findings
again on the export it already has; Splunk isn't queried.

**Destructive actions ask twice.** Deleting an investigation or a network run, removing a job, stopping a job,
re-analysing a run, replacing the range of values already mapped, removing a Splunk instance, and the older
session / query pages' invalidate, re-run and delete. The server refuses the first request and answers with
what would be lost (sizes, files, running searches); the page shows it and sends the request again only after
you confirm. Deleting an investigation needs its name typed, deleting a network run the word `delete`.
`run.py --wipe` lists what it removes and asks you to type `wipe` (`--yes` for scripts).

**Jobs.** Each run is a job with steps and a log. Jobs keep running when you close the browser or restart
Voyager. *Stop* also cancels its Splunk searches; *Resume* continues an interrupted or stopped job where it
stopped, without repeating finished windows.

## Command line

**Authentication analysis.** *Auth analysis* (entity mapper) reads the raw events the entity mapper exported
and reports failed, locked and successful logons: per account and target (invalid credentials, lockouts,
first and last failure, first lockout, success after failure / after the lockout, sources, client OS users,
database links, each event with its raw evidence), per source (accounts tried, accounts with failures, most
failures on one account, peak in 10 minutes), an hourly timeline, listener connections, outbound connection
failures and alert-log logons. Parsed: `oracle:audit:db` LOGON rows, `oracle:audit:text` CONNECT records
(length-prefixed fields, so SQL text is never mistaken for a status), `oracle:listener:xml`, `oracle:alert:xml`,
Windows Security 4624/4625/4648/4740/4771/4776, Linux sshd / pam / faillock. An event exported under several
mapped values counts once. Output: `entities/auth_report.html` and `entities/auth_events.csv`; by hand:
`python auth_analysis.py data\investigations\<case>`. `python auth_samples.py <case>` picks a few raw events
per sourcetype to look at a dump's formats.

**Large exports.** The merge of the time windows keeps its memory bounded however big the export is: above
300,000 rows it spreads the rows over compressed buckets beside the output (about 40 bytes per row) and
aggregates one bucket at a time, in up to 4 processes, logging progress and the time left. The merged
`requests.jsonl` is not compressed: count roughly 300 bytes per distinct request (site + path + query string).
`VOYAGER_MERGE_BUCKET_ROWS` changes the bucket size (memory per process grows with it).

Everything the GUI does is available from the command line too:

```
python splunk_export.py run "@query.spl" --earliest 2026-11-01 --latest 2026-11-20 --chunk 1d --out-dir exports\x
python network_feed.py query "index=web" --site host --src clientip        # print the network-analysis SPL
python network_feed.py merge exports\x -o requests.jsonl
python -I payload_analyzer\payload_analyzer.py pipeline requests.jsonl -o analysis.json
python -I payload_analyzer\report_builder.py analysis.json -o report.html
python pivot_graph.py seed cases\acct "admin@example.com" --earliest 2026-10-01 --latest 2026-11-01
python pivot_graph.py status cases\acct                                     # range searched and range found
python pivot_graph.py build cases\acct cases\other -o combined.html          # several cases in one graph
```

Each export run writes one part file per time window, and compresses it into its own zip as soon as that window
is downloaded (`part-0001.jsonl` -> `part-0001.jsonl.zip`), so loose files never pile up during a long run
(`--no-pack` keeps them loose). A resumed run first compresses the windows it finished before, and Voyager
compresses the finished windows of every run under its investigations every two minutes, including runs still
going with an older exporter. All the tools read loose parts, per-window zips and the single `export.zip` of
earlier versions. By hand: `python exportfiles.py pack cases data\investigations` (finished windows only).

A value already in a case keeps the time range of its first search; `seed ... --reset-range` searches it again
with the new range. Each script has `--help`. The command-line tools use the default instance from the same settings
(`data/settings.json`), or `--base`/`--locale`/`--app`; the environment variables `SPLUNK_BASE`, `SPLUNK_LOCALE`,
`SPLUNK_APP` and `SPLUNK_COOKIE` override the default instance.

## Where things are

| Path | Contents |
| --- | --- |
| `run.py`, `app/`, `monitors/` | web app and terminal dashboard |
| `jobrun.py` | runs one job's steps, detached from the web app |
| `updater.py` | update check, fast-forward and rollback used by `run.py` |
| `splunk_export.py` | resumable, windowed Splunk export |
| `network_feed.py` | query builder, window merge and findings between the export and Payload Analyzer |
| `network_map.py`, `network_map_template.html` | attack map of a network run |
| `auth_analysis.py` | authentication analysis of an entity-mapper dump (+ `auth_report_template.html`) |
| `auth_samples.py` | sample raw events per sourcetype from a dump |
| `credentials.py` | credentials in request URLs: scan, credentials.jsonl, report section |
| `blocklist.py` | global blocklist for the findings lists |
| `exportfiles.py` | export folders: part files, per-window zips or `export.zip`; `pack` command |
| `pivot_graph.py`, `pivot_graph_template.html` | entity mapper |
| `payload_analyzer/` | Payload Analyzer, unchanged copy (commit in `UPSTREAM_COMMIT`), standard library only |
| `data/` | your local state: session cookies, settings, investigations. Never commit it |

## Security notes

- Voyager holds a working Splunk session. It listens on this computer only (`VOYAGER_HOST` changes that;
  don't expose it). It refuses state-changing requests from other web pages, and accepts cookies only from the
  Splunk URL in Settings.
- Investigation folders contain raw log data and decoded payloads. Keep them where your organisation's data rules
  allow; `pivot_graph.py build --sanitize` and `payload_analyzer.py sanitize` produce shareable versions.
- Reports describe what the logs contain; they don't establish that an attack succeeded.

## Tests

```
python -m unittest discover -s tests                          # Voyager, including both modules end to end
python -I -m unittest discover -s payload_analyzer/tests      # Payload Analyzer
```

The end-to-end tests run against `tests/mock_splunk.py`, a small fake Splunk with made-up data.

## Licence

MIT No Attribution ([LICENSE](LICENSE)).
