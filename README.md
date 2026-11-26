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

For long runs, open one Splunk tab with `#voyager` at the end of its URL: it becomes the keep-alive tab and
reloads itself when Splunk ends the session, so the exports continue on their own. While an export runs, Voyager
also asks Windows not to go to sleep (closing the lid still does).

## Using the modules

**Network analysis.** Enter only the search part (`index=web sourcetype=access_combined site="shop.example"`).
Voyager appends the aggregation Payload Analyzer reads:

```
| stats count min(_time) as et max(_time) as lt values(src) as src values(status) as status values(action) as action
  by site uri_path uri_query
```

If your fields are named differently, map them under *Field extraction and field names*; if they are not
extracted at all, add `rex`/`eval` lines there. *Show the SPL that will run* displays the exact query.
Times are converted to UTC locally, so the Splunk user time zone doesn't matter.

**Entity mapper.** One value per line. Each value is searched as given and in its URL-encoded, form-encoded
and double-encoded forms. Sources with more events than the pull limit are only counted; *Always pull sources
containing* forces a pull. In the graph, *Search it in Voyager* on any node adds that value to the same
investigation. When two searched values appear in the same event, they get a direct (dashed) link.

**After updating Payload Analyzer**, *Re-analyse* on a network run runs the analysis, report and findings
again on the export it already has; Splunk isn't queried.

**Jobs.** Each run is a job with steps and a log. Jobs keep running when you close the browser or restart
Voyager. *Stop* also cancels its Splunk searches; *Resume* continues an interrupted or stopped job where it
stopped, without repeating finished windows.

## Command line

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

A value already in a case keeps the time range of its first search; `seed ... --reset-range` searches it again
with the new range. Each script has `--help`. The command-line tools use the default instance from the same settings
(`data/settings.json`), or `--base`/`--locale`/`--app`; the environment variables `SPLUNK_BASE`, `SPLUNK_LOCALE`,
`SPLUNK_APP` and `SPLUNK_COOKIE` override the default instance.

## Where things are

| Path | Contents |
| --- | --- |
| `run.py`, `app/`, `monitors/` | web app and terminal dashboard |
| `jobrun.py` | runs one job's steps, detached from the web app |
| `splunk_export.py` | resumable, windowed Splunk export |
| `network_feed.py` | query builder, window merge and findings between the export and Payload Analyzer |
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
