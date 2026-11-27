"""Investigations GUI: pages and JSON API for the network analysis and entity mapper modules."""
import os
from urllib.parse import urlsplit

from flask import Blueprint, render_template, jsonify, request, g, send_from_directory, abort, Response, url_for

import voyager_settings
from app.config import logger, BASE_DIR as ROOT_DIR
from app.routes.views import load_preferred_user
from app.services import workbench as wb

workbench_bp = Blueprint("workbench", __name__)
workbench_bp.before_request(load_preferred_user)


def _err(e, code=400):
    return jsonify({"status": "error", "message": str(e)}), code


def _json():
    if not request.is_json:
        abort(415)
    return request.get_json(silent=True) or {}


def _int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ pages
@workbench_bp.route("/investigations")
def investigations_page():
    return render_template("investigations.html", current_user=g.user, settings=voyager_settings.load())


@workbench_bp.route("/investigations/<slug>")
def investigation_page(slug):
    try:
        inv = wb.get_investigation(slug)
    except (FileNotFoundError, ValueError):
        abort(404)
    return render_template("investigation.html", current_user=g.user, inv=inv, settings=voyager_settings.load())


@workbench_bp.route("/settings")
def settings_page():
    return render_template("settings.html", current_user=g.user, settings=voyager_settings.load())


@workbench_bp.route("/inv/<slug>/files/<path:p>")
def inv_file(slug, p):
    """Reports, graphs and CSVs of an investigation (nothing outside its folder)."""
    try:
        d = wb.inv_dir(slug)
    except (FileNotFoundError, ValueError):
        abort(404)
    if not (p.endswith(".html") or p.endswith(".csv") or p.endswith(".json") or p.endswith(".spl")):
        abort(404)
    return send_from_directory(str(d), p, as_attachment=p.endswith(".csv"))


@workbench_bp.route("/voyager.user.js")
def userscript():
    origins = voyager_settings.origins()
    if not origins:
        return Response("// Add a Splunk instance in Voyager's Settings page first, then reload this link.\n",
                        mimetype="application/javascript")
    with open(os.path.join(ROOT_DIR, "app", "static", "voyager.user.js.tmpl"), encoding="utf-8") as fh:
        js = fh.read()
    backend = f"{request.scheme}://{request.host}"
    match = "\n".join(f"// @match        {o}/*" for o in origins)
    js = js.replace("// @match        __MATCH__", match).replace("__BACKEND__", backend)
    return Response(js, mimetype="application/javascript")


# ------------------------------------------------------------------ API
@workbench_bp.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "GET":
        return jsonify(voyager_settings.load())
    data = _json()
    try:
        return jsonify(voyager_settings.save(data))
    except (ValueError, OSError) as e:
        return _err(e)


@workbench_bp.route("/api/blocklist/add", methods=["POST"])
def api_blocklist_add():
    """Append one entry to the global blocklist (from a findings row)."""
    import blocklist
    entry = str(_json().get("entry") or "").strip()
    if not entry or "\n" in entry:
        return _err(ValueError("one entry, on one line"))
    s = voyager_settings.load()
    text = s.get("blocklist") or ""
    if entry not in [l.strip() for l in text.splitlines()]:
        text = text.rstrip("\n") + "\n" + entry + "\n"
    try:
        s = voyager_settings.save({"blocklist": text})
    except (ValueError, OSError) as e:
        return _err(e)
    return jsonify({"blocklist": s["blocklist"], "rules": len(blocklist.from_settings(s).rules)})


@workbench_bp.route("/api/blocklist/suggest", methods=["POST"])
def api_blocklist_suggest():
    import blocklist
    return jsonify({"entry": blocklist.suggest(_json().get("value"))})


@workbench_bp.route("/api/update", methods=["GET"])
def api_update_status():
    import updater
    s = voyager_settings.load()
    return jsonify({**updater.status, "mode": s.get("auto_update"), "interval": s.get("update_interval"),
                    "supervised": os.environ.get("VOYAGER_CHILD") == "1", "checkout": updater.is_checkout()})


@workbench_bp.route("/api/update/<action>", methods=["POST"])
def api_update_action(action):
    import threading
    import updater
    _json()
    if action == "check":
        updater.check()
        return api_update_status()
    if action == "apply":
        if os.environ.get("VOYAGER_CHILD") != "1":
            return _err("Voyager was started with --no-supervisor: update with git pull and restart it yourself")
        if not updater.check() or updater.status["blocked"]:
            return _err(updater.status["blocked"] or updater.status["error"] or "already up to date")

        def go():
            if updater.apply(logger.info) and getattr(updater, "restart_hook", None):
                updater.restart_hook()
        threading.Thread(target=go, daemon=True).start()
        return jsonify({"status": "updating"})
    abort(404)


@workbench_bp.route("/api/inv", methods=["GET", "POST"])
def api_investigations():
    if request.method == "GET":
        return jsonify(wb.list_investigations())
    d = _json()
    try:
        return jsonify(wb.create_investigation(d.get("name", ""), d.get("earliest", ""), d.get("latest", ""),
                                               d.get("notes", ""), d.get("instance", "")))
    except ValueError as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>", methods=["GET", "PATCH", "DELETE"])
def api_investigation(slug):
    try:
        if request.method == "DELETE":
            wb.delete_investigation(slug)
            return jsonify({"status": "deleted"})
        if request.method == "PATCH":
            d = _json()
            wb.update_investigation(slug, **d)
        return jsonify(wb.get_investigation(slug))
    except FileNotFoundError:
        return _err("no such investigation", 404)
    except (ValueError, RuntimeError) as e:
        return _err(e)


@workbench_bp.route("/api/network/preview", methods=["POST"])
def api_network_preview():
    from network_feed import build_query
    d = _json()
    try:
        return jsonify({"spl": build_query(d.get("base", ""), d.get("extract", ""), d.get("fields") or {})})
    except ValueError as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/network", methods=["POST"])
def api_network(slug):
    d = _json()
    try:
        jid = wb.start_network(slug, d.get("base", ""), d.get("extract", ""), d.get("fields") or {},
                               d.get("earliest") or None, d.get("latest") or None, d.get("chunk") or "1d",
                               d.get("title", ""), bool(d.get("low_memory")))
        return jsonify({"status": "started", "job": jid})
    except (ValueError, FileNotFoundError) as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/network/<jid>/reanalyze", methods=["POST"])
def api_reanalyze(slug, jid):
    _json()
    try:
        return jsonify({"status": "started", "job": wb.reanalyze_network(slug, jid)})
    except (ValueError, RuntimeError, FileNotFoundError) as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/entities", methods=["POST"])
def api_entities(slug):
    d = _json()
    try:
        jid = wb.start_entities(slug, d.get("values") or [], d.get("earliest") or None, d.get("latest") or None,
                                d.get("include", ""), _int(d.get("max_events"), 500000), _int(d.get("bin"), 5),
                                d.get("group") or "sourcetype", d.get("title", ""), bool(d.get("reset_range")))
        return jsonify({"status": "started", "job": jid})
    except (ValueError, FileNotFoundError) as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/entities/build", methods=["POST"])
def api_rebuild(slug):
    d = _json()
    try:
        return jsonify({"status": "started", "job": wb.rebuild_graph(slug, _int(d.get("bin"), 5),
                                                                     d.get("group") or "sourcetype")})
    except (ValueError, FileNotFoundError) as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/jobs/<jid>/<action>", methods=["POST"])
def api_job_action(slug, jid, action):
    _json()
    try:
        if action == "stop":
            wb.stop_job(slug, jid)
        elif action == "resume":
            wb.start_job(slug, jid)
        elif action == "delete":
            wb.delete_job(slug, jid)
        else:
            abort(404)
        return jsonify({"status": "ok"})
    except (RuntimeError, ValueError, FileNotFoundError) as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/jobs/<jid>/log")
def api_job_log(slug, jid):
    try:
        return Response(wb.read_log(slug, jid, _int(request.args.get("tail"), 400)), mimetype="text/plain")
    except (ValueError, FileNotFoundError):
        abort(404)
