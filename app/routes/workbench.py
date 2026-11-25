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
    s = voyager_settings.load()
    if not s["splunk_base"]:
        return Response("// Set the Splunk URL in Voyager's Settings page first, then reload this link.\n",
                        mimetype="application/javascript")
    with open(os.path.join(ROOT_DIR, "app", "static", "voyager.user.js.tmpl"), encoding="utf-8") as fh:
        js = fh.read()
    backend = f"{request.scheme}://{request.host}"
    js = js.replace("__MATCH__", s["splunk_base"].rstrip("/") + "/*").replace("__BACKEND__", backend)
    return Response(js, mimetype="application/javascript")


# ------------------------------------------------------------------ API
@workbench_bp.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "GET":
        return jsonify(voyager_settings.load())
    data = _json()
    base = (data.get("splunk_base") or "").strip()
    if base:
        u = urlsplit(base)
        if u.scheme not in ("https", "http") or not u.netloc:
            return _err("Splunk URL must look like https://splunk.example.com")
        data["splunk_base"] = f"{u.scheme}://{u.netloc}{u.path.rstrip('/')}"
    try:
        return jsonify(voyager_settings.save(data))
    except (ValueError, OSError) as e:
        return _err(e)


@workbench_bp.route("/api/inv", methods=["GET", "POST"])
def api_investigations():
    if request.method == "GET":
        return jsonify(wb.list_investigations())
    d = _json()
    try:
        return jsonify(wb.create_investigation(d.get("name", ""), d.get("earliest", ""), d.get("latest", ""),
                                               d.get("notes", "")))
    except ValueError as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>", methods=["GET", "PATCH"])
def api_investigation(slug):
    try:
        if request.method == "PATCH":
            d = _json()
            wb.update_investigation(slug, **d)
        return jsonify(wb.get_investigation(slug))
    except FileNotFoundError:
        return _err("no such investigation", 404)
    except ValueError as e:
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
                               d.get("title", ""))
        return jsonify({"status": "started", "job": jid})
    except (ValueError, FileNotFoundError) as e:
        return _err(e)


@workbench_bp.route("/api/inv/<slug>/entities", methods=["POST"])
def api_entities(slug):
    d = _json()
    try:
        jid = wb.start_entities(slug, d.get("values") or [], d.get("earliest") or None, d.get("latest") or None,
                                d.get("include", ""), _int(d.get("max_events"), 500000), _int(d.get("bin"), 5),
                                d.get("group") or "sourcetype", d.get("title", ""))
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
