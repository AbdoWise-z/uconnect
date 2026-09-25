"""A read-only web view of a uConnect rendezvous server.

    pip install -r requirements.txt
    UCONNECT_SERVER=127.0.0.1:4433 python app.py

The rendezvous server itself is untouched and keeps running in a terminal.
This is a separate process that watches it over the ordinary client protocol,
so it can run elsewhere, be restarted freely, or not run at all.

Everything shown is already public to anyone who can reach that server: topics
are listed unless a member opts out, LOOKUP needs no key because K never
reaches the server, and metadata is plaintext by design. This makes existing
exposure visible; it does not create any.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from observer import (Observer, ObserverError, deployment_info, derived_stats,
                      summarise)

app = Flask(__name__)

SERVER = os.environ.get("UCONNECT_SERVER", "127.0.0.1:4433")
TTL = float(os.environ.get("UCONNECT_CACHE_TTL", "5"))
LIMIT = int(os.environ.get("UCONNECT_LIMIT", "30"))
REFRESH = int(os.environ.get("UCONNECT_REFRESH", "15"))

observer = Observer(SERVER, ttl=TTL, limit=LIMIT)


@app.route("/")
def index():
    try:
        data, stale, err = observer.overview(members=True)
    except ObserverError as exc:
        return render_template("index.html", error=str(exc), view=None, server=SERVER,
                               build=deployment_info(), refresh=REFRESH), 503
    return render_template("index.html", view=summarise(data), error=err, stale=stale,
                           server=SERVER, build=deployment_info(), refresh=REFRESH)


@app.route("/topic/<topic_id>")
def topic(topic_id: str):
    try:
        data, stale, err = observer.topic(topic_id)
    except ObserverError as exc:
        return render_template("topic.html", error=str(exc), topic=None, server=SERVER,
                               build=deployment_info(), refresh=REFRESH), 400
    return render_template("topic.html", topic=data.get("topic"), error=err, stale=stale,
                           server=SERVER, build=deployment_info(), refresh=REFRESH)


# --- JSON API ---------------------------------------------------------------
# `stale` is reported rather than hidden: a consumer deserves to know it is
# looking at the last good answer instead of a fresh one.
@app.route("/api/overview")
def api_overview():
    members = request.args.get("members", "1") not in ("0", "false", "no")
    try:
        data, stale, err = observer.overview(members=members)
    except ObserverError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    return jsonify({**data, "derived": derived_stats(data), "build": deployment_info(),
                    "stale": stale, "warning": err})


@app.route("/api/topic/<topic_id>")
def api_topic(topic_id: str):
    try:
        data, stale, err = observer.topic(topic_id)
    except ObserverError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({**data, "stale": stale, "warning": err})


@app.route("/api/build")
def api_build():
    return jsonify(deployment_info())


@app.route("/healthz")
def healthz():
    """Liveness of this dashboard, and separately of the server it watches."""
    build = deployment_info()
    try:
        observer.overview(members=False)
        return jsonify({"ok": True, "server": SERVER, "rendezvous": "reachable",
                        "commit": build.get("short")})
    except ObserverError as exc:
        # The dashboard is up; the thing it observes is not. A 503 with the
        # distinction spelled out beats a 200 that hides an outage.
        return jsonify({"ok": False, "server": SERVER, "error": str(exc),
                        "commit": build.get("short")}), 503


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    # Loopback by default: this is unauthenticated, and defaulting to 0.0.0.0
    # would publish a topic directory from whatever host happened to run it.
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False, threaded=True)
