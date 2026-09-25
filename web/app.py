"""A read-only web view of a uConnect rendezvous server, plus a small
interactive app for creating topics and watching signaling activity live.

    pip install -r requirements.txt
    UCONNECT_SERVER=127.0.0.1:4433 python app.py

The rendezvous server itself is untouched and keeps running in a terminal.
This is a separate process that watches it over the ordinary client protocol.

Two things worth knowing before reading further:

 *  Topic keys are generated IN THE BROWSER and never sent here. A topic's
    secret is the only credential the protocol has; a server that minted it
    would know every key it ever handed out, which would quietly undo the one
    property the whole design exists to provide. The server is told a topic id
    only so it can count it, and it would learn that anyway the moment a peer
    registered.

 *  The live feed carries signaling, not conversations. Peer traffic is
    end-to-end encrypted and never reaches the rendezvous server, so
    registrations, lookups and membership changes are all there is to see.
"""

from __future__ import annotations

import json
import os
import queue

from flask import (Flask, Response, jsonify, render_template, request,
                   stream_with_context)

from chat import BridgeManager, ChatError
from events import EventHub
from observer import (Observer, ObserverError, deployment_info, derived_stats,
                      summarise)
from sessions import LimitError, SessionRegistry, client_ip, trust_proxy_enabled

app = Flask(__name__)

SERVER = os.environ.get("UCONNECT_SERVER", "127.0.0.1:4433")
TTL = float(os.environ.get("UCONNECT_CACHE_TTL", "5"))
LIMIT = int(os.environ.get("UCONNECT_LIMIT", "30"))
COOKIE = "uconn_sid"

observer = Observer(SERVER, ttl=TTL, limit=LIMIT)
sessions = SessionRegistry(
    max_per_ip=int(os.environ.get("UCONNECT_MAX_SESSIONS_PER_IP", "10")),
    max_total_streams=int(os.environ.get("UCONNECT_MAX_STREAMS", "24")),
)
hub = EventHub(observer, interval=float(os.environ.get("UCONNECT_FEED_INTERVAL", "3")))
bridges = BridgeManager(
    SERVER,
    max_total=int(os.environ.get("UCONNECT_MAX_CHATS", "8")),
    lifetime=int(os.environ.get("UCONNECT_CHAT_LIFETIME", "1800")),
)

TRUST_PROXY = trust_proxy_enabled()


def _ip() -> str:
    return client_ip(request.headers, request.remote_addr, TRUST_PROXY)


def _session():
    """Current session, or None if this address is over its limit."""
    try:
        return sessions.touch(request.cookies.get(COOKIE), _ip()), None
    except LimitError as exc:
        return None, str(exc)


def _with_cookie(resp, sess):
    if sess is not None:
        resp.set_cookie(COOKIE, sess.sid, max_age=86400, httponly=True,
                        samesite="Lax")
    return resp


# --- read-only dashboard ----------------------------------------------------
@app.route("/")
def index():
    try:
        data, stale, err = observer.overview(members=True)
    except ObserverError as exc:
        return render_template("index.html", error=str(exc), view=None, server=SERVER,
                               build=deployment_info()), 503
    return render_template("index.html", view=summarise(data), error=err, stale=stale,
                           server=SERVER, build=deployment_info())


@app.route("/topic/<topic_id>")
def topic(topic_id: str):
    try:
        data, stale, err = observer.topic(topic_id)
    except ObserverError as exc:
        return render_template("topic.html", error=str(exc), topic=None, server=SERVER,
                               build=deployment_info()), 400
    return render_template("topic.html", topic=data.get("topic"), error=err, stale=stale,
                           server=SERVER, build=deployment_info())


# --- the interactive app ----------------------------------------------------
@app.route("/app")
def live_app():
    sess, limited = _session()
    resp = app.make_response(
        render_template("app.html", server=SERVER, build=deployment_info(),
                        limited=limited, error=None, stale=False,
                        session=sess.sid[:8] if sess else None,
                        topics=sess.topics if sess else [],
                        limits=sessions.stats())
    )
    return _with_cookie(resp, sess), (429 if limited else 200)


@app.route("/api/topic", methods=["POST"])
def register_topic():
    """Record a topic the browser just generated.

    The id arrives already created; nothing is minted here. This only files it
    against the session so the page can list what you made, and enforces a
    per-session cap so the endpoint cannot be used as free storage.
    """
    sess, limited = _session()
    if limited:
        return jsonify({"ok": False, "error": limited}), 429

    body = request.get_json(silent=True) or {}
    tid = str(body.get("topic_id", "")).strip().lower()
    if len(tid) != 32 or any(c not in "0123456789abcdef" for c in tid):
        return jsonify({"ok": False, "error": "topic id must be 32 hex characters"}), 400
    if "key" in body or "k" in body:
        # Refused rather than ignored. A client sending a key is a client that
        # has misunderstood something important, and silently dropping it would
        # let that misunderstanding ship.
        return jsonify({
            "ok": False,
            "error": "do not send topic keys to the server; generate them in the browser",
        }), 400

    try:
        sessions.record_topic(sess.sid, tid)
    except LimitError as exc:
        return _with_cookie(jsonify({"ok": False, "error": str(exc)}), sess), 429
    return _with_cookie(jsonify({"ok": True, "topic_id": tid, "topics": sess.topics}), sess)


@app.route("/api/events")
def events():
    """Server-Sent Events feed of signaling activity.

    SSE rather than WebSockets: the data only ever flows one way, and SSE needs
    no extra dependency, survives the existing threaded worker, and reconnects
    by itself in the browser. A WebSocket would add a handshake, a second
    protocol and an async worker to operate, for a channel nothing ever sends
    up. Swapping it later is a contained change -- the hub already speaks in
    discrete events.
    """
    sess, limited = _session()
    if limited:
        return jsonify({"ok": False, "error": limited}), 429

    try:
        sessions.open_stream(sess.sid)
    except LimitError as exc:
        return _with_cookie(jsonify({"ok": False, "error": str(exc)}), sess), 429

    hub.start()
    q = hub.subscribe()
    sid = sess.sid

    @stream_with_context
    def gen():
        try:
            yield "retry: 5000\n\n"
            while True:
                try:
                    ev = q.get(timeout=20)
                    yield f"event: {ev['kind']}\ndata: {json.dumps(ev)}\n\n"
                except queue.Empty:
                    # Idle servers are normal, and a silent connection gets cut
                    # by proxies and NATs that see nothing for a minute.
                    yield ": keepalive\n\n"
        finally:
            # Runs when the client disconnects, which is the only way this loop
            # ever ends. Without it the stream slot leaks and the feed closes
            # itself to everyone after max_total_streams visitors.
            hub.unsubscribe(q)
            sessions.close_stream(sid)

    resp = Response(gen(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"   # nginx would otherwise buffer it
    return _with_cookie(resp, sess)


# --- chat -------------------------------------------------------------------
# Everything below hands a topic key to this process. See chat.py: a browser
# cannot run the handshake itself, so the gateway does it, and the gateway can
# therefore read the conversation. The page states that before anyone types.
@app.route("/chat")
def chat_page():
    sess, limited = _session()
    resp = app.make_response(
        render_template("chat.html", server=SERVER, build=deployment_info(),
                        limited=limited, error=None, stale=False,
                        chat=bridges.stats(),
                        joined=(bridges.get(sess.sid) if sess else None))
    )
    return _with_cookie(resp, sess), (429 if limited else 200)


@app.route("/api/chat/join", methods=["POST"])
def chat_join():
    sess, limited = _session()
    if limited:
        return jsonify({"ok": False, "error": limited}), 429

    body = request.get_json(silent=True) or {}
    try:
        b = bridges.start(sess.sid, str(body.get("topic", "")), str(body.get("nick", "web")))
    except ChatError as exc:
        return _with_cookie(jsonify({"ok": False, "error": str(exc)}), sess), 400
    return _with_cookie(
        jsonify({"ok": True, "topic_id": b.topic_id, "nick": b.nick}), sess)


@app.route("/api/chat/say", methods=["POST"])
def chat_say():
    sess, limited = _session()
    if limited:
        return jsonify({"ok": False, "error": limited}), 429
    b = bridges.get(sess.sid)
    if b is None:
        return _with_cookie(jsonify({"ok": False, "error": "not in a topic"}), sess), 409

    text = str((request.get_json(silent=True) or {}).get("text", "")).strip()
    if not text:
        return _with_cookie(jsonify({"ok": False, "error": "empty message"}), sess), 400
    if len(text) > 2000:
        text = text[:2000]
    try:
        b.say(text)
    except ChatError as exc:
        return _with_cookie(jsonify({"ok": False, "error": str(exc)}), sess), 409
    return _with_cookie(jsonify({"ok": True}), sess)


@app.route("/api/chat/leave", methods=["POST"])
def chat_leave():
    sess, limited = _session()
    if limited:
        return jsonify({"ok": False, "error": limited}), 429
    bridges.stop(sess.sid)
    return _with_cookie(jsonify({"ok": True}), sess)


@app.route("/api/chat/stream")
def chat_stream():
    sess, limited = _session()
    if limited:
        return jsonify({"ok": False, "error": limited}), 429
    b = bridges.get(sess.sid)
    if b is None:
        return _with_cookie(jsonify({"ok": False, "error": "not in a topic"}), sess), 409

    try:
        sessions.open_stream(sess.sid)
    except LimitError as exc:
        return _with_cookie(jsonify({"ok": False, "error": str(exc)}), sess), 429

    q = b.subscribe()
    sid = sess.sid

    @stream_with_context
    def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    ev = q.get(timeout=20)
                    yield f"event: {ev.get('t', 'msg')}\ndata: {json.dumps(ev)}\n\n"
                    if ev.get("t") == "closed":
                        break
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            b.unsubscribe(q)
            sessions.close_stream(sid)

    resp = Response(gen(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return _with_cookie(resp, sess)


# --- JSON API ---------------------------------------------------------------
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
    build = deployment_info()
    try:
        observer.overview(members=False)
        return jsonify({"ok": True, "server": SERVER, "rendezvous": "reachable",
                        "commit": build.get("short"), "sessions": sessions.stats()})
    except ObserverError as exc:
        return jsonify({"ok": False, "server": SERVER, "error": str(exc),
                        "commit": build.get("short")}), 503


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    # Bind loopback by default. This is an unauthenticated read-only view, and
    # putting it on 0.0.0.0 by default would publish a topic directory from
    # whatever host happened to run it.
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False, threaded=True)
