"""uconnect -- Python bindings for uConnect's C API (uconnect_c.h), over ctypes.

    node = uconnect.Node("127.0.0.1:4433")
    node.run_in_background()
    topic = node.join(uconnect.Creds.parse("uconn://<32hex>#<64hex>"))
    topic.queue_events()
    topic.publish(b"meta")
    while (ev := node.next_event(timeout_ms=1000)) is not None:
        ...
    node.close()

Events come from the C API's event queue, drained on whatever thread calls
Node.next_event(), rather than from callbacks on the library's loop thread:
that is the path the C API offers runtimes that would rather not be entered
from a foreign thread.

A Topic here is only a (node, topic id) pair, as in the C API: it holds no
handle into the library, so after leave() or shutdown it is merely absent --
calls on it return False, None or empty -- never dangling.

The shared library is found through $UCONNECT_C_LIB, else in this checkout's
build/src/capi, else wherever the system loader looks.
"""

import ctypes
import enum
import os
import sys
from ctypes import (POINTER, Structure, byref, c_bool, c_char, c_char_p, c_int, c_size_t,
                    c_uint8, c_uint16, c_uint32, c_uint64, c_void_p)
from dataclasses import dataclass
from typing import List, Optional

DEFAULT_TIMEOUT_MS = 3000
URI_MAX = 106


# ---------------------------------------------------------------------------
# The C types, field for field
# ---------------------------------------------------------------------------
class _TopicId(Structure):
    _fields_ = [("bytes", c_uint8 * 16)]


class _DevId(Structure):
    _fields_ = [("bytes", c_uint8 * 16)]


class _Key(Structure):
    _fields_ = [("bytes", c_uint8 * 32)]


class _Creds(Structure):
    _fields_ = [("id", _TopicId), ("keyed", c_bool), ("key", _Key)]


class _NodeConfig(Structure):
    _fields_ = [
        ("server", c_char_p),
        ("bind_port", c_uint16),
        ("keepalive_s", c_uint32),
        ("max_total_peers", c_size_t),
        ("punch_timeout_s", c_uint32),
        ("force_relay", c_bool),
        ("verbose", c_bool),
        ("datagram_fallback", c_int),
        ("rekey_shift", c_uint8),
    ]


class _PeerInfo(Structure):
    _fields_ = [
        ("dev_id", _DevId),
        ("age_s", c_uint32),
        ("stale", c_bool),
        ("meta", POINTER(c_uint8)),
        ("meta_len", c_size_t),
    ]


class _LinkInfo(Structure):
    _fields_ = [
        ("relayed", c_bool),
        ("messages_sent", c_uint64),
        ("messages_received", c_uint64),
        ("bytes_sent", c_uint64),
        ("bytes_received", c_uint64),
        ("datagrams_sent", c_uint64),
        ("datagrams_received", c_uint64),
    ]


_STATS_FIELDS = [
    "topics_total", "topics_listed", "entries_total", "entries_fresh",
    "registers", "lookups", "connects", "expired",
    "rej_quota", "rej_rate_limited",
    "relays_open", "relays_allocated", "relay_bytes",
    "connections",
]


class _ServerStats(Structure):
    _fields_ = [(name, c_uint64) for name in _STATS_FIELDS]


class _Event(Structure):
    _fields_ = [
        ("kind", c_int),
        ("topic", _TopicId),
        ("dev", _DevId),
        ("peer_state", c_int),
        ("datagram_path", c_int),
        ("peer_gone", c_int),
        ("data", POINTER(c_uint8)),
        ("len", c_size_t),
    ]


class PeerState(enum.IntEnum):
    UNKNOWN = 0
    PROBING = 1
    HANDSHAKING = 2
    CONNECTED = 3
    FAILED = 4
    CLOSED = 5


class PeerGone(enum.IntEnum):
    LOCAL = 0
    TIMED_OUT = 1
    GOING_AWAY = 2
    SHUTTING_DOWN = 3
    UNSPECIFIED = 4


class DatagramFallback(enum.IntEnum):
    TCP = 0
    RELAY = 1
    NONE = 2


class DatagramPath(enum.IntEnum):
    NONE = 0
    OPENING = 1
    DIRECT = 2
    RELAYED = 3
    TCP = 4
    FAILED = 5


class EventKind(enum.IntEnum):
    PEER = 0
    DATA = 1
    DATAGRAM = 2
    DATAGRAM_PATH = 3
    PEER_CLOSED = 4


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _library_path() -> str:
    if os.environ.get("UCONNECT_C_LIB"):
        return os.environ["UCONNECT_C_LIB"]
    if sys.platform == "win32":
        name = "uconnect_c.dll"
    elif sys.platform == "darwin":
        name = "libuconnect_c.dylib"
    else:
        name = "libuconnect_c.so"
    here = os.path.dirname(os.path.abspath(__file__))
    built = os.path.normpath(os.path.join(here, "..", "..", "build", "src", "capi", name))
    return built if os.path.exists(built) else name


_lib = ctypes.CDLL(_library_path())

_node_p = c_void_p
_list_p = c_void_p
_u8_p = POINTER(c_uint8)

# name: (restype, argtypes). Every function in uconnect_c.h, so that a symbol
# the library stops exporting fails here, at import, rather than mid-run.
_PROTOTYPES = {
    "uconnect_peer_state_name": (c_char_p, [c_int]),
    "uconnect_peer_gone_name": (c_char_p, [c_int]),
    "uconnect_datagram_path_name": (c_char_p, [c_int]),
    "uconnect_max_message": (c_size_t, []),
    "uconnect_max_datagram": (c_size_t, []),
    "uconnect_last_error": (c_char_p, []),

    "uconnect_creds_generate": (c_bool, [c_bool, POINTER(_Creds)]),
    "uconnect_creds_parse": (c_bool, [c_char_p, POINTER(_Creds)]),
    "uconnect_creds_to_uri": (c_size_t, [POINTER(_Creds), POINTER(c_char), c_size_t]),

    "uconnect_peer_list_size": (c_size_t, [_list_p]),
    "uconnect_peer_list_get": (c_bool, [_list_p, c_size_t, POINTER(_PeerInfo)]),
    "uconnect_peer_list_free": (None, [_list_p]),

    "uconnect_node_config_init": (None, [POINTER(_NodeConfig)]),
    "uconnect_node_new": (_node_p, [POINTER(_NodeConfig)]),
    "uconnect_node_free": (None, [_node_p]),
    "uconnect_node_run": (None, [_node_p]),
    "uconnect_node_run_in_background": (None, [_node_p]),
    "uconnect_node_shutdown": (None, [_node_p]),
    "uconnect_node_is_running": (c_bool, [_node_p]),
    "uconnect_node_local_port": (c_uint16, [_node_p]),
    "uconnect_node_reflexive": (c_bool, [_node_p, c_void_p]),
    "uconnect_node_server_connected": (c_bool, [_node_p]),
    "uconnect_node_pending_requests": (c_size_t, [_node_p]),
    "uconnect_node_explore": (c_size_t, [_node_p, c_uint32, c_void_p, c_size_t, c_uint32]),
    "uconnect_node_try_explore": (c_bool, [_node_p, c_uint32, c_void_p, c_size_t, c_uint32,
                                           POINTER(c_size_t)]),
    "uconnect_node_stats": (c_bool, [_node_p, c_uint32, POINTER(_ServerStats)]),
    "uconnect_node_join": (c_bool, [_node_p, POINTER(_Creds)]),
    "uconnect_node_create": (c_bool, [_node_p, c_bool, POINTER(_Creds)]),
    "uconnect_node_leave": (None, [_node_p, _TopicId]),
    "uconnect_node_topics": (c_size_t, [_node_p, POINTER(_TopicId), c_size_t]),
    "uconnect_node_creds": (c_bool, [_node_p, _TopicId, POINTER(_Creds)]),

    "uconnect_topic_publish": (c_bool, [_node_p, _TopicId, _u8_p, c_size_t, c_bool]),
    "uconnect_topic_unpublish": (None, [_node_p, _TopicId]),
    "uconnect_topic_self": (c_bool, [_node_p, _TopicId, POINTER(_DevId)]),
    "uconnect_topic_peers": (_list_p, [_node_p, _TopicId, c_uint8, c_bool, c_uint32]),
    "uconnect_topic_resolve": (_list_p, [_node_p, _TopicId, _DevId, c_uint32]),
    "uconnect_topic_connect": (None, [_node_p, _TopicId, _DevId]),
    "uconnect_topic_connect_all": (None, [_node_p, _TopicId, c_size_t]),
    "uconnect_topic_disconnect": (None, [_node_p, _TopicId, _DevId]),
    "uconnect_topic_disconnect_all": (None, [_node_p, _TopicId]),
    "uconnect_topic_connected": (c_size_t, [_node_p, _TopicId, POINTER(_DevId), c_size_t]),
    "uconnect_topic_state": (c_int, [_node_p, _TopicId, _DevId]),
    "uconnect_topic_link": (c_bool, [_node_p, _TopicId, _DevId, POINTER(_LinkInfo)]),
    "uconnect_topic_send": (c_bool, [_node_p, _TopicId, _DevId, _u8_p, c_size_t]),
    "uconnect_topic_broadcast": (c_size_t, [_node_p, _TopicId, _u8_p, c_size_t]),
    "uconnect_topic_open_datagrams": (c_bool, [_node_p, _TopicId, _DevId, c_int]),
    "uconnect_topic_close_datagrams": (None, [_node_p, _TopicId, _DevId]),
    "uconnect_topic_datagram_path": (c_int, [_node_p, _TopicId, _DevId]),
    "uconnect_topic_send_datagram": (c_bool, [_node_p, _TopicId, _DevId, _u8_p, c_size_t]),
    "uconnect_topic_on_peer": (None, [_node_p, _TopicId, c_void_p, c_void_p]),
    "uconnect_topic_on_data": (None, [_node_p, _TopicId, c_void_p, c_void_p]),
    "uconnect_topic_on_datagram": (None, [_node_p, _TopicId, c_void_p, c_void_p]),
    "uconnect_topic_on_datagram_path": (None, [_node_p, _TopicId, c_void_p, c_void_p]),
    "uconnect_topic_on_peer_closed": (None, [_node_p, _TopicId, c_void_p, c_void_p]),
    "uconnect_topic_set_max_peers": (None, [_node_p, _TopicId, c_size_t]),
    "uconnect_topic_set_auto_connect": (None, [_node_p, _TopicId, c_bool]),
    "uconnect_topic_is_authenticated": (c_bool, [_node_p, _TopicId]),
    "uconnect_topic_sas": (c_size_t, [_node_p, _TopicId, _DevId, POINTER(c_char), c_size_t]),
    "uconnect_topic_channel_binding": (c_bool, [_node_p, _TopicId, _DevId, POINTER(c_uint8)]),

    "uconnect_topic_queue_events": (None, [_node_p, _TopicId]),
    "uconnect_node_next_event": (POINTER(_Event), [_node_p, c_uint32]),
    "uconnect_event_free": (None, [POINTER(_Event)]),
}

for _name, (_res, _args) in _PROTOTYPES.items():
    _fn = getattr(_lib, _name)
    _fn.restype = _res
    _fn.argtypes = _args


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class UconnectError(Exception):
    pass


def last_error() -> str:
    return _lib.uconnect_last_error().decode("utf-8", "replace")


def max_message() -> int:
    return _lib.uconnect_max_message()


def _topic_id(raw: bytes) -> _TopicId:
    return _TopicId.from_buffer_copy(raw)


def _dev_id(raw: bytes) -> _DevId:
    return _DevId.from_buffer_copy(raw)


def _buffer(data: bytes):
    """A (pointer, length) pair for bytes, as the C API takes them."""
    if not data:
        return None, 0
    return (c_uint8 * len(data)).from_buffer_copy(data), len(data)


def _list_peers(handle) -> Optional[List["Peer"]]:
    if not handle:
        return None
    try:
        out = []
        info = _PeerInfo()
        for i in range(_lib.uconnect_peer_list_size(handle)):
            if _lib.uconnect_peer_list_get(handle, i, byref(info)):
                meta = ctypes.string_at(info.meta, info.meta_len) if info.meta_len else b""
                out.append(Peer(bytes(info.dev_id.bytes), info.age_s, info.stale, meta))
        return out
    finally:
        _lib.uconnect_peer_list_free(handle)


# ---------------------------------------------------------------------------
# The Python API
# ---------------------------------------------------------------------------
@dataclass
class Peer:
    dev_id: bytes
    age_s: int
    stale: bool
    meta: bytes


@dataclass
class Event:
    kind: EventKind
    topic: bytes
    dev: bytes
    peer_state: PeerState
    datagram_path: DatagramPath
    peer_gone: PeerGone
    data: bytes


class Creds:
    """Topic credentials: a public id, and for a keyed topic a secret key."""

    def __init__(self, raw: _Creds):
        self._raw = raw

    @classmethod
    def generate(cls, keyed: bool = True) -> "Creds":
        raw = _Creds()
        if not _lib.uconnect_creds_generate(keyed, byref(raw)):
            raise UconnectError(last_error())
        return cls(raw)

    @classmethod
    def parse(cls, uri: str) -> "Creds":
        raw = _Creds()
        if not _lib.uconnect_creds_parse(uri.encode(), byref(raw)):
            raise UconnectError(f"not a uconn:// URI: {uri!r}")
        return cls(raw)

    @property
    def id(self) -> bytes:
        return bytes(self._raw.id.bytes)

    @property
    def keyed(self) -> bool:
        return self._raw.keyed

    def to_uri(self) -> str:
        buf = ctypes.create_string_buffer(URI_MAX)
        _lib.uconnect_creds_to_uri(byref(self._raw), buf, URI_MAX)
        return buf.value.decode()


class Topic:
    """A joined topic: a node and a topic id, and nothing that can dangle."""

    def __init__(self, node: "Node", topic_id: bytes):
        self._node = node
        self.id = topic_id
        self._tid = _topic_id(topic_id)

    @property
    def _h(self):
        return self._node._handle()

    def publish(self, meta: bytes = b"", unlisted: bool = False) -> bool:
        ptr, n = _buffer(meta)
        return _lib.uconnect_topic_publish(self._h, self._tid, ptr, n, unlisted)

    def unpublish(self) -> None:
        _lib.uconnect_topic_unpublish(self._h, self._tid)

    def self_id(self) -> Optional[bytes]:
        dev = _DevId()
        return bytes(dev.bytes) if _lib.uconnect_topic_self(self._h, self._tid, byref(dev)) else None

    def peers(self, max: int = 30, want_meta: bool = False,
              timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Optional[List[Peer]]:
        """A sample of the topic's peers; None if the lookup itself failed."""
        return _list_peers(_lib.uconnect_topic_peers(self._h, self._tid, max, want_meta, timeout_ms))

    def resolve(self, dev: bytes, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Optional[Peer]:
        got = _list_peers(_lib.uconnect_topic_resolve(self._h, self._tid, _dev_id(dev), timeout_ms))
        return got[0] if got else None

    def connect(self, dev: bytes) -> None:
        _lib.uconnect_topic_connect(self._h, self._tid, _dev_id(dev))

    def connect_all(self, max_peers: int = 8) -> None:
        _lib.uconnect_topic_connect_all(self._h, self._tid, max_peers)

    def disconnect(self, dev: bytes) -> None:
        _lib.uconnect_topic_disconnect(self._h, self._tid, _dev_id(dev))

    def connected(self) -> List[bytes]:
        n = _lib.uconnect_topic_connected(self._h, self._tid, None, 0)
        devs = (_DevId * max(n, 1))()
        n = min(n, _lib.uconnect_topic_connected(self._h, self._tid, devs, n))
        return [bytes(devs[i].bytes) for i in range(n)]

    def state(self, dev: bytes) -> PeerState:
        return PeerState(_lib.uconnect_topic_state(self._h, self._tid, _dev_id(dev)))

    def link(self, dev: bytes) -> Optional[dict]:
        li = _LinkInfo()
        if not _lib.uconnect_topic_link(self._h, self._tid, _dev_id(dev), byref(li)):
            return None
        return {name: getattr(li, name) for name, _ in _LinkInfo._fields_}

    def send(self, dev: bytes, data: bytes) -> bool:
        ptr, n = _buffer(data)
        return _lib.uconnect_topic_send(self._h, self._tid, _dev_id(dev), ptr, n)

    def broadcast(self, data: bytes) -> int:
        ptr, n = _buffer(data)
        return _lib.uconnect_topic_broadcast(self._h, self._tid, ptr, n)

    def is_authenticated(self) -> bool:
        return _lib.uconnect_topic_is_authenticated(self._h, self._tid)

    def sas(self, dev: bytes) -> Optional[str]:
        buf = ctypes.create_string_buffer(64)
        n = _lib.uconnect_topic_sas(self._h, self._tid, _dev_id(dev), buf, len(buf))
        return buf.value.decode() if n else None

    def queue_events(self) -> None:
        """Deliver this topic's events through Node.next_event()."""
        _lib.uconnect_topic_queue_events(self._h, self._tid)

    def leave(self) -> None:
        _lib.uconnect_node_leave(self._h, self._tid)


class Node:
    def __init__(self, server: str, *, force_relay: bool = False, verbose: bool = False):
        cfg = _NodeConfig()
        _lib.uconnect_node_config_init(byref(cfg))
        self._server = server.encode()  # kept alive for the call; the library copies it
        cfg.server = self._server
        cfg.force_relay = force_relay
        cfg.verbose = verbose
        self._h = _lib.uconnect_node_new(byref(cfg))
        if not self._h:
            raise UconnectError(last_error())

    def _handle(self):
        if not self._h:
            raise UconnectError("node is closed")
        return self._h

    def __enter__(self) -> "Node":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def run_in_background(self) -> None:
        _lib.uconnect_node_run_in_background(self._handle())

    def shutdown(self) -> None:
        _lib.uconnect_node_shutdown(self._handle())

    def close(self) -> None:
        """Shut down and free the node. Nothing may be using it on another thread."""
        if self._h:
            _lib.uconnect_node_free(self._h)
            self._h = None

    @property
    def local_port(self) -> int:
        return _lib.uconnect_node_local_port(self._handle())

    def server_connected(self) -> bool:
        return _lib.uconnect_node_server_connected(self._handle())

    def stats(self, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Optional[dict]:
        s = _ServerStats()
        if not _lib.uconnect_node_stats(self._handle(), timeout_ms, byref(s)):
            return None
        return {name: getattr(s, name) for name in _STATS_FIELDS}

    def join(self, creds: Creds) -> Topic:
        if not _lib.uconnect_node_join(self._handle(), byref(creds._raw)):
            raise UconnectError(last_error() or "join refused: node is shut down")
        return Topic(self, creds.id)

    def topics(self) -> List[bytes]:
        n = _lib.uconnect_node_topics(self._handle(), None, 0)
        ids = (_TopicId * max(n, 1))()
        n = min(n, _lib.uconnect_node_topics(self._handle(), ids, n))
        return [bytes(ids[i].bytes) for i in range(n)]

    def next_event(self, timeout_ms: int = 0) -> Optional[Event]:
        """The next queued event, or None on timeout or once shut down and drained."""
        p = _lib.uconnect_node_next_event(self._handle(), timeout_ms)
        if not p:
            return None
        try:
            e = p.contents
            return Event(
                kind=EventKind(e.kind),
                topic=bytes(e.topic.bytes),
                dev=bytes(e.dev.bytes),
                peer_state=PeerState(e.peer_state),
                datagram_path=DatagramPath(e.datagram_path),
                peer_gone=PeerGone(e.peer_gone),
                data=ctypes.string_at(e.data, e.len) if e.len else b"",
            )
        finally:
            _lib.uconnect_event_free(p)


def peer_state_name(s: PeerState) -> str:
    return _lib.uconnect_peer_state_name(s).decode()


def peer_gone_name(g: PeerGone) -> str:
    return _lib.uconnect_peer_gone_name(g).decode()
