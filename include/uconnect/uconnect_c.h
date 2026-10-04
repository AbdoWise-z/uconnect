#pragma once
// uConnect C API: a flat C ABI over uconnect.hpp, for FFI callers (Dart,
// Python, Rust, C#) that cannot call C++ directly. Built as the shared library
// uconnect_c.
//
//   uconnect_node_config cfg;
//   uconnect_node_config_init(&cfg);
//   cfg.server = "rv.example.com:4433";
//   uconnect_node* node = uconnect_node_new(&cfg);
//   uconnect_node_run_in_background(node);
//
//   uconnect_topic_creds creds;
//   uconnect_creds_parse("uconn://<32hex>#<64hex>", &creds);
//   uconnect_node_join(node, &creds);
//   uconnect_topic_on_data(node, creds.id, my_on_data, my_ctx);
//   uconnect_topic_publish(node, creds.id, meta, meta_len, false);
//   uconnect_topic_connect_all(node, creds.id, 8);
//   uconnect_topic_broadcast(node, creds.id, payload, payload_len);
//
//   uconnect_node_free(node);  // shuts down
//
// Semantics are those of uconnect.hpp; the comments here cover only what the C
// boundary changes. In particular:
//
// Topics by id. Where C++ hands out a Topic&, which dangles after leave() or
// shutdown(), this API names a topic by its uconnect_topic_id on every call.
// A topic that is not joined -- never was, was left, or went with a shutdown
// -- is not an error, just absent: calls on it do nothing and return false,
// 0, NULL, or the "unknown"/"none" enum value. A call already running on a
// topic finishes before leave or shutdown takes it away, so leave can wait
// out a blocking call (peers, resolve, publish) for up to its timeout.
//
// Errors. No C++ exception crosses this boundary. A call that caught one
// fails in its ordinary way and leaves the message in uconnect_last_error().
//
// Defaults. C has no default arguments, so every parameter is explicit.
// UCONNECT_DEFAULT_TIMEOUT_MS is the C++ API's default timeout.
//
// Threads. Callbacks run on the node's loop thread, as in C++, and the same
// calls are rejected there (see Topic's "events" section). Runtimes that
// cannot take a call on a foreign thread -- Dart is one -- should not register
// callbacks at all, and drain an event queue instead: see "Event queue".
//
// Buffers. Variable-length results use one of two shapes. Bounded ones are
// written into a caller array and the call returns the total available, which
// may exceed the capacity (as snprintf does). Ones carrying per-item byte
// payloads come back as an owned list object with its own free function.
//
// NULL. A NULL node is treated as one with nothing joined. A NULL data pointer
// is accepted only with a length of 0.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(UCONNECT_STATIC)
#  ifdef UCONNECT_C_BUILD
#    define UCONNECT_API __declspec(dllexport)
#  else
#    define UCONNECT_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__)
#  define UCONNECT_API __attribute__((visibility("default")))
#else
#  define UCONNECT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define UCONNECT_DEFAULT_TIMEOUT_MS 3000u

// "uconn://" + 32 hex + "#" + 64 hex + NUL: the longest URI to_uri can write.
#define UCONNECT_URI_MAX 106u

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------
// Fixed-size identifiers are wrapped in structs so they pass by value and
// cannot be confused with one another or with a bare pointer.
typedef struct { uint8_t bytes[16]; } uconnect_topic_id;
typedef struct { uint8_t bytes[16]; } uconnect_dev_id;
typedef struct { uint8_t bytes[32]; } uconnect_key;

// The numeric values match the C++ enums one for one.
typedef enum {
    UCONNECT_TOPIC_OPEN  = 0,
    UCONNECT_TOPIC_KEYED = 1,
} uconnect_topic_mode;

typedef enum {
    UCONNECT_PEER_UNKNOWN     = 0,
    UCONNECT_PEER_PROBING     = 1,
    UCONNECT_PEER_HANDSHAKING = 2,
    UCONNECT_PEER_CONNECTED   = 3,
    UCONNECT_PEER_FAILED      = 4,
    UCONNECT_PEER_CLOSED      = 5,
} uconnect_peer_state;

typedef enum {
    UCONNECT_GONE_LOCAL         = 0,
    UCONNECT_GONE_TIMED_OUT     = 1,
    UCONNECT_GONE_GOING_AWAY    = 2,
    UCONNECT_GONE_SHUTTING_DOWN = 3,
    UCONNECT_GONE_UNSPECIFIED   = 4,
} uconnect_peer_gone;

typedef enum {
    UCONNECT_DATAGRAM_FALLBACK_TCP   = 0,
    UCONNECT_DATAGRAM_FALLBACK_RELAY = 1,
    UCONNECT_DATAGRAM_FALLBACK_NONE  = 2,
} uconnect_datagram_fallback;

typedef enum {
    UCONNECT_DATAGRAM_PATH_NONE    = 0,
    UCONNECT_DATAGRAM_PATH_OPENING = 1,
    UCONNECT_DATAGRAM_PATH_DIRECT  = 2,
    UCONNECT_DATAGRAM_PATH_RELAYED = 3,
    UCONNECT_DATAGRAM_PATH_TCP     = 4,
    UCONNECT_DATAGRAM_PATH_FAILED  = 5,
} uconnect_datagram_path;

// Static strings; never freed.
UCONNECT_API const char* uconnect_peer_state_name(uconnect_peer_state);
UCONNECT_API const char* uconnect_peer_gone_name(uconnect_peer_gone);
UCONNECT_API const char* uconnect_datagram_path_name(uconnect_datagram_path);

typedef struct {
    uint8_t  family;     // 4 or 6
    uint8_t  addr[16];   // v4 occupies addr[0..3]
    uint16_t port;       // host byte order
} uconnect_endpoint;

typedef struct {
    uconnect_topic_id   id;
    uconnect_topic_mode mode;
    uint32_t            peers;
    uint32_t            fresh_peers;
} uconnect_topic_summary;

typedef struct {
    uint64_t topics_total, topics_listed;
    uint64_t entries_total, entries_fresh;
    uint64_t registers, lookups, connects, expired;
    uint64_t rej_quota, rej_rate_limited;
    uint64_t relays_open, relays_allocated, relay_bytes;
    uint64_t connections;
} uconnect_server_stats;

typedef struct {
    bool relayed;

    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;

    uint64_t datagrams_sent;
    uint64_t datagrams_received;
} uconnect_link_info;

// Message and datagram size limits; Topic::max_message() and max_datagram().
UCONNECT_API size_t uconnect_max_message(void);
UCONNECT_API size_t uconnect_max_datagram(void);

// Check this right after a call fails: it holds the message when that call
// failed by catching an exception, and is empty when it failed in an ordinary
// way. Valid until the next uconnect call on this thread.
UCONNECT_API const char* uconnect_last_error(void);

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
typedef struct {
    uconnect_topic_id id;
    bool              keyed;  // false => open topic, and `key` is ignored
    uconnect_key      key;
} uconnect_topic_creds;

// False only if the system could not supply randomness; see uconnect_last_error.
UCONNECT_API bool uconnect_creds_generate(bool keyed, uconnect_topic_creds* out);

// uri is NUL-terminated. False if it is not a valid uconn:// URI.
UCONNECT_API bool uconnect_creds_parse(const char* uri, uconnect_topic_creds* out);

// Writes the NUL-terminated URI into buf and returns its length without the
// NUL, snprintf-style: a return >= cap means it was truncated.
// UCONNECT_URI_MAX is always enough.
UCONNECT_API size_t uconnect_creds_to_uri(const uconnect_topic_creds*, char* buf, size_t cap);

// ---------------------------------------------------------------------------
// Peer lists
// ---------------------------------------------------------------------------
// The result of a lookup. Owns each peer's meta bytes; the pointers in a
// uconnect_peer_info stay valid until the list is freed.
typedef struct uconnect_peer_list uconnect_peer_list;

typedef struct {
    uconnect_dev_id dev_id;
    uint32_t        age_s;
    bool            stale;
    const uint8_t*  meta;      // NULL when meta_len is 0
    size_t          meta_len;  // 0 unless meta was asked for, or resolved
} uconnect_peer_info;

UCONNECT_API size_t uconnect_peer_list_size(const uconnect_peer_list*);
// False if index is out of range.
UCONNECT_API bool   uconnect_peer_list_get(const uconnect_peer_list*, size_t index,
                                           uconnect_peer_info* out);
UCONNECT_API void   uconnect_peer_list_free(uconnect_peer_list*);  // NULL is a no-op

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------
typedef struct uconnect_node uconnect_node;

// Mirrors Node::Config. Durations are in whole seconds, as there.
typedef struct {
    const char*                server;  // required: host:port; copied by uconnect_node_new
    uint16_t                   bind_port;
    uint32_t                   keepalive_s;
    size_t                     max_total_peers;
    uint32_t                   punch_timeout_s;
    bool                       force_relay;
    bool                       verbose;
    uconnect_datagram_fallback datagram_fallback;
    uint8_t                    rekey_shift;
} uconnect_node_config;

// Fills every field with Node::Config's defaults and sets server to NULL.
// Always start from this rather than a zeroed struct: zero is not the default
// for several fields, and rekey_shift = 0 is rejected.
UCONNECT_API void uconnect_node_config_init(uconnect_node_config*);

// NULL on failure -- a bad config, a port that cannot be bound, a server name
// that does not resolve -- with the reason in uconnect_last_error.
UCONNECT_API uconnect_node* uconnect_node_new(const uconnect_node_config*);

// Shuts the node down if it is running, then frees it and any events still
// queued. Never call this from a callback, nor while another thread may still
// be inside a call on this node -- an event consumer included: shut down
// first, which wakes it, and let it return. NULL is a no-op.
UCONNECT_API void uconnect_node_free(uconnect_node*);

// --- lifecycle -------------------------------------------------------------
UCONNECT_API void     uconnect_node_run(uconnect_node*);  // blocking
UCONNECT_API void     uconnect_node_run_in_background(uconnect_node*);
// Also leaves every topic, as far as this API is concerned: from here on no
// topic is joined, and joining fails.
UCONNECT_API void     uconnect_node_shutdown(uconnect_node*);
UCONNECT_API bool     uconnect_node_is_running(const uconnect_node*);
UCONNECT_API uint16_t uconnect_node_local_port(const uconnect_node*);
UCONNECT_API bool     uconnect_node_reflexive(const uconnect_node*, uconnect_endpoint* out);
UCONNECT_API bool     uconnect_node_server_connected(const uconnect_node*);
UCONNECT_API size_t   uconnect_node_pending_requests(const uconnect_node*);

// --- discovery without joining ---------------------------------------------
// Node::explore: writes up to `cap` summaries (cap is the C++ `limit`) and
// returns how many it wrote -- on failure, however many it had.
UCONNECT_API size_t uconnect_node_explore(uconnect_node*, uint32_t cursor,
                                          uconnect_topic_summary* out, size_t cap,
                                          uint32_t timeout_ms);
// Node::try_explore: false when any request it needed failed, where explore
// returns a partial listing. On success *count is how many it wrote.
UCONNECT_API bool   uconnect_node_try_explore(uconnect_node*, uint32_t cursor,
                                              uconnect_topic_summary* out, size_t cap,
                                              uint32_t timeout_ms, size_t* count);
UCONNECT_API bool   uconnect_node_stats(uconnect_node*, uint32_t timeout_ms,
                                        uconnect_server_stats* out);

// --- topics ----------------------------------------------------------------
// Joining a topic already joined is a no-op that succeeds, keeping the
// credentials it was first joined with. False after shutdown.
UCONNECT_API bool uconnect_node_join(uconnect_node*, const uconnect_topic_creds*);
// Generates credentials, joins with them, and writes them to *out.
UCONNECT_API bool uconnect_node_create(uconnect_node*, bool keyed, uconnect_topic_creds* out);
UCONNECT_API void uconnect_node_leave(uconnect_node*, uconnect_topic_id);

// Joined topic ids into out[0..cap); returns how many are joined.
UCONNECT_API size_t uconnect_node_topics(const uconnect_node*, uconnect_topic_id* out, size_t cap);
// False if the topic is not joined; doubles as the membership test.
UCONNECT_API bool   uconnect_node_creds(const uconnect_node*, uconnect_topic_id,
                                        uconnect_topic_creds* out);

// ---------------------------------------------------------------------------
// Topic
// ---------------------------------------------------------------------------
// Every call names its topic by id; see "Topics by id" above.

// --- membership ------------------------------------------------------------
UCONNECT_API bool uconnect_topic_publish(uconnect_node*, uconnect_topic_id,
                                         const uint8_t* meta, size_t meta_len, bool unlisted);
UCONNECT_API void uconnect_topic_unpublish(uconnect_node*, uconnect_topic_id);
// False until published.
UCONNECT_API bool uconnect_topic_self(const uconnect_node*, uconnect_topic_id,
                                      uconnect_dev_id* out);

// --- discovery -------------------------------------------------------------
// Topic::try_peers: NULL when the lookup itself failed, an empty list when the
// topic is empty. (Topic::peers() is this with NULL read as empty.)
UCONNECT_API uconnect_peer_list* uconnect_topic_peers(uconnect_node*, uconnect_topic_id,
                                                      uint8_t max, bool want_meta,
                                                      uint32_t timeout_ms);
// A one-entry list, or NULL if the peer was not found or the lookup failed.
UCONNECT_API uconnect_peer_list* uconnect_topic_resolve(uconnect_node*, uconnect_topic_id,
                                                        uconnect_dev_id, uint32_t timeout_ms);

// --- connections -----------------------------------------------------------
UCONNECT_API void uconnect_topic_connect(uconnect_node*, uconnect_topic_id, uconnect_dev_id);
UCONNECT_API void uconnect_topic_connect_all(uconnect_node*, uconnect_topic_id, size_t max_peers);
UCONNECT_API void uconnect_topic_disconnect(uconnect_node*, uconnect_topic_id, uconnect_dev_id);
UCONNECT_API void uconnect_topic_disconnect_all(uconnect_node*, uconnect_topic_id);

// Connected dev ids into out[0..cap); returns how many are connected.
UCONNECT_API size_t              uconnect_topic_connected(const uconnect_node*, uconnect_topic_id,
                                                          uconnect_dev_id* out, size_t cap);
UCONNECT_API uconnect_peer_state uconnect_topic_state(const uconnect_node*, uconnect_topic_id,
                                                      uconnect_dev_id);
// False if there is no live session.
UCONNECT_API bool                uconnect_topic_link(const uconnect_node*, uconnect_topic_id,
                                                     uconnect_dev_id, uconnect_link_info* out);

// --- messages --------------------------------------------------------------
UCONNECT_API bool   uconnect_topic_send(uconnect_node*, uconnect_topic_id, uconnect_dev_id,
                                        const uint8_t* data, size_t len);
UCONNECT_API size_t uconnect_topic_broadcast(uconnect_node*, uconnect_topic_id,
                                             const uint8_t* data, size_t len);

// --- datagrams -------------------------------------------------------------
UCONNECT_API bool uconnect_topic_open_datagrams(uconnect_node*, uconnect_topic_id,
                                                uconnect_dev_id, uconnect_datagram_fallback);
UCONNECT_API void uconnect_topic_close_datagrams(uconnect_node*, uconnect_topic_id,
                                                 uconnect_dev_id);
UCONNECT_API uconnect_datagram_path uconnect_topic_datagram_path(const uconnect_node*,
                                                                 uconnect_topic_id,
                                                                 uconnect_dev_id);
// len must be 1..uconnect_max_datagram(); an empty payload returns false on every path.
UCONNECT_API bool uconnect_topic_send_datagram(uconnect_node*, uconnect_topic_id,
                                               uconnect_dev_id, const uint8_t* data, size_t len);

// --- callbacks -------------------------------------------------------------
// Invoked on the node's loop thread; do not block. `data` is valid only for
// the duration of the call -- copy what you keep. Passing a NULL fn clears the
// callback; registering one replaces the queue for that kind of event if
// uconnect_topic_queue_events was called.
//
// An event already queued inside the node when a callback is replaced, or its
// topic left, is still delivered to the old one. Keep `user` valid until
// uconnect_node_free returns.
typedef void (*uconnect_peer_fn)(void* user, uconnect_dev_id dev, uconnect_peer_state state);
typedef void (*uconnect_bytes_fn)(void* user, uconnect_dev_id dev,
                                  const uint8_t* data, size_t len);
typedef void (*uconnect_datagram_path_fn)(void* user, uconnect_dev_id dev,
                                          uconnect_datagram_path path);
typedef void (*uconnect_peer_closed_fn)(void* user, uconnect_dev_id dev, uconnect_peer_gone why);

UCONNECT_API void uconnect_topic_on_peer(uconnect_node*, uconnect_topic_id,
                                         uconnect_peer_fn, void* user);
UCONNECT_API void uconnect_topic_on_data(uconnect_node*, uconnect_topic_id,
                                         uconnect_bytes_fn, void* user);
UCONNECT_API void uconnect_topic_on_datagram(uconnect_node*, uconnect_topic_id,
                                             uconnect_bytes_fn, void* user);
UCONNECT_API void uconnect_topic_on_datagram_path(uconnect_node*, uconnect_topic_id,
                                                  uconnect_datagram_path_fn, void* user);
UCONNECT_API void uconnect_topic_on_peer_closed(uconnect_node*, uconnect_topic_id,
                                                uconnect_peer_closed_fn, void* user);

// --- policy ----------------------------------------------------------------
UCONNECT_API void uconnect_topic_set_max_peers(uconnect_node*, uconnect_topic_id, size_t);
UCONNECT_API void uconnect_topic_set_auto_connect(uconnect_node*, uconnect_topic_id, bool);

// --- identity --------------------------------------------------------------
UCONNECT_API bool uconnect_topic_is_authenticated(const uconnect_node*, uconnect_topic_id);

// Writes the NUL-terminated SAS and returns its length, snprintf-style; 0 if
// there is none (a keyed topic, or no connected peer).
UCONNECT_API size_t uconnect_topic_sas(const uconnect_node*, uconnect_topic_id, uconnect_dev_id,
                                       char* buf, size_t cap);
// False if there is no live session.
UCONNECT_API bool   uconnect_topic_channel_binding(const uconnect_node*, uconnect_topic_id,
                                                   uconnect_dev_id, uint8_t out[32]);

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------
// The alternative to callbacks for runtimes that must not be entered from a
// foreign thread. A topic switched over with uconnect_topic_queue_events
// posts all five kinds of event to its node's queue, replacing any callbacks;
// the application drains the queue from a thread of its own.
//
// The queue is unbounded. Drain it promptly: a stalled consumer holds every
// received message in memory, since nothing pushes back on the senders. An
// event that cannot be allocated is dropped.
typedef enum {
    UCONNECT_EVENT_PEER          = 0,  // peer_state
    UCONNECT_EVENT_DATA          = 1,  // data, len
    UCONNECT_EVENT_DATAGRAM      = 2,  // data, len
    UCONNECT_EVENT_DATAGRAM_PATH = 3,  // datagram_path
    UCONNECT_EVENT_PEER_CLOSED   = 4,  // peer_gone
} uconnect_event_kind;

// Only the fields named against `kind` above are meaningful. `topic` may name
// a topic since left, for events queued before the leave.
typedef struct {
    uconnect_event_kind    kind;
    uconnect_topic_id      topic;
    uconnect_dev_id        dev;
    uconnect_peer_state    peer_state;
    uconnect_datagram_path datagram_path;
    uconnect_peer_gone     peer_gone;
    const uint8_t*         data;  // owned by the event; NULL when len is 0
    size_t                 len;
} uconnect_event;

UCONNECT_API void uconnect_topic_queue_events(uconnect_node*, uconnect_topic_id);

// The next event, waiting up to timeout_ms (0 = do not wait). NULL on timeout,
// and immediately whenever the queue is empty once uconnect_node_shutdown has
// been called -- which also wakes a consumer blocked here, so a consumer loop
// can run until it sees NULL after asking for shutdown. Free each event
// returned.
UCONNECT_API uconnect_event* uconnect_node_next_event(uconnect_node*, uint32_t timeout_ms);
UCONNECT_API void            uconnect_event_free(uconnect_event*);  // NULL is a no-op

#ifdef __cplusplus
}  // extern "C"
#endif
