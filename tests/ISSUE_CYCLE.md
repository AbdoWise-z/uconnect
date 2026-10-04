# GitHub issue regression cycle — 2026-10-04

Starting revision: `139188d`. Reviewed all 17 issues open at the start of the cycle.
The table below records the reproductions, fixes, and validation for this batch.

| Issue | Reproduction before the fix | Fix and regression coverage |
| --- | --- | --- |
| [24](https://github.com/AbdoWise-z/uconnect/issues/24) | 2,000 directory requests: 38.58 ms for 100 members, 5,125.36 ms for 10,000 members in the Windows debug build. | Maintain fresh counts and one expiry-index entry per fresh member. Remove hidden topics from the listing index. Existing stable-cursor regression retained; new tests cover refresh, update, expiry, re-registration and deletion. Same benchmark after the fix: 1.23 ms and 1.48 ms. |
| [56](https://github.com/AbdoWise-z/uconnect/issues/56) | Linux build using the Dockerfile's global `-static` flag failed linking the shared C API into the test executable. | Apply `UCONNECT_STATIC_SERVER` only to the shipped server. Linux builds tests and the shared C API, and `file` confirms that the server is statically linked. Docker's Linux engine was unavailable, so an actual Alpine image build remains unverified. |
| [57](https://github.com/AbdoWise-z/uconnect/issues/57) | `chat_metadata.py` registered ESC/C1 metadata against a real local server; `/peers` emitted it unchanged. | Sanitize directory metadata and roster names. The real chat executable must produce the marker without terminal controls. |
| [58](https://github.com/AbdoWise-z/uconnect/issues/58) | A 100-member lookup with maximum metadata and eight candidates produced an empty frame. | Fit the sample to the encoded frame budget, retaining the total. Cover IPv4 and IPv6. Encoding failure produces an explicit protocol error. |
| [59](https://github.com/AbdoWise-z/uconnect/issues/59) | C11 UBSan reported `left shift of negative value -13` in ordinary base-point multiplication. | Use bounded multiplication for the carry. Retain `x25519_ubsan.c`; rerun it and the existing crypto vectors. |
| [60](https://github.com/AbdoWise-z/uconnect/issues/60) | The session accepted and emitted an empty application datagram. | Reject empty application datagrams in both the session and public API; retain a private keepalive-send path. Tests cover direct UDP, relay UDP and TCP fallback. Document the 1–1100-byte range in C/C++ APIs and README. |
| [61](https://github.com/AbdoWise-z/uconnect/issues/61) | Flask returned HTTP 200 after a primed observer cache became stale on repeated server errors. | Health returns 503 on stale/error results; ordinary observer fallback remains available. Test outage and recovery. |
| [62](https://github.com/AbdoWise-z/uconnect/issues/62) | A valid ID followed by `#` parsed as an open invite. | Reject an empty key fragment, while preserving valid open and keyed invites. |
| [63](https://github.com/AbdoWise-z/uconnect/issues/63) | With a saturated local accept backlog, cancellation left pending dials alive past 500 ms. | Check cancellation before the connecting-state return, impose dial/relay deadlines and avoid duplicate outstanding dials to the same candidate. |
| [64](https://github.com/AbdoWise-z/uconnect/issues/64) | Silent inbound connections exceeded the configured test cap and the excess socket stayed open. | Bound pending inbound sockets globally and per IP, independently of established peers. Verify refusal and release after clients close. |
| [65](https://github.com/AbdoWise-z/uconnect/issues/65) | A fresh Windows process with a synchronized 16-thread start called intercepted `WSAStartup` 16 times. | Use thread-safe function-local initialization. The same test requires exactly one startup call and success for every caller. |
| [66](https://github.com/AbdoWise-z/uconnect/issues/66) | Extracting the existing unsynchronized nickname read/write into a test seam produced inconsistent snapshots and ThreadSanitizer race reports. | Use mutex-protected nickname snapshots for the network callback. The concurrent regression passes normally and under ThreadSanitizer. |
| [67](https://github.com/AbdoWise-z/uconnect/issues/67) | The real `deploy_web` function, run with temporary paths and fake service/venv commands, skipped pip when a matching hash outlived its venv. | Invalidate the dependency hash before recreating the environment. No installed service was touched. |
| [70](https://github.com/AbdoWise-z/uconnect/issues/70) | 199 distinct simulated UDP sources created 199 buckets despite a test limit of eight. | Refuse new source buckets when full; existing sources retain service. Test the cap, expiry and admission after expiry. |
| [73](https://github.com/AbdoWise-z/uconnect/issues/73) | Repeated lookup/resolve discovery of short-lived peers exceeded an eight-entry cache budget. | Evict the oldest inactive entries over the per-topic budget; retain sessions, attempts and scheduled retries. |
| [76](https://github.com/AbdoWise-z/uconnect/issues/76) | Three regressions failed: UDP relay tokens admitted as TCP, retained probe-key bytes after destruction, and unescaped CSV notes. The missing vector include was confirmed by inspection. | Check relay kind, erase the probe key on destruction, include `<vector>` directly, and quote CSV commas/quotes/newlines. |
| [77](https://github.com/AbdoWise-z/uconnect/issues/77) | A delayed successful registration after `publish()` timed out produced no cleanup request. | Transfer timed-out registration requests to bounded loop-owned reconciliation. Tests cover abandoned publication and a newer publish, with the control connection preserved. |

## Verification results

- Windows/MinGW: all 11 CTest checks passed, including all 258 C++ cases.
- Ubuntu/WSL: all 10 CTest checks passed across the full run and one rerun,
  including all 258 C++ cases. The first smoke-test attempt could not bind
  port 14433 because the concurrently running Windows smoke test held it.
  Rerunning that test alone passed in 18.52 seconds; no code change was needed.
- The full checks include direct/relay message and datagram transfers, the
  throughput smoke test, C API Python integration, and real chat metadata output.
- X25519 C11 UBSan and the nickname ThreadSanitizer regression passed.
- `git diff --check` passed.
- Actual Docker image construction was not tested: Docker's Linux engine was unavailable.

## Repeating verification

Publication verification on 2026-10-05, after rebasing onto `583534d` and
preserving seven newer upstream commits:

- Windows/MinGW: all 11 CTest checks passed, including 266 C++ cases. The
  interrupted full run completed checks 1-7; the resumed run passed checks 8-11.
- Ubuntu/WSL: the full CTest run passed all 10 checks, including 266 C++ cases.
- Both platforms rebuilt successfully. Separate `UC_PORT` values (24433 on
  Windows and 24434 on Linux) avoided the earlier cross-platform port collision.
- The Docker image-build limitation above still applies.

```sh
cmake --build <build>
ctest --test-dir <build> --output-on-failure
cmake --build <build> --target uconnect_listing_bench
<build>/tests/uconnect_listing_bench
```

The listing benchmark is deliberately separate from CTest because it measures elapsed time.
CTest includes the C++ suite, chat metadata, observer tests, available Flask health tests,
Windows networking initialization on MinGW, Linux deployment repair, and the existing
server, benchmark and end-to-end tests.

From a Linux shell at the repository root:

```sh
gcc -std=c11 -fsanitize=undefined -fno-sanitize-recover=undefined \
    -Ithird_party tests/x25519_ubsan.c third_party/x25519.c -o /tmp/x25519-ubsan
/tmp/x25519-ubsan
g++ -std=c++20 -pthread -fsanitize=thread -g \
    tests/test_main.cpp tests/test_chat.cpp -o /tmp/chat-tsan
TSAN_OPTIONS=halt_on_error=1 /tmp/chat-tsan issue66
python3 tests/deploy_web_venv.py
```
