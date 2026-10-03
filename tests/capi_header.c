// Compiled as C, not C++. uconnect_c.h exists for C callers, and nothing else
// in the build would notice if it stopped compiling as C.
#include "uconnect/uconnect_c.h"

size_t uconnect_capi_header_compiles_as_c(void);

size_t uconnect_capi_header_compiles_as_c(void) {
    uconnect_node_config cfg;
    uconnect_node_config_init(&cfg);
    return sizeof cfg + sizeof(uconnect_event) + sizeof(uconnect_peer_info);
}
