#ifndef FORT_SERVER_PRIVATE_H
#define FORT_SERVER_PRIVATE_H

#include "fort-server.h"

// Apparently, there's no way in Platformio to set up private includes for
// a library, so I'll just remind that it's all internal logic that shouldn't
// be included in your project.

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define FORT_TASK_NAME  "fort-task"
#define FORT_TASK_PRIO  10
#define FORT_TASK_STACK 1024

// Timeout in ms for HELLO and SHUTD handshake responses
#define FORT_REPONSE_TIMEOUT 15000

#define FORT_EVT_SERVER_HELLO  (1 << 0)
#define FORT_EVT_GATEWAY_HELLO (2 << 0)
#define FORT_EVT_GATEWAY_BINDR (3 << 0)
#define FORT_EVT_GATEWAY_SHUTD (4 << 0)

#if FORT_EXTRA_DEBUG
#    define STATE_FMT_SPEC   "%s"
#    define STATE_FMT(state) fort_state_to_str(state)
#else
#    define STATE_FMT_SPEC   "0x%X"
#    define STATE_FMT(state) ((unsigned int)(state))
#endif

// TODO: make two versions: for incoming packets and for API functions
#define EXPECT_STATE(sess_ptr, state_)                             \
    if ((sess_ptr)->state != (state_)) {                           \
        ESP_LOGE(TAG,                                              \
                 "Wrong state: expected " STATE_FMT_SPEC           \
                 ", got" STATE_FMT_SPEC,                           \
                 STATE_FMT(state_), STATE_FMT((sess_ptr)->state)); \
        return FORT_ERR_WRONG_STATE;                               \
    }

typedef struct {
    TaskHandle_t fort_task;
} fort_globals_t;

extern fort_globals_t fort_globals;

// To be used in fort_header::packet_type
typedef enum {
    PACKET_HELLO = 0x01,
    PACKET_BINDR = 0x02,
    PACKET_OPENC = 0x03,
    PACKET_SHUTD = 0x04,
    PACKET_BLANK = 0x05,
    PACKET_MAX
} packet_type;

// Are we okay with misaligned memory access on ESP32?
typedef struct __attribute__((__packed__)) {
    uint8_t packet_type;
    uint16_t port;
    uint16_t data_length;
} fort_header;

static_assert(sizeof(fort_header) == 5, "fort_header is not fully packed");

// Packet handler function for a state machine.
// Arguments: session, header, data
typedef fort_error (*fort_pkt_handler)(fort_session *, const fort_header *,
                                       const void *);

fort_error fort_on_pkt_hello(fort_session *, const fort_header *, const void *);
fort_error fort_on_pkt_bindr(fort_session *, const fort_header *, const void *);
fort_error fort_on_pkt_openc(fort_session *, const fort_header *, const void *);
fort_error fort_on_pkt_shutd(fort_session *, const fort_header *, const void *);
fort_error fort_on_pkt_blank(fort_session *, const fort_header *, const void *);
// Called if the handler in the state machine table is NULL
fort_error fort_on_pkt_default(fort_session *, const fort_header *,
                               const void *);

// First index is the current state, second is the incoming packet type.
// All the elements are NULL by default, which invokes the default handler
// (print a warning and (TODO)disconnect if in strict mode)
// clang-format off
const fort_pkt_handler state_table[FORT_STATE_MAX][PACKET_MAX] = {
    [FORT_STATE_UNITIALIZED] = {},
    [FORT_STATE_IDLE] = {},
    [FORT_STATE_HELLO_SENT] = {
        [PACKET_HELLO] = fort_on_pkt_hello,
        [PACKET_BLANK] = fort_on_pkt_blank
    },
    [FORT_STATE_HELLO_RECEIVED] = {
        [PACKET_BINDR] = fort_on_pkt_bindr,
        [PACKET_SHUTD] = fort_on_pkt_shutd,
        [PACKET_BLANK] = fort_on_pkt_blank
    },
    [FORT_STATE_BOUND] = {
        [PACKET_OPENC] = fort_on_pkt_openc,
        [PACKET_SHUTD] = fort_on_pkt_shutd,
        [PACKET_BLANK] = fort_on_pkt_blank
    },
    [FORT_STATE_CLOSING] = {
        [PACKET_SHUTD] = fort_on_pkt_shutd,
        [PACKET_BLANK] = fort_on_pkt_blank
    },
    [FORT_STATE_CLOSED] = {},
};
// clang-format on

// utility functions for sending/receiving the set amount of data (blocking)
// socket close is treated as an error even if all the data is sent/received
inline static fort_error fort_send_all(int socket, void *buffer, size_t len,
                                       int flags);
inline static fort_error fort_recv_all(int socket, void *buffer, size_t len,
                                       int flags);

#if FORT_EXTRA_DEBUG
const char *fort_state_to_str(fort_state state);
#endif

fort_error fort_do_connect(fort_session *sess, const char *hostname,
                           const uint16_t port);
fort_error fort_do_listen(fort_session *sess, const uint16_t port,
                          const int backlog);
fort_error fort_do_disconnect(fort_session *sess);
fort_error fort_do_end(fort_session *sess);
fort_error fort_do_close(fort_session *sess);

fort_error receive_packet_step(fort_session *sess);
fort_error handle_packet(fort_session *sess, const fort_header *hdr,
                         const void *data);
void fort_task(void *parameters);

#endif  // FORT_SERVER_PRIVATE_H