#ifndef FORT_SERVER_PRIVATE_H
#define FORT_SERVER_PRIVATE_H

// Apparently, there's no way in Platformio to set up private includes for
// a library, so I'll just remind that it's all internal logic that shouldn't
// be included in your project.

#include "fort-server.h"

#include "stdint.h"
#include "stddef.h"
#include "assert.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#define FORT_TASK_NAME     "fort-task"
#define FORT_TASK_PRIO     10
#define FORT_TASK_STACK    1024

// Timeout in ms for HELLO and SHUTD handshake responses
#define FORT_REPONSE_TIMEOUT 15000

#define FORT_EVT_SERVER_HELLO  (1 << 0)
#define FORT_EVT_GATEWAY_HELLO (2 << 0)
#define FORT_EVT_GATEWAY_BINDR (3 << 0)
#define FORT_EVT_GATEWAY_SHUTD (4 << 0)

#if FORT_EXTRA_DEBUG
#define STATE_FMT_SPEC "%s"
#define STATE_FMT(state) fort_state_to_str(state)
#else
#define STATE_FMT_SPEC "0x%X"
#define STATE_FMT(state) ((unsigned int)(state))
#endif

#define EXPECT_STATE(sess_ptr, state_)                                  \
if ((sess_ptr)->state != (state_)) {                                    \
    ESP_LOGE(TAG,                                                       \
        "Wrong state: expected " STATE_FMT_SPEC ", got" STATE_FMT_SPEC, \
        STATE_FMT(state_), STATE_FMT((sess_ptr)->state));               \
    return FORT_ERR_WRONG_STATE;                                                          \
}

typedef struct {
    SemaphoreHandle_t api_lock;
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
} packet_type;

// Are we okay with misaligned memory access on ESP32?
typedef struct __attribute__ ((__packed__)) {
    uint8_t packet_type;
    uint16_t port;
    uint16_t data_length;
} fort_header;

static_assert(sizeof(fort_header) == 5, "fort_header is not fully packed");


// utility functions for sending/receiving the set amount of data (blocking)
// socket close is treated as an error even if all the data is sent/received
static inline fort_error fort_send_all(int socket, void *buffer, size_t len, int flags);
static inline fort_error fort_recv_all(int socket, void *buffer, size_t len, int flags);

#if FORT_EXTRA_DEBUG
const char *fort_state_to_str(fort_state state);
#endif

fort_error fort_do_connect(fort_session *sess, const char *hostname, const uint16_t port);
fort_error fort_do_listen(fort_session *sess, const uint16_t port, const int backlog);
fort_error fort_do_disconnect(fort_session *sess);
fort_error fort_do_end(fort_session *sess);

ssize_t receive_packet_step(fort_session *sess, char **response);
ssize_t handle_packet(fort_session *sess, const fort_header *hdr, const void *data, char **response);
void fort_task(void *parameters);

#endif // FORT_SERVER_PRIVATE_H
