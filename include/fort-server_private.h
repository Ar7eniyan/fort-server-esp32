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

#define FORT_EVT_SERVER_HELLO  (1 << 0)
#define FORT_EVT_GATEWAY_HELLO (2 << 0)
#define FORT_EVT_GATEWAY_BINDR (3 << 0)

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
static inline ssize_t send_all(int socket, void *buffer, size_t len, int flags);
static inline ssize_t recv_all(int socket, void *buffer, size_t len, int flags);

int fort_do_connect(fort_session *sess, const char *hostname, const uint16_t port);
int fort_do_listen(fort_session *sess, const uint16_t port, const int backlog);

ssize_t receive_packet_step(fort_session *sess, char **response);
ssize_t handle_packet(fort_session *sess, const fort_header *hdr, const void *data, char **response);
void fort_task(void *parameters);

#endif // FORT_SERVER_PRIVATE_H
