#ifndef FORT_SERVER_H
#define FORT_SERVER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>

#include <freertos/event_groups.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FORT_STATE_IDLE, 
    FORT_STATE_HELLO_SENT,
    FORT_STATE_HELLO_RECEIVED,
    FORT_STATE_BOUND,
    FORT_STATE_CLOSING,
    FORT_STATE_CLOSED,
} fort_state;

typedef enum {
    FORT_ERR_OK = 0,
    FORT_ERR_SOCKCLOSED = -1,
    FORT_ERR_RECV = -2,
    FORT_ERR_SEND = -3,
} fort_error;

typedef struct {
    int error;
    bool forwarding_enabled;
    fort_state state;
    
    // for fort_bind_and_listen()
    uint16_t gateway_bind_port;
    
    int service_socket;
    struct sockaddr_in gateway_addr;

    EventGroupHandle_t events;
    QueueHandle_t accept_queue;  // for `data` channel sockets
    SemaphoreHandle_t lock; 
} fort_session;

// Set up the main task, etc
int fort_begin(void);

// connect to the gateway, open a session
int fort_connect(const char *hostname, const uint16_t port);

// bind to a port and listen with a backlog in a single function
int fort_bind_and_listen(uint16_t port, int backlog);

int fort_accept(uint64_t timeout_ms);

int fort_disconnect(void);


// This implementation supports only one session.
// Seriously, why would you need more on ESP32?
extern fort_session fort_main_session;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // FORT_SERVER_H