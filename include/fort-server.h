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
    // Normal operation
    FORT_ERR_OK = 0,
    // Gateway closed service socket
    FORT_ERR_SOCKET_CLOSED = -1,
    // Error in recv()
    FORT_ERR_RECV = -2,
    // Error in send()
    FORT_ERR_SEND = -3,
    // Error in getaddrinfo()
    FORT_ERR_GETAI = -4,
    // Error in socket()
    FORT_ERR_SOCKET = -5,
    // Error in connect()
    FORT_ERR_CONNECT = -6,
    // Gateway failed to bind to a requested port, try a different port
    FORT_ERR_GATEWAY_BIND = -7,
    // fort_accept() timed out
    FORT_ERR_TIMEOUT = -8,
    // Unexpected session state
    FORT_ERR_WRONG_STATE = -9,
    // Accept queue is full
    FORT_ERR_QUEUE_FULL = -10,
} fort_error;

// TODO: hide the implementation to restrict a user to the public API
typedef struct {
    // Critical errors that don't occur during normal functioning    
    fort_error error;
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
fort_error fort_begin(void);

// connect to the gateway, open a session
fort_error fort_connect(const char *hostname, const uint16_t port);

// bind to a port and listen with a backlog in a single function
fort_error fort_bind_and_listen(uint16_t port, int backlog);

int fort_accept(uint64_t timeout_ms);

fort_error fort_disconnect(void);

// close the service socket and other resources, cleanup the session for next use
fort_error fort_end(void);

fort_error fort_clear_error(void);

fort_state fort_current_state(void);

const char *fort_strerror(fort_error err);


// This implementation supports only one session.
// Seriously, why would you need more on ESP32?
extern fort_session fort_main_session;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // FORT_SERVER_H