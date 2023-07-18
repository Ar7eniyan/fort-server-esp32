#include "fort-server_private.h"
#include "fort-server.h"

#include "esp_log.h"

static const char *TAG = "fort-server";

ssize_t send_all(int socket, void *buffer, size_t len, int flags) {
    char *ptr = (char *)buffer;
    while (len) {
        ssize_t i = send(socket, ptr, len, flags);
        if (i < 1) return i;
        ptr += i;
        len -= i;
    }
    return ptr - (char *)buffer; // the same as len
}

ssize_t recv_all(int socket, void *buffer, size_t len, int flags) {
    char *ptr = (char *)buffer;
    while (len) {
        ssize_t i = recv(socket, ptr, len, flags);
        if (i < 1) return i;
        ptr += i;
        len -= i;
    }
    return ptr - (char *)buffer; // the same as len
}

ssize_t fort_send_all(int socket, void *buffer, size_t len, int flags)
{
    ssize_t rc = send_all(socket, buffer, len, flags);
    if (rc > 0) return rc;
    if (rc == 0) {
        ESP_LOGE(TAG, "Unexpected socket close");
        return FORT_ERR_SOCKCLOSED;
    }
    ESP_LOGE(TAG, "Socket send() error: %s", strerror(errno));
    return FORT_ERR_SEND;
}

ssize_t fort_recv_all(int socket, void *buffer, size_t len, int flags)
{
    ssize_t rc = recv_all(socket, buffer, len, flags);
    if (rc > 0) return rc;
    if (rc == 0) {
        ESP_LOGE(TAG, "Unexpected socket close");
        return FORT_ERR_SOCKCLOSED;
    }
    ESP_LOGE(TAG, "Socket recv() error: %s", strerror(errno));
    return FORT_ERR_RECV;
}

#if FORT_EXTRA_DEBUG
const char *fort_state_to_str(fort_state state) {
    switch (state) {
    case FORT_STATE_IDLE: return "FORT_STATE_IDLE";
    case FORT_STATE_HELLO_SENT: return "FORT_STATE_HELLO_SENT";
    case FORT_STATE_HELLO_RECEIVED: return "FORT_STATE_HELLO_RECEIVED";
    case FORT_STATE_BOUND: return "FORT_STATE_BOUND";
    case FORT_STATE_CLOSING: return "FORT_STATE_CLOSING";
    case FORT_STATE_CLOSED: return "FORT_STATE_CLOSED";
    default: return "not a valid state";
    }
}
#endif

int fort_begin(void)
{
    fort_main_session.state = FORT_STATE_IDLE;
    fort_main_session.lock = xSemaphoreCreateMutex();
    xTaskCreate(
        fort_task, FORT_TASK_NAME, FORT_TASK_STACK,NULL, FORT_TASK_PRIO, &fort_globals.fort_task
    );

    fort_main_session.events = xEventGroupCreate();
    return 0;
}


int fort_connect(const char *hostname, const uint16_t port)
{
    EXPECT_STATE(&fort_main_session, FORT_STATE_IDLE);
    if (fort_main_session.error) {
        return fort_main_session.error;
    }

    xSemaphoreTake(fort_main_session.lock, portMAX_DELAY);

    int err = fort_do_connect(&fort_main_session, hostname, port);
    // TODO: add a timeout
    // wait for the gateway to respond with a HELLO
    xEventGroupWaitBits(fort_main_session.events, FORT_EVT_GATEWAY_HELLO, pdTRUE, pdTRUE, portMAX_DELAY);

    if (err != 0) {
        fort_main_session.error = err;
    }
    xSemaphoreGive(fort_main_session.lock);
    return err;
}

// connect and send hello
int fort_do_connect(fort_session *sess, const char *hostname, const uint16_t port)
{
    int err;
    struct addrinfo hints, *servinfo = NULL;
    struct sockaddr_in gateway_addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;        // use IPv4
    hints.ai_socktype = SOCK_STREAM;  // TCP stream sockets

    // resolve the gateway address and put it in servinfo
    if ((err = getaddrinfo(hostname, NULL, &hints, &servinfo)) != 0) {
        // seems like there's no gai_strerror() in LwIP,
        // but errors are defined in esp-lwip/src/include/lwip/netdb.h
        ESP_LOGE(TAG, "getaddrinfo error: %d", err);
        if (servinfo) freeaddrinfo(servinfo);
        return -1;
    }

    // use the firt addrinfo entry, fill in the port manually
    memcpy(&gateway_addr, servinfo->ai_addr, servinfo->ai_addrlen);
    gateway_addr.sin_port = htons(port);

    int service_sock = socket(
        servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol
    );
    if (service_sock == -1) {
        ESP_LOGE(TAG, "socket creation error: %s", strerror(errno));
        return -1;
    }
    
    err = connect(service_sock, (struct sockaddr *)&gateway_addr, servinfo->ai_addrlen);
    if (err == -1) {
        ESP_LOGE(TAG, "connect error: %s", strerror(errno));
        return -1;
    }

    // send our HELLO to the gateway
    fort_header hello = { .packet_type = PACKET_HELLO, .data_length = 0 };
    if ((err = fort_send_all(service_sock, &hello, sizeof hello, 0)) < 0) {
        close(service_sock);
        return err;
    }

    sess->service_socket = service_sock;
    sess->gateway_addr = gateway_addr;
    sess->state = FORT_STATE_HELLO_SENT;
    xEventGroupSetBits(sess->events, FORT_EVT_SERVER_HELLO);
    freeaddrinfo(servinfo);
    return 0;
}

int fort_bind_and_listen(uint16_t port, int backlog)
{
    EXPECT_STATE(&fort_main_session, FORT_STATE_HELLO_RECEIVED);
    if (fort_main_session.error) {
        return fort_main_session.error;
    }

    xSemaphoreTake(fort_main_session.lock, portMAX_DELAY);

    int err = fort_do_listen(&fort_main_session, port, backlog);
    if (err != 0) goto ret;

    // TODO: add a timeout
    xEventGroupWaitBits(fort_main_session.events, FORT_EVT_GATEWAY_BINDR,
        pdTRUE, pdTRUE, portMAX_DELAY);

    if (fort_main_session.gateway_bind_port == port) {
        fort_main_session.state = FORT_STATE_BOUND;
    } else {
        err = -1;
        ESP_LOGE(TAG, "gateway bind failure: port %u (got) != port %u (expected)", 
            fort_main_session.gateway_bind_port, port);
    }

ret:
    if (err != 0) {
        fort_main_session.error = err;
    }

    xSemaphoreGive(fort_main_session.lock);
    return err;
}

int fort_do_listen(fort_session *sess, const uint16_t port, const int backlog)
{
    sess->accept_queue = xQueueCreate(backlog, sizeof(int));
    sess->gateway_bind_port = port;

    fort_header bind = {
        .packet_type = PACKET_BINDR,
        .port = sess->gateway_bind_port,
        .data_length = 0
    };
    int err = fort_send_all(sess->service_socket, &bind, sizeof bind, 0);
    return err < FORT_ERR_OK ? err : FORT_ERR_OK;
}

int fort_accept(uint64_t timeout_ms)
{
    EXPECT_STATE(&fort_main_session, FORT_STATE_BOUND);
    if (fort_main_session.error) {
        return fort_main_session.error;
    }

    int sock;
    int rc = xQueueReceive(
        fort_main_session.accept_queue, &sock, pdTICKS_TO_MS(timeout_ms));
    return rc == pdTRUE ? sock : -1;
}

int fort_disconnect(void)
{
    if (fort_main_session.error) {
        return fort_main_session.error;
    }
    // Can't use EXPECT_STATE because there are multiple states allowed
    if (fort_main_session.state != FORT_STATE_BOUND &&
        fort_main_session.state != FORT_STATE_HELLO_RECEIVED) {
        ESP_LOGE(TAG,
            "Unexpected state when trying to disconnect: " STATE_FMT_SPEC,
            STATE_FMT(fort_main_session.state));
        return -1;
    }

    xSemaphoreTake(fort_main_session.lock, portMAX_DELAY);
    int err = fort_do_disconnect(&fort_main_session);
    if (err != 0) goto ret;
    // TODO: add a timeout
    xEventGroupWaitBits(fort_main_session.events, FORT_EVT_GATEWAY_SHUTD, pdTRUE, pdTRUE, portMAX_DELAY);
    
    if (fort_main_session.accept_queue) {
        vQueueDelete(fort_main_session.accept_queue);
        fort_main_session.accept_queue = NULL;
    }

ret:
    xSemaphoreGive(fort_main_session.lock);
    return err;
}

int fort_do_disconnect(fort_session *sess)
{
    sess->state = FORT_STATE_CLOSING;
    fort_header shutd = { .packet_type = PACKET_SHUTD, .data_length = 0, .port = 0 };
    int err = fort_send_all(sess->service_socket, &shutd, sizeof shutd, 0);
    return err < FORT_ERR_OK ? err : FORT_ERR_OK;
}

// Called only from fort-task when there are incoming data on service_socket,
// does not block.
ssize_t receive_packet_step(fort_session *sess, char **response) {
    // Can I somehow wait (return) until a full header/data arrives
    // and then read it in a one go?

    int response_len = 0;
    static size_t bytes_left = sizeof(fort_header);
    static char hdr_buf[sizeof(fort_header)];
    static char *recv_ptr = hdr_buf;
    static char *data_buf;

    if (bytes_left) {
        ssize_t received = recv(sess->service_socket, recv_ptr, bytes_left, MSG_DONTWAIT);
        if (received == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            ESP_LOGE(TAG, "recv error: %s", strerror(errno));
        } else if (received == 0) {
            // TODO: properly deal with it later
            ESP_LOGE(TAG, "unexpected socket close");
            abort();
        } else {
            bytes_left -= (size_t)received;
            recv_ptr += received;
        }
    }
    
    // finished receiving packet header
    if (!bytes_left && recv_ptr == hdr_buf + sizeof(fort_header)) {
        bytes_left = ((fort_header *)hdr_buf)->data_length;
        // TODO: use a local buffer for data with length <= 1024 or so
        data_buf = bytes_left ? (char *)malloc(bytes_left) : NULL;
        // check if malloc succeeds
        assert(!bytes_left || data_buf);
        recv_ptr = data_buf;
    }
    // we've just received packet data or its length is zero after receiving header
    // in both cases the packet is ready for processing
    if (!bytes_left && recv_ptr != hdr_buf + sizeof(fort_header)) {
        xSemaphoreTake(sess->lock, portMAX_DELAY);
        response_len = handle_packet(sess, (const fort_header *)hdr_buf, data_buf, response);
        xSemaphoreGive(sess->lock);
        free(data_buf);

        bytes_left = sizeof(fort_header);
        recv_ptr = hdr_buf;
    }

    return response_len;
}

// TODO: break down to multiple functions
ssize_t handle_packet(fort_session *sess, const fort_header *hdr, const void *data, char **response)
{
    size_t len = (size_t)hdr->data_length;
    ssize_t response_len = 0;

    switch (hdr->packet_type) {
    case PACKET_HELLO:
        EXPECT_STATE(sess, FORT_STATE_HELLO_SENT);
        sess->state = FORT_STATE_HELLO_RECEIVED;
        xEventGroupSetBits(sess->events, FORT_EVT_GATEWAY_HELLO);
        break;

    case PACKET_BINDR:
        EXPECT_STATE(sess, FORT_STATE_HELLO_RECEIVED);
        sess->gateway_bind_port = hdr->port;
        xEventGroupSetBits(sess->events, FORT_EVT_GATEWAY_BINDR);
        break;
 
    case PACKET_OPENC: {
        EXPECT_STATE(sess, FORT_STATE_BOUND);
        struct sockaddr_in addr = sess->gateway_addr;
        addr.sin_port = htons(hdr->port);

        int sock = socket(addr.sin_family, SOCK_STREAM, 0);
        if (sock == -1) {
            ESP_LOGE(TAG, "socket creation error: %s", strerror(errno));
            break;
        }
        int err = connect(sock, (struct sockaddr *)&addr, sizeof addr);
        if (err == -1) {
            ESP_LOGE(TAG, "connect error: %s", strerror(errno));
            break;
        }
        
        if(xQueueSend(sess->accept_queue, &sock, 0) == errQUEUE_FULL) {
            ESP_LOGE(TAG, "the queue is full, cannot accept a new connection");
            close(sock);
            break;
        }

        break;
    }
    case PACKET_SHUTD: {
        if (sess->state == FORT_STATE_CLOSING) {
            // we initiated a shutdown and got a response from the gateway
            sess->state = FORT_STATE_CLOSED;
            xEventGroupSetBits(sess->events, FORT_EVT_GATEWAY_SHUTD);
            break;
        }
        if (sess->state != FORT_STATE_HELLO_RECEIVED && 
            sess->state != FORT_STATE_BOUND) {
            ESP_LOGW(TAG, "Wrong state (" STATE_FMT_SPEC 
                ") for SHUTD initiation, proceeding anyway",
                STATE_FMT(sess->state));
        }
        // gateway initiated shutdown, so it's its job to close all the connections, 
        // we just respond with a SHUTD packet
        fort_header shutd = { .packet_type = PACKET_SHUTD, .data_length = 0, .port = 0 };
        int err = fort_send_all(sess->service_socket, &shutd, sizeof shutd, 0);
        if (err < FORT_ERR_OK) {
            ESP_LOGE(TAG, "Can't reply with SHUTD packet, "
                "closing the socket by ourselves instead of the gateway");
            close(sess->service_socket);
        }
        sess->state = FORT_STATE_CLOSED;
        break;
    }
    case PACKET_BLANK:
        if (len) {
            ESP_LOGD(TAG, "got a BLANK packet: %.*s", (int)len, (const char *)data);
        } else {
            ESP_LOGD(TAG, "got a BLANK packet with no data");
        }
        break;

    default:
        ESP_LOGW(TAG, "got an unknown packet type: 0x%X", hdr->packet_type);
        break;
    }

    return response_len;
}

// the main task that processes all incoming packets and responses on them
// TODO: split into two tasks: network and internal logic
void fort_task(void *parameters)
{
    fort_session *sess = &fort_main_session;
    struct pollfd fds[20];
    int nevents = 0;
    size_t nfds = 1;
    char *response = NULL;
    ssize_t response_len = 0; // can return a negative value on error

    xEventGroupWaitBits(fort_main_session.events, FORT_EVT_SERVER_HELLO, pdTRUE, pdTRUE, portMAX_DELAY);
    fds[0].fd = sess->service_socket;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    for (;;) {
        nevents = poll(fds, nfds, 1000);
        if (nevents < 0) {
            ESP_LOGE(TAG, "poll error: %s", strerror(errno));
        } else if (nevents == 0) {
            continue;
        }

        if (fds[0].revents & POLLIN) {
            response_len = receive_packet_step(sess, &response);
            if (response_len) fds[0].events |= POLLOUT;
        }
        if (fds[0].revents & POLLOUT) {
            // Don't care about non-blocking, because we should send the response
            // before processing a new packet
            fort_send_all(sess->service_socket, response, response_len, 0);
            free(response);
            fds[0].events &= ~(short)POLLOUT;
        }

        fds[0].revents = 0;
    }

    vTaskDelete(NULL);
}

fort_session fort_main_session = {
    
};

// initialized by fort_begin
fort_globals_t fort_globals;
