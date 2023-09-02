#include "fort-server.h"
#include "fort-server_private.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "unity.h"

#include <stdint.h>
#include <sys/socket.h>

#define SERVICE_PORT   1337
#define BIND_PORT      31337
#define USER_CONN_PORT 1234


typedef void *(*void_ptr_func)(void);
void executor_task(void *);
TaskHandle_t executor_task_handle;
void *execution_result;
SemaphoreHandle_t execution_sem;

void start_exec(void_ptr_func func)
{
    assert(xTaskNotify(executor_task_handle, (uint32_t)func,
                       eSetValueWithoutOverwrite) == pdPASS);
}

void *wait_for_exec_result(void)
{
    assert(xSemaphoreTake(execution_sem, portMAX_DELAY) == pdTRUE);
    return execution_result;
}

// Returns a socket bound to localhost:port
int make_local_socket(uint16_t port)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock != -1);

    // Get rid of "Address already in use" error
    int yes = 1;
    assert(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == 0);

    assert(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return sock;
}

void setUp(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    execution_sem = xSemaphoreCreateBinary();
    assert(execution_sem != NULL);
    assert(xTaskCreate(executor_task, "executor", 4096, NULL, 5,
                       &executor_task_handle) == pdPASS);
}

void tearDown(void) {}

void test_begin(void)
{
    TEST_ASSERT(fort_begin() == FORT_ERR_OK);
    TEST_ASSERT(fort_current_state() == FORT_STATE_IDLE);
}

void test_connect_fail(void)
{
    TEST_ASSERT(fort_connect("localhost", SERVICE_PORT) == FORT_ERR_CONNECT);
    TEST_ASSERT(fort_current_state() == FORT_STATE_IDLE);
    fort_clear_error();
}

// Wrapper functions to match void_ptr_func signature
void *run_fort_connect(void)
{
    // void * is large enough to hold an enum (fort_error)
    return (void *)fort_connect("localhost", SERVICE_PORT);
}

void *run_fort_disconnect(void) { return (void *)fort_disconnect(); }

void *run_fort_bind_and_listen(void)
{
    return (void *)fort_bind_and_listen(BIND_PORT, 5);
}

// Connect the server to a fake gateway on localhost.
// State before: IDLE; state after: HELLO_RECEIVED.
void connect_localhost(int *local_socket, int *service_socket)
{
    *local_socket = make_local_socket(SERVICE_PORT);
    TEST_ASSERT(listen(*local_socket, 1) == 0);

    start_exec(run_fort_connect);

    int service_sock = accept(*local_socket, NULL, NULL);
    TEST_ASSERT(service_sock != -1);
    *service_socket = service_sock;
    // Receive a HELLO packet from server
    fort_header server_hello;
    TEST_ASSERT(recv(service_sock, &server_hello, sizeof(server_hello), 0) ==
                sizeof(server_hello));
    TEST_ASSERT_EQUAL_HEX8(PACKET_HELLO, server_hello.packet_type);
    TEST_ASSERT_EQUAL_HEX16(0, server_hello.data_length);

    // Reply with a HELLO handshake
    fort_header gateway_hello = {.packet_type = PACKET_HELLO, .data_length = 0};
    TEST_ASSERT(send(service_sock, &gateway_hello, sizeof(gateway_hello), 0) ==
                sizeof(gateway_hello));

    TEST_ASSERT(wait_for_exec_result() == FORT_ERR_OK);
    TEST_ASSERT(fort_current_state() == FORT_STATE_HELLO_RECEIVED);
}

// Disconnect initiated by server (using fort_disconnect()).
// State before: HELLO_RECEIVED or BOUND; state after: CLOSED.
// The service socket (passed as a parameter) is closed by this function.
void disconnect_localhost_server(int *service_sock)
{
    start_exec(run_fort_disconnect);

    // Receive a SHUTD packet from server
    fort_header server_shutd;
    TEST_ASSERT(recv(*service_sock, &server_shutd, sizeof(server_shutd), 0) ==
                sizeof(server_shutd));
    TEST_ASSERT_EQUAL_HEX8(PACKET_SHUTD, server_shutd.packet_type);
    TEST_ASSERT_EQUAL_HEX16(0, server_shutd.data_length);

    // Reply with a SHUTD confirmation
    fort_header gateway_shutd = {.packet_type = PACKET_SHUTD, .data_length = 0};
    TEST_ASSERT(send(*service_sock, &gateway_shutd, sizeof(gateway_shutd), 0) ==
                sizeof(gateway_shutd));

    TEST_ASSERT(wait_for_exec_result() == FORT_ERR_OK);
    TEST_ASSERT(fort_current_state() == FORT_STATE_CLOSED);

    close(*service_sock);
}

// Disconnect initiated by gateway (sends a SHUTD packet).
// State before: BOUND or HELLO_RECEIVED; state after: CLOSED.
// The service socket (passed as a parameter) is closed by this function.
void disconnect_localhost_gateway(int *sevice_sock)
{
    // Send a SHUTD from gateway
    fort_header gateway_shutd = {.packet_type = PACKET_SHUTD, .data_length = 0};
    TEST_ASSERT(send(*sevice_sock, &gateway_shutd, sizeof(gateway_shutd), 0) ==
                sizeof(gateway_shutd));

    // Wait for SHUTD confirmation from server
    fort_header server_shutd;
    TEST_ASSERT(recv(*sevice_sock, &server_shutd, sizeof(server_shutd), 0) ==
                sizeof(server_shutd));
    TEST_ASSERT_EQUAL_HEX8(PACKET_SHUTD, server_shutd.packet_type);
    TEST_ASSERT_EQUAL_HEX16(0, server_shutd.data_length);

    close(*sevice_sock);
    vTaskDelay(pdMS_TO_TICKS(1000));
    TEST_ASSERT(fort_current_state() == FORT_STATE_CLOSED);
}

void test_connect_then_server_disconnect(void)
{
    int local_sock, service_sock;
    connect_localhost(&local_sock, &service_sock);
    disconnect_localhost_server(&service_sock);
    close(local_sock);

    TEST_ASSERT(fort_end() == FORT_ERR_OK);
}

void test_connect_then_gateway_disconnect(void)
{
    int local_sock, service_sock;
    connect_localhost(&local_sock, &service_sock);
    disconnect_localhost_gateway(&service_sock);

    close(local_sock);
    TEST_ASSERT(fort_end() == FORT_ERR_OK);
}

// Successfully bind to a port.
// State before: HELLO_RECEIVED; state after: BOUND.
void test_bind(int *service_sock)
{
    start_exec(run_fort_bind_and_listen);

    // Receive a BINDR packet from server
    fort_header server_bindr;
    TEST_ASSERT(recv(*service_sock, &server_bindr, sizeof(server_bindr), 0) ==
                sizeof(server_bindr));
    TEST_ASSERT_EQUAL_HEX8(PACKET_BINDR, server_bindr.packet_type);
    TEST_ASSERT_EQUAL_HEX16(BIND_PORT, server_bindr.port);
    TEST_ASSERT_EQUAL_HEX16(0, server_bindr.data_length);

    // Confirm successful binding
    fort_header gateway_bindr = {
        .packet_type = PACKET_BINDR, .port = BIND_PORT, .data_length = 0};
    TEST_ASSERT(send(*service_sock, &gateway_bindr, sizeof(gateway_bindr), 0) ==
                sizeof(gateway_bindr));

    TEST_ASSERT(wait_for_exec_result() == FORT_ERR_OK);
    TEST_ASSERT(fort_current_state() == FORT_STATE_BOUND);
}

// Unsuccessfuly bind.
// State before: HELLO_RECEIVED; state after: HELLO_RECEIVED.
void test_bind_failure(int *service_sock)
{
    start_exec(run_fort_bind_and_listen);

    // Receive a BINDR packet from server
    fort_header server_bindr;
    TEST_ASSERT(recv(*service_sock, &server_bindr, sizeof(server_bindr), 0) ==
                sizeof(server_bindr));
    TEST_ASSERT_EQUAL_HEX8(PACKET_BINDR, server_bindr.packet_type);
    TEST_ASSERT_EQUAL_HEX16(BIND_PORT, server_bindr.port);
    TEST_ASSERT_EQUAL_HEX16(0, server_bindr.data_length);

    // Unsuccessful binding, port = 0
    fort_header gateway_bindr = {
        .packet_type = PACKET_BINDR, .port = 0, .data_length = 0};
    TEST_ASSERT(send(*service_sock, &gateway_bindr, sizeof(gateway_bindr), 0) ==
                sizeof(gateway_bindr));

    TEST_ASSERT(wait_for_exec_result() == FORT_ERR_GATEWAY_BIND);
    TEST_ASSERT(fort_current_state() == FORT_STATE_HELLO_RECEIVED);
}

// Accept a connection, run some data over it and close it.
// State before: BOUND; state after: BOUND.
void test_accept(int *service_sock)
{
    int sock = make_local_socket(USER_CONN_PORT);
    TEST_ASSERT(listen(sock, 1) == 0);

    // Inform server about an ongoing connection
    fort_header gateway_openc = {
        .packet_type = PACKET_OPENC, .port = USER_CONN_PORT, .data_length = 0};
    TEST_ASSERT(send(*service_sock, &gateway_openc, sizeof(gateway_openc), 0) ==
                sizeof(gateway_openc));

    // -1 means block forever
    int lsock = fort_accept(-1);
    TEST_ASSERT(lsock > 0);
    int rsock = accept(sock, NULL, NULL);

    const char buf[] = "Hello, world!";
    char buf2[sizeof buf];

    // server to "client"
    TEST_ASSERT(send(lsock, buf, sizeof buf, 0) == sizeof buf);
    TEST_ASSERT(recv(rsock, buf2, sizeof buf2, 0) == sizeof buf2);
    TEST_ASSERT(strncmp(buf, buf2, sizeof buf) == 0);
    // "client" to server
    TEST_ASSERT(send(rsock, buf, sizeof buf, 0) == sizeof buf);
    TEST_ASSERT(recv(lsock, buf2, sizeof buf2, 0) == sizeof buf2);
    TEST_ASSERT(strncmp(buf, buf2, sizeof buf) == 0);
    close(rsock);
    close(lsock);
}

void test_connect_bind_accept_disconnect(void)
{
    int local_sock, service_sock;
    connect_localhost(&local_sock, &service_sock);

    test_bind_failure(&service_sock);
    test_bind(&service_sock);
    test_accept(&service_sock);

    disconnect_localhost_server(&service_sock);
    close(local_sock);
    TEST_ASSERT(fort_end() == FORT_ERR_OK);
}

void executor_task(void *)
{
    uint32_t notification_value;
    for (;;) {
        assert(xTaskNotifyWait(0, 0, &notification_value, portMAX_DELAY) ==
               pdPASS);
        execution_result = ((void_ptr_func)notification_value)();
        assert(xSemaphoreGive(execution_sem) == pdTRUE);
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_begin);
    RUN_TEST(test_connect_fail);
    RUN_TEST(test_connect_then_server_disconnect);
    RUN_TEST(test_connect_then_gateway_disconnect);
    RUN_TEST(test_connect_bind_accept_disconnect);
    UNITY_END();
}