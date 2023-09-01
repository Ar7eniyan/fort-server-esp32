#include "fort-server.h"
// Should I use private definitions, or hardcode the values?
// #include "fort-server_private.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "unity.h"

#include <sys/socket.h>

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
    TEST_ASSERT(fort_main_session.state == FORT_STATE_IDLE);
}

void test_connect_fail(void)
{
    TEST_ASSERT(fort_connect("localhost", 1337) == FORT_ERR_CONNECT);
    TEST_ASSERT(fort_main_session.state == FORT_STATE_IDLE);
    fort_clear_error();
}

// Wrapper functions to match void_ptr_func signature
void *run_fort_connect(void)
{
    // void * is large enough to hold an enum (fort_error)
    return (void *)fort_connect("localhost", 1337);
}

void *run_fort_disconnect(void) { return (void *)fort_disconnect(); }

// The session should be in the IDLE state at this point
// After this function, the session will be in the HELLO_RECEIVED state.
void connect_localhost(int *local_socket, int *service_socket)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(1337);
    TEST_ASSERT(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock != -1);
    *local_socket = sock;
    TEST_ASSERT(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(listen(sock, 1) == 0);

    start_exec(run_fort_connect);

    int service_sock = accept(sock, NULL, NULL);
    TEST_ASSERT(service_sock != -1);
    *service_socket = service_sock;
    // Receive a HELLO packet from server
    char server_hello[5];
    TEST_ASSERT(recv(service_sock, server_hello, sizeof(server_hello), 0) ==
                sizeof(server_hello));
    TEST_ASSERT_EQUAL_HEX8(0x01, server_hello[0]);  // packet type
    TEST_ASSERT_EQUAL_HEX16(0, server_hello[3]);    // data length

    // Reply with a HELLO handshake
    // Packet type - 0x01 (HELLO), port - 0, data length - 0
    const char gateway_hello[] = {0x01, 0x00, 0x00, 0x00, 0x00};
    TEST_ASSERT(send(service_sock, gateway_hello, sizeof(gateway_hello), 0) ==
                sizeof(gateway_hello));

    TEST_ASSERT(wait_for_exec_result() == FORT_ERR_OK);
    TEST_ASSERT(fort_main_session.state == FORT_STATE_HELLO_RECEIVED);
}

// The session should be in the BOUND or HELLO_RECEIVED state at this point.
// After this function, the session will be in the CLOSED state.
// The service socket (passed as a parameter) is closed by this function.
void disconnect_localhost(int *service_sock)
{
    start_exec(run_fort_disconnect);

    // Receive a SHUTD packet from server
    char server_shutd[5];
    TEST_ASSERT(recv(*service_sock, server_shutd, sizeof(server_shutd), 0) ==
                sizeof(server_shutd));
    TEST_ASSERT_EQUAL_HEX8(0x04, server_shutd[0]);  // packet type
    TEST_ASSERT_EQUAL_HEX16(0, server_shutd[3]);    // data length

    // Reply with a SHUTD confirmation
    // Packet type - 0x04 (SHUTD), port - 0, data length - 0
    const char gateway_shutd[] = {0x04, 0x00, 0x00, 0x00, 0x00};
    TEST_ASSERT(send(*service_sock, gateway_shutd, sizeof(gateway_shutd), 0) ==
                sizeof(gateway_shutd));

    TEST_ASSERT(wait_for_exec_result() == FORT_ERR_OK);
    TEST_ASSERT(fort_main_session.state == FORT_STATE_CLOSED);

    close(*service_sock);
}

void test_connect_disconnect(void)
{
    int local_sock, service_sock;
    connect_localhost(&local_sock, &service_sock);
    disconnect_localhost(&service_sock);
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
    RUN_TEST(test_connect_disconnect);
    UNITY_END();
}