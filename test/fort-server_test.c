#include "fort-server.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "unity.h"


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
    UNITY_END();
}