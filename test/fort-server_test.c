#include "fort-server.h"

#include "esp_netif.h"
#include "unity.h"


void setUp(void) { ESP_ERROR_CHECK(esp_netif_init()); }

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


void app_main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_begin);
    RUN_TEST(test_connect_fail);
    UNITY_END();
}