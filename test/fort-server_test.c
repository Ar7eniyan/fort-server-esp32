#include "fort-server.h"

#include "unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_begin(void) { TEST_ASSERT(fort_begin() == FORT_ERR_OK); }

void app_main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_begin);
    UNITY_END();
}