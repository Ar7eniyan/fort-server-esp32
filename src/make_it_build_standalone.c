#include "fort-server.h"

#include <assert.h>
#include <stdbool.h>

void app_main(void);

// Dummy app_main function is required to test if the library builds standalone.
// Make it weak not to interfere with the real one
void __attribute__((weak)) app_main(void) { assert(false); };
