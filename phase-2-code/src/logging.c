#include "logging.h"

// Dummy implementation that does nothing
void log_message(log_level_t level, const char *fmt, ...) {
    // Do nothing
    (void)level;
    (void)fmt;
}