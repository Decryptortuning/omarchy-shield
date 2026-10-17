#ifndef SHIELD_BOOTSTRAP_IO_H
#define SHIELD_BOOTSTRAP_IO_H
#include <stdbool.h>
/* Validates only the declared stdio contract, never grants boot authority. */
bool sb_standard_fds(void);
#endif
