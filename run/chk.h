#ifndef AETHER_HARDEN_H
#define AETHER_HARDEN_H

#include <stdbool.h>

bool is_debugged(void);
void deny_attach(void);
void self_destruct(void);

/* Returns true if environment is cool to run. */
bool harden_check(void);

#endif
