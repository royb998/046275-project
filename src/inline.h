

#include "pin.h"

/* ---------- Enums ---------- */

enum
{
    INVALID = -1,
    SUCCESS = 0,

} inline_rc_t;

/* ---------- Functions ---------- */

/**
 * Determine if a given routine is a valid candidate for function inlining.
 *
 * @param IN  rtn routine to check.
 *
 * @returns 0 for valid function
 */
int is_valid_for_inlining(RTN rtn);

int find_inlining_candidates(IMG img);
