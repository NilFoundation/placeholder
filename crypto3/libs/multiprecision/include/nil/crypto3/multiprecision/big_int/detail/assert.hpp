#pragma once

#include <cassert>

#define NIL_CO3_MP_ASSERT(expr) assert(expr)
#define NIL_CO3_MP_ASSERT_MSG(expr, msg) assert((expr) && (msg))
