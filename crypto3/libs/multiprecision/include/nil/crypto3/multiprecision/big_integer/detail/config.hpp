#pragma once

#if !defined(NIL_CO3_MP_FORCEINLINE)

#if defined(NDEBUG) && !defined(_DEBUG)

#if defined(_MSC_VER)
#define NIL_CO3_MP_FORCEINLINE __forceinline
#elif defined(__GNUC__) && __GNUC__ > 3
// Clang also defines __GNUC__ (as 4)
#define NIL_CO3_MP_FORCEINLINE inline __attribute__((__always_inline__))
#else
#define NIL_CO3_MP_FORCEINLINE inline
#endif

#else

#define NIL_CO3_MP_FORCEINLINE inline

#endif

#endif
