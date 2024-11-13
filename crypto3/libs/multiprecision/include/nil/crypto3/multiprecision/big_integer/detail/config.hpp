#pragma once

#include <bits/endian.h>

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

#if defined(__BYTE_ORDER)
#if defined(__BIG_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN)
#undef NIL_CO3_MP_ENDIAN_BIG_BYTE
#define NIL_CO3_MP_ENDIAN_BIG_BYTE 1
#endif
#if defined(__LITTLE_ENDIAN) && (__BYTE_ORDER == __LITTLE_ENDIAN)
#undef NIL_CO3_MP_ENDIAN_LITTLE_BYTE
#define NIL_CO3_MP_ENDIAN_LITTLE_BYTE 1
#endif
#if defined(__PDP_ENDIAN) && (__BYTE_ORDER == __PDP_ENDIAN)
#undef NIL_CO3_MP_ENDIAN_LITTLE_WORD
#define NIL_CO3_MP_ENDIAN_LITTLE_WORD 1
#endif
#endif
#if !defined(__BYTE_ORDER) && defined(_BYTE_ORDER)
#if defined(_BIG_ENDIAN) && (_BYTE_ORDER == _BIG_ENDIAN)
#undef NIL_CO3_MP_ENDIAN_BIG_BYTE
#define NIL_CO3_MP_ENDIAN_BIG_BYTE 1
#endif
#if defined(_LITTLE_ENDIAN) && (_BYTE_ORDER == _LITTLE_ENDIAN)
#undef NIL_CO3_MP_ENDIAN_LITTLE_BYTE
#define NIL_CO3_MP_ENDIAN_LITTLE_BYTE 1
#endif
#if defined(_PDP_ENDIAN) && (_BYTE_ORDER == _PDP_ENDIAN)
#undef NIL_CO3_MP_ENDIAN_LITTLE_WORD
#define NIL_CO3_MP_ENDIAN_LITTLE_WORD 1
#endif
#endif

#endif
