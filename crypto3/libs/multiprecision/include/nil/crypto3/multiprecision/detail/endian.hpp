//---------------------------------------------------------------------------//
// Copyright (c) 2021 Matt Borland
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <bits/endian.h>

#define NIL_CO3_MP_ENDIAN_BIG_BYTE 0
#define NIL_CO3_MP_ENDIAN_BIG_WORD 0
#define NIL_CO3_MP_ENDIAN_LITTLE_BYTE 0
#define NIL_CO3_MP_ENDIAN_LITTLE_WORD 0

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
