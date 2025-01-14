//---------------------------------------------------------------------------//
// Copyright (c) 2021 Matt Borland
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <boost/predef/other/endian.h>

#define NIL_CO3_MP_ENDIAN_BIG_BYTE 0
#define NIL_CO3_MP_ENDIAN_BIG_WORD 0
#define NIL_CO3_MP_ENDIAN_LITTLE_BYTE 0
#define NIL_CO3_MP_ENDIAN_LITTLE_WORD 0

#if defined(BOOST_ENDIAN_BIG_BYTE)
    #undef NIL_CO3_MP_ENDIAN_BIG_BYTE
    #define NIL_CO3_MP_ENDIAN_BIG_BYTE 1
#endif

#if defined(BOOST_ENDIAN_LITTLE_BYTE)
    #undef NIL_CO3_MP_ENDIAN_LITTLE_BYTE
    #define NIL_CO3_MP_ENDIAN_LITTLE_BYTE 1
#endif

#if defined(BOOST_ENDIAN_BIG_WORD)
    #undef NIL_CO3_MP_ENDIAN_BIG_WORD
    #define NIL_CO3_MP_ENDIAN_BIG_WORD 1
#endif

#if defined(BOOST_ENDIAN_LITTLE_WORD)
    #undef NIL_CO3_MP_ENDIAN_LITTLE_WORD
    #define NIL_CO3_MP_ENDIAN_LITTLE_WORD 1
#endif

