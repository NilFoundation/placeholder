//---------------------------------------------------------------------------//
// Copyright (c) 2010-2021 Douglas Gregor
// Copyright (c) 2021 Matt Borland
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#if defined(__SIZEOF_INT128__)
#define NIL_CO3_MP_HAS_INT128
#endif

// same again for __int128:
#if defined(NIL_CO3_MP_HAS_INT128) && defined(__cplusplus)
namespace nil::crypto3::multiprecision::detail {
#ifdef __GNUC__
    __extension__ typedef __int128 int128_t;
    __extension__ typedef unsigned __int128 uint128_t;
#else
    typedef __int128 int128_type;
    typedef unsigned __int128 uint128_type;
#endif
}  // namespace nil::crypto3::multiprecision::detail
#endif
