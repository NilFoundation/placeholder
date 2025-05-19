//---------------------------------------------------------------------------//
// Copyright (c) 2020 Madhur Chauhan
// Copyright (c) 2020 John Maddock
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include "nil/crypto3/multiprecision/detail/config.hpp"  // IWYU pragma: keep

// nix will sometimes have immintrin.h even on non-x86 platforms
// so we additionally check for x86_64 or i386 (using the same checks as in immintrin.h)
#if __has_include(<immintrin.h>) \
    && (defined(__x86_64__) || defined(__i386__)) \
    && !defined(NIL_CO3_MP_DISABLE_INTRINSICS)

#define NIL_CO3_MP_HAS_INTRINSICS

#include <immintrin.h>  // IWYU pragma: export (this is a portable umbrella header for intrinsics)

#endif