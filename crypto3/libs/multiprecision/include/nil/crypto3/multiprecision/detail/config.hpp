//---------------------------------------------------------------------------//
// Copyright (c) 2021 Matt Borland
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// Enable to use limb shift instead of byte shift with memmove in runtime
// #define NIL_CO3_MP_USE_LIMB_SHIFT

// Disable use of intrinsics
// #define NIL_CO3_MP_DISABLE_INTRINSICS

// Disable use of int128
// #define NIL_CO3_MP_DISABLE_INT128

#if defined(GPU_PROVER)
  #define NIL_CO3_MP_DISABLE_INT128
  #define NIL_CO3_MP_DISABLE_INTRINSICS
  // black magick, i do not remember why i did this
  struct float128_type {};
#endif
