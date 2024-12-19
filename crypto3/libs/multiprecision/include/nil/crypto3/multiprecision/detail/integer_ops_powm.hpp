//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// Reusing big_uint's implementation. TODO(ioxid): optimize for builtin types
#include "nil/crypto3/multiprecision/detail/big_uint/ops/powm.hpp"  // IWYU pragma: export
