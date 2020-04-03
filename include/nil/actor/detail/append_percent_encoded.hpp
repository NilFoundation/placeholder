//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <string>

#include <nil/actor/fwd.hpp>

namespace nil::actor::detail {

    // Escapes all reserved characters according to RFC 3986 in `x` and
    // adds the encoded string to `str`.
    BOOST_SYMBOL_VISIBLE void append_percent_encoded(std::string &str, string_view x, bool is_path = false);

}    // namespace nil::actor::detail
