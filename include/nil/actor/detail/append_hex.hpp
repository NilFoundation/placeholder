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
#include <type_traits>

#include <nil/actor/byte.hpp>

#include <nil/actor/detail/type_traits.hpp>

namespace nil::actor::detail {

    enum class hex_format {
        uppercase,
        lowercase,
    };

    template<hex_format format = hex_format::uppercase>
    void append_hex(std::string &result, const void *vptr, size_t n) {
        if (n == 0) {
            result += "00";
            return;
        }
        auto xs = reinterpret_cast<const uint8_t *>(vptr);
        const char *tbl;
        if constexpr (format == hex_format::uppercase)
            tbl = "0123456789ABCDEF";
        else
            tbl = "0123456789abcdef";
        char buf[3] = {0, 0, 0};
        for (size_t i = 0; i < n; ++i) {
            auto c = xs[i];
            buf[0] = tbl[c >> 4];
            buf[1] = tbl[c & 0x0F];
            result += buf;
        }
    }

    template<hex_format format = hex_format::uppercase, class T = int>
    void append_hex(std::string &result, const T &x) {
        append_hex<format>(result, &x, sizeof(T));
    }

}    // namespace nil::actor::detail
