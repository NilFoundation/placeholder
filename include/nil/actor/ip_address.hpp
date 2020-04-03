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

#include <nil/actor/ipv6_address.hpp>

namespace nil {
    namespace actor {

        /// An IP address. The address family is IPv6 unless `embeds_v4` returns true.
        using ip_address = ipv6_address;

    }    // namespace actor
}    // namespace nil
