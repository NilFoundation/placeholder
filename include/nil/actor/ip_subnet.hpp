//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/ipv6_subnet.hpp>

namespace nil {
    namespace actor {

        /// An IP subnetwork. The address family is IPv6 unless `embeds_v4` returns
        /// true.
        using ip_subnet = ipv6_subnet;

    }    // namespace actor
}    // namespace nil
