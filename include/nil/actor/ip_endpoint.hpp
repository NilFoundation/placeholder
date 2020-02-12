//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/ipv6_endpoint.hpp>

namespace nil {
    namespace actor {

        /// An IP endpoint that contains an ::ipv6_address and a port.
        using ip_endpoint = ipv6_endpoint;

    }    // namespace actor
}    // namespace nil
