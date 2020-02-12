//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#include <nil/actor/ipv4_endpoint.hpp>

#include <nil/actor/detail/fnv_hash.hpp>

namespace nil {
    namespace actor {

        ipv4_endpoint::ipv4_endpoint(ipv4_address address, uint16_t port) : address_(address), port_(port) {
            // nop
        }

        size_t ipv4_endpoint::hash_code() const noexcept {
            auto result = detail::fnv_hash(address_.data());
            return detail::fnv_hash_append(result, port_);
        }

        long ipv4_endpoint::compare(ipv4_endpoint x) const noexcept {
            auto res = address_.compare(x.address());
            return res == 0 ? port_ - x.port() : res;
        }

        std::string to_string(const ipv4_endpoint &ep) {
            return to_string(ep.address()) + ":" + std::to_string(ep.port());
        }

    }    // namespace actor
}    // namespace nil
