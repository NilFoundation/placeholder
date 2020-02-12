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

#include <cstdint>
#include <functional>

#include <nil/actor/detail/comparable.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/ipv6_address.hpp>
#include <nil/actor/meta/type_name.hpp>

namespace nil {
    namespace actor {

        /// An IP endpoint that contains an ::ipv6_address and a port.
        class ipv6_endpoint : detail::comparable<ipv6_endpoint>, detail::comparable<ipv6_endpoint, ipv4_endpoint> {
        public:
            // -- constructors -----------------------------------------------------------

            ipv6_endpoint(ipv6_address address, uint16_t port);

            ipv6_endpoint(ipv4_address address, uint16_t port);

            ipv6_endpoint() = default;

            ipv6_endpoint(const ipv6_endpoint &) = default;

            ipv6_endpoint &operator=(const ipv6_endpoint &) = default;

            // -- properties -------------------------------------------------------------

            /// Returns the IPv6 address.
            ipv6_address address() const noexcept {
                return address_;
            }

            /// Sets the address of this endpoint.
            void address(ipv6_address x) noexcept {
                address_ = x;
            }

            /// Returns the port of this endpoint.
            uint16_t port() const noexcept {
                return port_;
            }

            /// Sets the port of this endpoint.
            void port(uint16_t x) noexcept {
                port_ = x;
            }

            /// Returns a hash for this object.
            size_t hash_code() const noexcept;

            /// Compares this endpoint to `x`.
            /// @returns 0 if `*this == x`, a positive value if `*this > x` and a negative
            /// value otherwise.
            long compare(ipv6_endpoint x) const noexcept;

            /// Compares this endpoint to `x`.
            /// @returns 0 if `*this == x`, a positive value if `*this > x` and a negative
            /// value otherwise.
            long compare(ipv4_endpoint x) const noexcept;

            template<class Inspector>
            friend typename Inspector::result_type inspect(Inspector &f, ipv6_endpoint &x) {
                return f(meta::type_name("ipv6_endpoint"), x.address_, x.port_);
            }

        private:
            /// The address of this endpoint.
            ipv6_address address_;
            /// The port of this endpoint.
            uint16_t port_;
        };

        std::string to_string(const ipv6_endpoint &ep);

    }    // namespace actor
}    // namespace nil

namespace std {

    template<>
    struct hash<nil::actor::ipv6_endpoint> {
        size_t operator()(const nil::actor::ipv6_endpoint &ep) const noexcept {
            return ep.hash_code();
        }
    };

}    // namespace std
