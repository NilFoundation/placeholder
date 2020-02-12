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
#include <nil/actor/ipv4_address.hpp>
#include <nil/actor/meta/type_name.hpp>

namespace nil {
    namespace actor {

        /// An IP endpoint that contains an ::ipv4_address and a port.
        class ipv4_endpoint : detail::comparable<ipv4_endpoint> {
        public:
            // -- constructors -----------------------------------------------------------

            ipv4_endpoint(ipv4_address address, uint16_t port);

            ipv4_endpoint() = default;

            ipv4_endpoint(const ipv4_endpoint &) = default;

            ipv4_endpoint &operator=(const ipv4_endpoint &) = default;

            // -- properties -------------------------------------------------------------

            /// Returns the IPv4 address.
            ipv4_address address() const noexcept {
                return address_;
            }

            /// Sets the address of this endpoint.
            void address(ipv4_address x) noexcept {
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

            /// Returns a hash for this object
            size_t hash_code() const noexcept;

            /// Compares this endpoint to `x`.
            /// @returns 0 if `*this == x`, a positive value if `*this > x` and a negative
            /// value otherwise.
            long compare(ipv4_endpoint x) const noexcept;

            template<class Inspector>
            friend typename Inspector::result_type inspect(Inspector &f, ipv4_endpoint &x) {
                return f(meta::type_name("ipv4_endpoint"), x.address_, x.port_);
            }

        private:
            ipv4_address address_;    /// The address of this endpoint.
            uint16_t port_;           /// The port of this endpoint.
        };

        std::string to_string(const ipv4_endpoint &ep);

    }    // namespace actor
}    // namespace nil

namespace std {

    template<>
    struct hash<nil::actor::ipv4_endpoint> {
        size_t operator()(const nil::actor::ipv4_endpoint &ep) const noexcept {
            return ep.hash_code();
        }
    };

}    // namespace std
