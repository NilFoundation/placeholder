//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>
#include <vector>

#include <nil/actor/detail/comparable.hpp>
#include <nil/actor/detail/parser/state.hpp>
#include <nil/actor/detail/unordered_flat_map.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/ip_address.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>

namespace nil {
    namespace actor {

        /// A URI according to RFC 3986.
        class uri : detail::comparable<uri>, detail::comparable<uri, string_view> {
        public:
            // -- member types -----------------------------------------------------------

            /// Pointer to implementation.
            using impl_ptr = intrusive_ptr<const detail::uri_impl>;

            /// Host subcomponent of the authority component. Either an IP address or
            /// an hostname as string.
            using host_type = variant<std::string, ip_address>;

            /// Bundles the authority component of the URI, i.e., userinfo, host, and
            /// port.
            struct authority_type {
                std::string userinfo;
                host_type host;
                uint16_t port;

                inline authority_type() : port(0) {
                    // nop
                }

                /// Returns whether `host` is empty, i.e., the host is not an IP address
                /// and the string is empty.
                bool empty() const noexcept {
                    auto str = get_if<std::string>(&host);
                    return str != nullptr && str->empty();
                }
            };

            /// Separates the query component into key-value pairs.
            using path_list = std::vector<string_view>;

            /// Separates the query component into key-value pairs.
            using query_map = detail::unordered_flat_map<std::string, std::string>;

            // -- constructors, destructors, and assignment operators --------------------

            uri();

            uri(uri &&) = default;

            uri(const uri &) = default;

            uri &operator=(uri &&) = default;

            uri &operator=(const uri &) = default;

            explicit uri(impl_ptr ptr);

            // -- properties -------------------------------------------------------------

            /// Returns whether all components of this URI are empty.
            bool empty() const noexcept;

            /// Returns the full URI as provided by the user.
            string_view str() const noexcept;

            /// Returns the scheme component.
            string_view scheme() const noexcept;

            /// Returns the authority component.
            const authority_type &authority() const noexcept;

            /// Returns the path component as provided by the user.
            string_view path() const noexcept;

            /// Returns the query component as key-value map.
            const query_map &query() const noexcept;

            /// Returns the fragment component.
            string_view fragment() const noexcept;

            /// Returns a hash code over all components.
            size_t hash_code() const noexcept;

            /// Returns a new URI with the `authority` component only.
            /// @returns A new URI in the form `scheme://authority` if the authority
            ///          exists, otherwise `none`.`
            optional<uri> authority_only() const;

            // -- comparison -------------------------------------------------------------

            int compare(const uri &other) const noexcept;

            int compare(string_view x) const noexcept;

            // -- friend functions -------------------------------------------------------

            friend error inspect(nil::actor::serializer &dst, uri &x);

            friend error_code<sec> inspect(nil::actor::binary_serializer &dst, uri &x);

            friend error inspect(nil::actor::deserializer &src, uri &x);

            friend error_code<sec> inspect(nil::actor::binary_deserializer &src, uri &x);

        private:
            impl_ptr impl_;
        };

        // -- related free functions ---------------------------------------------------

        template<class Inspector>
        typename Inspector::result_type inspect(Inspector &f, uri::authority_type &x) {
            return f(x.userinfo, x.host, x.port);
        }

        /// @relates uri
        std::string to_string(const uri &x);

        /// @relates uri
        std::string to_string(const uri::authority_type &x);

        /// @relates uri
        error parse(string_view str, uri &dest);

        /// @relates uri
        expected<uri> make_uri(string_view str);

    }    // namespace actor
}    // namespace nil

namespace std {

    template<>
    struct hash<nil::actor::uri> {
        size_t operator()(const nil::actor::uri &x) const noexcept {
            return x.hash_code();
        }
    };

}    // namespace std
