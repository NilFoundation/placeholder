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

#include <nil/actor/uri_builder.hpp>

#include <nil/actor/detail/uri_impl.hpp>
#include <nil/actor/make_counted.hpp>

namespace nil {
    namespace actor {

        uri_builder::uri_builder() : impl_(make_counted<detail::uri_impl>()) {
            // nop
        }

        uri_builder &uri_builder::scheme(std::string str) {
            impl_->scheme = std::move(str);
            return *this;
        }

        uri_builder &uri_builder::userinfo(std::string str) {
            impl_->authority.userinfo = std::move(str);
            return *this;
        }

        uri_builder &uri_builder::host(std::string str) {
            impl_->authority.host = std::move(str);
            return *this;
        }

        uri_builder &uri_builder::host(ip_address addr) {
            impl_->authority.host = addr;
            return *this;
        }

        uri_builder &uri_builder::port(uint16_t value) {
            impl_->authority.port = value;
            return *this;
        }

        uri_builder &uri_builder::path(std::string str) {
            impl_->path = std::move(str);
            return *this;
        }

        uri_builder &uri_builder::query(uri::query_map map) {
            impl_->query = std::move(map);
            return *this;
        }

        uri_builder &uri_builder::fragment(std::string str) {
            impl_->fragment = std::move(str);
            return *this;
        }

        uri uri_builder::make() {
            impl_->assemble_str();
            return uri {std::move(impl_)};
        }

    }    // namespace actor
}    // namespace nil
