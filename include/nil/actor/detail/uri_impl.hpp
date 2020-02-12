//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <utility>

#include <nil/actor/error.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/meta/load_callback.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/uri.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class uri_impl {
            public:
                // -- constructors, destructors, and assignment operators --------------------

                uri_impl();

                uri_impl(const uri_impl &) = delete;

                uri_impl &operator=(const uri_impl &) = delete;

                // -- member variables -------------------------------------------------------

                static uri_impl default_instance;

                /// Null-terminated buffer for holding the string-representation of the URI.
                std::string str;

                /// Scheme component.
                std::string scheme;

                /// Assembled authority component.
                uri::authority_type authority;

                /// Path component.
                std::string path;

                /// Query component as key-value pairs.
                uri::query_map query;

                /// The fragment component.
                std::string fragment;

                // -- properties -------------------------------------------------------------

                bool valid() const noexcept {
                    return !scheme.empty() && (!authority.empty() || !path.empty());
                }

                // -- modifiers --------------------------------------------------------------

                /// Assembles the human-readable string representation for this URI.
                void assemble_str();

                // -- friend functions -------------------------------------------------------

                friend void intrusive_ptr_add_ref(const uri_impl *p);

                friend void intrusive_ptr_release(const uri_impl *p);

            private:
                // -- member variables -------------------------------------------------------

                mutable std::atomic<size_t> rc_;
            };

            // -- related free functions -------------------------------------------------

            /// @relates uri_impl
            template<class Inspector>
            typename Inspector::result_type inspect(Inspector &f, uri_impl &x) {
                auto load = [&] {
                    x.str.clear();
                    if (x.valid())
                        x.assemble_str();
                };
                return f(x.scheme, x.authority, x.path, x.query, x.fragment, meta::load_callback(load));
            }
        }    // namespace detail
    }        // namespace actor
}    // namespace nil