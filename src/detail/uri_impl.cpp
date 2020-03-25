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

#include <nil/actor/detail/uri_impl.hpp>

#include <nil/actor/detail/append_percent_encoded.hpp>
#include <nil/actor/detail/parser/read_uri.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/ip_address.hpp>
#include <nil/actor/string_algorithms.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            // -- constructors, destructors, and assignment operators ----------------------

            uri_impl::uri_impl() : rc_(1) {
                // nop
            }

            // -- member variables ---------------------------------------------------------

            uri_impl uri_impl::default_instance;

            // -- modifiers ----------------------------------------------------------------

            void uri_impl::assemble_str() {
                append_percent_encoded(str, scheme);
                str += ':';
                if (authority.empty()) {
                    ACTOR_ASSERT(!path.empty());
                    append_percent_encoded(str, path, true);
                } else {
                    str += "//";
                    str += to_string(authority);
                    if (!path.empty()) {
                        str += '/';
                        append_percent_encoded(str, path, true);
                    }
                }
                if (!query.empty()) {
                    str += '?';
                    auto i = query.begin();
                    auto add_kvp = [&](decltype(*i) kvp) {
                        append_percent_encoded(str, kvp.first);
                        str += '=';
                        append_percent_encoded(str, kvp.second);
                    };
                    add_kvp(*i);
                    for (++i; i != query.end(); ++i) {
                        str += '&';
                        add_kvp(*i);
                    }
                }
                if (!fragment.empty()) {
                    str += '#';
                    append_percent_encoded(str, fragment);
                }
            }

            // -- friend functions ---------------------------------------------------------

            void intrusive_ptr_add_ref(const uri_impl *p) {
                p->rc_.fetch_add(1, std::memory_order_relaxed);
            }

            void intrusive_ptr_release(const uri_impl *p) {
                if (p->rc_ == 1 || p->rc_.fetch_sub(1, std::memory_order_acq_rel) == 1)
                    delete p;
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
