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

#include <nil/actor/ref_counted.hpp>
#include <nil/actor/intrusive_ptr.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class Base>
            class embedded final : public Base {
            public:
                template<class... Ts>
                embedded(intrusive_ptr<ref_counted> storage, Ts &&... xs) :
                    Base(std::forward<Ts>(xs)...), storage_(std::move(storage)) {
                    // nop
                }

                ~embedded() {
                    // nop
                }

                void request_deletion(bool) noexcept override {
                    intrusive_ptr<ref_counted> guard;
                    guard.swap(storage_);
                    // this code assumes that embedded is part of pair_storage<>,
                    // i.e., this object lives inside a union!
                    this->~embedded();
                }

            protected:
                intrusive_ptr<ref_counted> storage_;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
