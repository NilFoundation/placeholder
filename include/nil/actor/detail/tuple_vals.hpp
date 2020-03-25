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

#include <tuple>
#include <stdexcept>

#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/make_type_erased_value.hpp>
#include <nil/actor/rtti_pair.hpp>
#include <nil/actor/type_nr.hpp>

#include <nil/actor/serialization/binary_deserializer.hpp>
#include <nil/actor/serialization/binary_serializer.hpp>

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/safe_equal.hpp>
#include <nil/actor/detail/message_data.hpp>
#include <nil/actor/detail/try_serialize.hpp>
#include <nil/actor/detail/stringification_inspector.hpp>

#define ACTOR_TUPLE_VALS_DISPATCH(x) \
    case x:                        \
        return tuple_inspect_delegate<x, sizeof...(Ts) - 1>(data_, f)

namespace nil {
    namespace actor {
        namespace detail {

            // avoids triggering static asserts when using ACTOR_TUPLE_VALS_DISPATCH
            template<size_t X, size_t Max, class T, class F>
            auto tuple_inspect_delegate(T &data, F &f) -> decltype(f(std::get<Max>(data))) {
                return f(std::get<(X < Max ? X : Max)>(data));
            }

            template<size_t X, size_t N>
            struct tup_ptr_access_pos {
                constexpr tup_ptr_access_pos() {
                    // nop
                }
            };

            template<size_t X, size_t N>
            constexpr tup_ptr_access_pos<X + 1, N> next(tup_ptr_access_pos<X, N>) {
                return {};
            }

            struct void_ptr_access {
                template<class T>
                void *operator()(T &x) const noexcept {
                    return &x;
                }
            };

            template<class Base, class... Ts>
            class tuple_vals_impl : public Base {
            public:
                // -- static invariants ------------------------------------------------------

                static_assert(sizeof...(Ts) > 0, "tuple_vals is not allowed to be empty");

                // -- member types -----------------------------------------------------------

                using super = message_data;

                using data_type = std::tuple<Ts...>;

                // -- friend functions -------------------------------------------------------

                template<class Inspector>
                friend typename Inspector::result_type inspect(Inspector &f, tuple_vals_impl &x) {
                    return apply_args(f, get_indices(x.data_), x.data_);
                }

                tuple_vals_impl(const tuple_vals_impl &) = default;

                template<class... Us>
                tuple_vals_impl(Us &&... xs) : data_(std::forward<Us>(xs)...), types_ {{make_rtti_pair<Ts>()...}} {
                    // nop
                }

                data_type &data() {
                    return data_;
                }

                const data_type &data() const {
                    return data_;
                }

                size_t size() const noexcept override {
                    return sizeof...(Ts);
                }

                const void *get(size_t pos) const noexcept override {
                    ACTOR_ASSERT(pos < size());
                    void_ptr_access f;
                    return mptr()->dispatch(pos, f);
                }

                void *get_mutable(size_t pos) override {
                    ACTOR_ASSERT(pos < size());
                    void_ptr_access f;
                    return this->dispatch(pos, f);
                }

                std::string stringify(size_t pos) const override {
                    std::string result;
                    stringification_inspector f {result};
                    mptr()->dispatch(pos, f);
                    return result;
                }

                using Base::copy;

                type_erased_value_ptr copy(size_t pos) const override {
                    type_erased_value_factory f;
                    return mptr()->dispatch(pos, f);
                }

                error load(size_t pos, deserializer &source) override {
                    return dispatch(pos, source);
                }

                error_code<sec> load(size_t pos, binary_deserializer &source) override {
                    return dispatch(pos, source);
                }

                uint32_t type_token() const noexcept override {
                    return make_type_token<Ts...>();
                }

                rtti_pair type(size_t pos) const noexcept override {
                    return types_[pos];
                }

                error save(size_t pos, serializer &sink) const override {
                    return mptr()->dispatch(pos, sink);
                }

                error_code<sec> save(size_t pos, binary_serializer &sink) const override {
                    return mptr()->dispatch(pos, sink);
                }

            private:
                template<class F>
                auto dispatch(size_t pos, F &f) -> decltype(f(std::declval<int &>())) {
                    ACTOR_ASSERT(pos < sizeof...(Ts));
                    switch (pos) {
                        ACTOR_TUPLE_VALS_DISPATCH(0);
                        ACTOR_TUPLE_VALS_DISPATCH(1);
                        ACTOR_TUPLE_VALS_DISPATCH(2);
                        ACTOR_TUPLE_VALS_DISPATCH(3);
                        ACTOR_TUPLE_VALS_DISPATCH(4);
                        ACTOR_TUPLE_VALS_DISPATCH(5);
                        ACTOR_TUPLE_VALS_DISPATCH(6);
                        ACTOR_TUPLE_VALS_DISPATCH(7);
                        ACTOR_TUPLE_VALS_DISPATCH(8);
                        ACTOR_TUPLE_VALS_DISPATCH(9);
                        default:
                            // fall back to recursive dispatch function
                            static constexpr size_t max_pos = sizeof...(Ts) - 1;
                            tup_ptr_access_pos<(10 < max_pos ? 10 : max_pos), max_pos> first;
                            return rec_dispatch(pos, f, first);
                    }
                }

                template<class F, size_t N>
                auto rec_dispatch(size_t, F &f, tup_ptr_access_pos<N, N>) -> decltype(f(std::declval<int &>())) {
                    return tuple_inspect_delegate<N, N>(data_, f);
                }

                template<class F, size_t X, size_t N>
                auto rec_dispatch(size_t pos, F &f, tup_ptr_access_pos<X, N> token)
                    -> decltype(f(std::declval<int &>())) {
                    return pos == X ? tuple_inspect_delegate<X, N>(data_, f) : rec_dispatch(pos, f, next(token));
                }

                tuple_vals_impl *mptr() const {
                    return const_cast<tuple_vals_impl *>(this);
                }

                data_type data_;
                std::array<rtti_pair, sizeof...(Ts)> types_;
            };

            template<class... Ts>
            class tuple_vals : public tuple_vals_impl<message_data, Ts...> {
            public:
                static_assert(sizeof...(Ts) > 0, "tuple_vals is not allowed to be empty");

                using super = tuple_vals_impl<message_data, Ts...>;

                using super::super;

                using super::copy;

                tuple_vals *copy() const override {
                    return new tuple_vals(*this);
                }
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
