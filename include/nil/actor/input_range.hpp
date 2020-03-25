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

#include <iterator>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        template<class T>
        class input_range {
        public:
            virtual ~input_range() {
                // nop
            }

            input_range() = default;
            input_range(const input_range &) = default;
            input_range &operator=(const input_range &) = default;

            class iterator : public std::iterator<std::input_iterator_tag, T> {
            public:
                iterator(input_range *range) : xs_(range) {
                    if (xs_)
                        advance();
                    else
                        x_ = nullptr;
                }

                iterator(const iterator &) = default;
                iterator &operator=(const iterator &) = default;

                bool operator==(const iterator &other) const {
                    return xs_ == other.xs_;
                }

                bool operator!=(const iterator &other) const {
                    return !(*this == other);
                }

                T &operator*() {
                    return *x_;
                }

                T *operator->() {
                    return x_;
                }

                iterator &operator++() {
                    advance();
                    return *this;
                }

                iterator operator++(int) {
                    iterator copy {xs_};
                    advance();
                    return copy;
                }

            private:
                void advance() {
                    x_ = xs_->next();
                    if (!x_)
                        xs_ = nullptr;
                }

                input_range *xs_;
                T *x_;
            };

            virtual T *next() = 0;

            iterator begin() {
                return this;
            }

            iterator end() const {
                return nullptr;
            }
        };

        template<class I>
        class input_range_impl : public input_range<detail::value_type_of_t<I>> {
        public:
            using value_type = detail::value_type_of_t<I>;

            input_range_impl(I first, I last) : pos_(first), last_(last) {
                // nop
            }

            value_type *next() override {
                return (pos_ == last_) ? nullptr : &(*pos_++);
            }

        private:
            I pos_;
            I last_;
        };

        /// @relates input_range
        template<class I>
        input_range_impl<I> make_input_range(I first, I last) {
            return {first, last};
        }

    }    // namespace actor
}    // namespace nil
