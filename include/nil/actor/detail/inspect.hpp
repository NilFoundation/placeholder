//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <chrono>

#include <nil/actor/meta/load_callback.hpp>

namespace nil::actor::detail {

    // -- inject `inspect` overloads for some STL types ----------------------------

    template<class Inspector, class Rep, class Period>
    auto inspect(Inspector &f, std::chrono::duration<Rep, Period> &x) {
        if constexpr (Inspector::reads_state) {
            return f(x.count());
        } else {
            auto tmp = Rep {};
            auto cb = [&] { x = std::chrono::duration<Rep, Period> {tmp}; };
            return f(tmp, meta::load_callback(cb));
        }
    }

    template<class Inspector, class Clock, class Duration>
    auto inspect(Inspector &f, std::chrono::time_point<Clock, Duration> &x) {
        if constexpr (Inspector::reads_state) {
            return f(x.time_since_epoch());
        } else {
            auto tmp = Duration {};
            auto cb = [&] { x = std::chrono::time_point<Clock, Duration> {tmp}; };
            return f(tmp, meta::load_callback(cb));
        }
    }

    // -- provide `is_inspectable` trait for metaprogramming -----------------------

    /// Checks whether `T` is inspectable by `Inspector`.
    template<class Inspector, class T>
    class is_inspectable {
    private:
        template<class U>
        static auto sfinae(Inspector &x, U &y) -> decltype(inspect(x, y));

        static std::false_type sfinae(Inspector &, ...);

        using result_type = decltype(sfinae(std::declval<Inspector &>(), std::declval<T &>()));

    public:
        static constexpr bool value = !std::is_same<result_type, std::false_type>::value;
    };

    // Pointers are never inspectable.
    template<class Inspector, class T>
    struct is_inspectable<Inspector, T *> : std::false_type {};

}    // namespace nil::actor::detail