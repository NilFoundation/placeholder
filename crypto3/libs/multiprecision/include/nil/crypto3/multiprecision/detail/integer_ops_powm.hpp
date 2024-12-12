#pragma once

#include <limits>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/ops/powm.hpp"

namespace nil::crypto3::multiprecision {
    template<typename T1, typename T2, typename T3,
             std::enable_if_t<std::numeric_limits<std::decay_t<T1>>::is_integer &&
                                  std::numeric_limits<std::decay_t<T2>>::is_integer &&
                                  std::is_integral_v<T3>,
                              int> = 0>
    constexpr T3 powm(T1 &&b, T2 &&e, T3 m) {
        // TODO(ioxid): optimize
        return static_cast<T3>(
            nil::crypto3::multiprecision::powm(std::forward<T1>(b), std::forward<T2>(e),
                                               detail::as_big_uint(detail::unsigned_or_throw(m))));
    }
}  // namespace nil::crypto3::multiprecision
