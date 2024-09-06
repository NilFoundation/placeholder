#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_COMMON_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_COMMON_HPP_

#include <array>
#include <cstddef>
#include <cstdint>

#include "ssz++.hpp"

namespace core {
    constexpr std::size_t HASH_SIZE = 32;

    class Hash : public std::array<std::byte, HASH_SIZE> {};

    /**
     * @brief Vector of bytes, serialisable with SSZ.
     * @tparam N size limit of a vector (see SSZ specification)
     */
    template<std::size_t N>
    using Bytes = ssz::list<std::byte, N>;
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_COMMON_HPP_
