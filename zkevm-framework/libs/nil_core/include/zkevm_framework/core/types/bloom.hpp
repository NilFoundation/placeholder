#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_BLOOM_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_BLOOM_HPP_

#include <array>
#include <cstddef>
#include <cstdint>

namespace core {
    namespace types {
        constexpr std::size_t BLOOM_BYTE_LENGTH = 256;

        class Bloom : public std::array<std::byte, BLOOM_BYTE_LENGTH> {};
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_BLOOM_HPP_
