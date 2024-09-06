#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_ADDRESS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_ADDRESS_HPP_

#include <array>
#include <cstddef>
#include <cstdint>

namespace core {
    namespace types {
        constexpr std::size_t ADDR_SIZE = 20;

        class Address : public std::array<std::byte, ADDR_SIZE> {};

        constexpr Address EMPTY_ADDRESS = {std::byte{0x0}};
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_ADDRESS_HPP_
