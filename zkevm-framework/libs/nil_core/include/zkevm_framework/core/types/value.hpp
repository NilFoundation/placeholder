#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_VALUE_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_VALUE_HPP_

#include "intx/intx.hpp"
#include "ssz++.hpp"

namespace core {
    namespace types {
        struct Value : ssz::ssz_container {
            intx::uint256 m_value;

            SSZ_CONT(m_value)
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_VALUE_HPP_
