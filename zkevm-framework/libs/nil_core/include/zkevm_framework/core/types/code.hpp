#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_CODE_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_CODE_HPP_

#include "zkevm_framework/core/common.hpp"

namespace core {
    namespace types {
        template<std::size_t N>
        class Code : public Bytes<N> {};
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_CODE_HPP_
