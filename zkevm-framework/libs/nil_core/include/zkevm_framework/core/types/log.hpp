#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_LOG_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_LOG_HPP_

#include "ssz++.hpp"
#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/address.hpp"

namespace core {
    namespace types {
        struct Log : ssz::ssz_variable_size_container {
            Address m_address;
            Hash m_topics;
            Bytes<6000> m_data;

            SSZ_CONT(m_address, m_topics, m_data)
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_LOG_HPP_
