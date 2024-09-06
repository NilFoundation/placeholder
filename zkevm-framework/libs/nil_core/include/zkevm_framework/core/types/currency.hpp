#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_CURRENCY_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_CURRENCY_HPP_

#include "ssz++.hpp"
#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/value.hpp"

namespace core {
    namespace types {
        using CurrencyId = Hash;

        struct CurrencyBalance : ssz::ssz_container {
            CurrencyId m_currency;
            Value m_balance;

            SSZ_CONT(m_currency, m_balance)
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_CURRENCY_HPP_
