#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/dummy.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{

            template<typename FieldType>
            using zkevm_delegatecall_operation = zkevm_dummy_operation<FieldType>;
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
