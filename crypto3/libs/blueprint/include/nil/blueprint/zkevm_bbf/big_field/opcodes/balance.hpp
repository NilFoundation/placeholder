#pragma once

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/dummy.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            namespace zkevm_big_field{
                template<typename FieldType>
                using zkevm_balance_operation = zkevm_dummy_operation<FieldType>;
            }
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
