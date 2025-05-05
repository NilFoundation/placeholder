#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/dummy.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType>
    using zkevm_staticcall_operation = zkevm_dummy_operation<FieldType>;
}