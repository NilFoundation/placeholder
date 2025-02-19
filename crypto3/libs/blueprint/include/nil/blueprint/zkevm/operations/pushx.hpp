//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_pushx_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using zkevm_table_type = typename op_type::zkevm_table_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_pushx_operation(std::size_t _x) : byte_count(_x) {
                this->pc_gap = _x + 1;
                this->stack_input = 0;
                this->stack_output = 1;
                if(_x == 0) this->gas_cost = 2;
                BOOST_ASSERT(_x < 33); // the maximum push is 32 bytes
            }

            std::size_t byte_count;

            std::map<gate_class, std::pair<
                std::vector<std::pair<std::size_t, constraint_type>>,
                std::vector<std::pair<std::size_t, lookup_constraint_type>>
                >>
                generate_gates(zkevm_circuit_type &zkevm_circuit) override
            {
                const auto& state = zkevm_circuit.get_state();
                std::vector<std::pair<std::size_t, constraint_type>> constraints;
                std::vector<std::pair<std::size_t, lookup_constraint_type>> lookup_constraints;

                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };

                // Table layout                                             Row #
                // +---------+--------+------------------+---------------------+
                // |  bytes  |b0      | b1       | b2       | ... |  b31       |
                // +---------+--------+------------------+---------------------+
                // |  bytes  |255 - b0| 255 - b1 | 255 - b2 | ... |  255 -b31  |
                // +---------+--------+------------------+---------------------+

                std::size_t position = 1;

                // this will need dynamic lookups into bytecode and memory circuits, but for now we just check
                // Only bytes after byte_count may be non-zero

                for(std::size_t i = 0; i < 32 - byte_count; i++) {
                    constraints.push_back({position, var_gen(i)});
                    constraints.push_back({position, var_gen(i) + var_gen(i, +1) - 255}); // Byte range check
                }

                // For other bytes
                for(std::size_t i = 32-byte_count; i < 32; i++) {
                    constraints.push_back({position, var_gen(i) + var_gen(i, +1) - 255}); // Byte range check
                    lookup_constraints.push_back({ position, {zkevm_circuit.get_bytecode_table_id(), {
                        var_gen(i) - var_gen(i) + 1,
                        state.pc() + i - (32 - byte_count) + 1,
                        var_gen(i),
                        var_gen(i) - var_gen(i),
                        state.bytecode_hash_hi(),
                        state.bytecode_hash_lo()
                    }}});
                }

                return {{gate_class::MIDDLE_OP, {constraints, lookup_constraints}}};
            }

            void generate_assignments(
                zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine, zkevm_word_type bytecode_input
            ) {
                using word_type = typename zkevm_stack::word_type;

                zkevm_word_type a =
                    bytecode_input & wrapping_sub(word_type(1) << (8 * byte_count),
                                                  1);  // use only byte_count lowest bytes

                const std::array<std::uint8_t, 32> bytes = w_to_8(a);
                const std::vector<std::size_t> &witness_cols = zkevm_table.get_opcode_cols();
                assignment_type &assignment = zkevm_table.get_assignment();
                const std::size_t curr_row = zkevm_table.get_current_row();

                for (std::size_t i = 0; i < 32; i++) {
                    assignment.witness(witness_cols[i], curr_row) = bytes[i];
                    assignment.witness(witness_cols[i], curr_row + 1) = 255 - bytes[i]; // For range-checking
                }
            }

            void generate_assignments(zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine) override {
                 generate_assignments(zkevm_table, machine, 0);
            }

            std::size_t rows_amount() override {
                return 2;
            }
        };
    }   // namespace blueprint
}   // namespace nil
