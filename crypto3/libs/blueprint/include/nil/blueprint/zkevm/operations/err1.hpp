//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
        class zkevm_err1_operation : public zkevm_operation<BlueprintFieldType> {
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
            using state_var = state_variable<BlueprintFieldType>;

            struct err1_map{
                std::array<state_var, 16> chunks;
                state_var is_jump;
                state_var is_jumpi;
                state_var is_overflow;
                state_var bytecode_length;
                state_var is_new_byte_opcode;
                state_var new_byte;
                state_var dest_diff;
                state_var cond_chunks_sum_inversed;
                state_var new_byte_diff_inversed;

                err1_map(std::vector<std::size_t> W, std::size_t range_checked_cols_amount = 32){
                    for( std::size_t i = 0; i < 16; i++) chunks[i] = state_var(W[i]);
                    is_jump = state_var(W[16]);
                    is_jumpi = state_var(W[17]);
                    is_overflow = state_var(W[18]);
                    bytecode_length = state_var(W[19]);
                    is_new_byte_opcode = state_var(W[20]);
                    new_byte = state_var(W[21]);
                    dest_diff = state_var(W[22]);
                    cond_chunks_sum_inversed = state_var(W[range_checked_cols_amount]);
                    new_byte_diff_inversed = state_var(W[range_checked_cols_amount+1]);
                }
            };

            zkevm_err1_operation(){
                this->gas_cost = 0;
            }

            std::map<gate_class, std::pair<
                std::vector<std::pair<std::size_t, constraint_type>>,
                std::vector<std::pair<std::size_t, lookup_constraint_type>>
            >> generate_gates(zkevm_circuit_type &zkevm_circuit) override {
                using circuit_integral_type = typename BlueprintFieldType::integral_type;

                const auto &state = zkevm_circuit.get_state();
                auto witness_cols = zkevm_circuit.get_opcode_cols();
                std::size_t range_checked_cols_amount = zkevm_circuit.get_opcode_range_checked_cols_amount();
                err1_map m(witness_cols, range_checked_cols_amount);

                std::vector<std::pair<std::size_t, constraint_type>> constraints;
                std::vector<std::pair<std::size_t, lookup_constraint_type>> lookup_constraints;

                std::size_t position = 1;//Top row
                constraints.push_back({position, m.is_jump() * (m.is_jump() - 1)});
                constraints.push_back({position, m.is_jumpi() * (m.is_jumpi() - 1)});
                constraints.push_back({position, m.is_jumpi() + m.is_jump() - 1});
                constraints.push_back({position, m.is_overflow() * (m.is_overflow() - 1)});

                constraint_type sum_cond_chunks;
                for( std::size_t i = 0; i < 16; i++){
                    sum_cond_chunks += m.chunks[i]();
                }
                constraints.push_back({position, m.is_jump() * sum_cond_chunks});
                constraints.push_back({position, m.is_jumpi() * (sum_cond_chunks * m.cond_chunks_sum_inversed() - 1)});

                constraints.push_back({position, m.dest_diff() * m.is_overflow()});
//                constraints.push_back({position, m.chunks[15].next()});
                constraints.push_back({position, (m.bytecode_length() - m.chunks[0].next() -  m.dest_diff()) * (1 - m.is_overflow())});

                constraint_type zero_constraint;
                constraint_type one_constraint = zero_constraint + 1;

                lookup_constraints.push_back({position,{ zkevm_circuit.get_bytecode_table_id(), {
                    one_constraint,
                    state.pc(),
                    m.is_jump() * (zkevm_circuit.get_opcodes_info().get_opcode_value(zkevm_opcode::JUMP))
                        + m.is_jumpi() * (zkevm_circuit.get_opcodes_info().get_opcode_value(zkevm_opcode::JUMPI)),
                    one_constraint,
                    state.bytecode_hash_hi(),
                    state.bytecode_hash_lo()
                }}});

                lookup_constraints.push_back({position,{ zkevm_circuit.get_bytecode_table_id(), {
                    zero_constraint,
                    zero_constraint,
                    m.bytecode_length(),
                    zero_constraint,
                    state.bytecode_hash_hi(),
                    state.bytecode_hash_lo()
                }}});

                lookup_constraints.push_back({position,{ zkevm_circuit.get_bytecode_table_id(), {
                    (1 - m.is_overflow()),
                    (1 - m.is_overflow()) * m.chunks[0].next(),    // Correct destination fits in one chunk. OVerwize is_overflow = true
                    (1 - m.is_overflow()) * m.new_byte(),
                    (1 - m.is_overflow()) * m.is_new_byte_opcode(),
                    (1 - m.is_overflow()) * state.bytecode_hash_hi(),
                    (1 - m.is_overflow()) * state.bytecode_hash_lo()
                }}});
                return {{gate_class::MIDDLE_OP,  {constraints, lookup_constraints}}};
            }

            void generate_assignments(zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine,
                                      zkevm_word_type additional_input) {
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                using circuit_integral_type = typename BlueprintFieldType::integral_type;

                assignment_type &assignment = zkevm_table.get_assignment();
                const std::size_t curr_row = zkevm_table.get_current_row();
                auto witness_cols = zkevm_table.get_opcode_cols();
                std::size_t range_checked_cols_amount = zkevm_table.get_opcode_range_checked_cols_amount();
                const std::size_t chunks_amount = 16;

                zkevm_opcode opcode_mnemo = machine.error_opcode();
                std::size_t opcode_num = zkevm_table.get_opcodes_info().get_opcode_number(opcode_mnemo);
                std::size_t opcode_value = zkevm_table.get_opcodes_info().get_opcode_value(opcode_mnemo);
                std::cout << "\topcode = " << opcode_to_string(opcode_mnemo) << std::endl;

                bool is_jump = (opcode_mnemo == zkevm_opcode::JUMP);
                bool is_jumpi = (opcode_mnemo == zkevm_opcode::JUMPI);
                zkevm_word_type dest = machine.stack_top();
                zkevm_word_type condition = is_jumpi?machine.stack_top(1):0;
                std::cout << "\tdest = " << dest << std::endl;

                std::size_t bytecode_length = machine.bytecode_length();
                std::cout << "\tbytecode_length = " << bytecode_length << std::endl;

                bool is_overflow = (dest >= bytecode_length);
                std::cout << "\tis_overflow = " << is_overflow << std::endl;
                const std::vector<value_type> dest_chunks = zkevm_word_to_field_element<BlueprintFieldType>(dest);
                const std::vector<value_type> condition_chunks = zkevm_word_to_field_element<BlueprintFieldType>(condition);

                err1_map m(witness_cols ,32);

                value_type c = 0;
                for (std::size_t i = 0; i < chunks_amount; i++) {
                    assignment.witness(m.chunks[i].index, curr_row) = condition_chunks[i];
                    assignment.witness(m.chunks[i].index, curr_row+1) = dest_chunks[i];
                    c += condition_chunks[i];
                }

                std::size_t dest_16 = w_to_16(dest)[chunks_amount - 1];
                std::cout << "\tdest 16 = " << dest_16 << std::endl;
                std::uint8_t new_byte = is_overflow? 0 : machine.bytecode_byte(dest_16);
                bool is_byte_opcode = is_overflow? 0: machine.is_bytecode_byte_opcode(dest_16);

                assignment.witness(m.is_jump.index, curr_row) = is_jump;
                assignment.witness(m.is_jumpi.index, curr_row) = is_jumpi;
                assignment.witness(m.is_overflow.index, curr_row) = is_overflow;
                assignment.witness(m.bytecode_length.index, curr_row) = machine.bytecode_length();
                assignment.witness(m.is_new_byte_opcode.index, curr_row) = is_byte_opcode;
                assignment.witness(m.new_byte.index, curr_row) = new_byte;
                assignment.witness(m.dest_diff.index, curr_row) = is_overflow? 0: machine.bytecode_length() - dest_16;
                assignment.witness(m.cond_chunks_sum_inversed.index, curr_row) = (c == 0? c: c.inversed());
                assignment.witness(m.new_byte_diff_inversed.index, curr_row) = (value_type(new_byte) - 0x5f).inversed();
            }

            void generate_assignments(zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine) override {
                 generate_assignments(zkevm_table, machine, 0); // just to have a default
            }

            std::size_t rows_amount() override {
                return 2;
            }

            constraint_type stack_size_transition(const zkevm_circuit_type &zkevm_circuit) override {
                constraint_type c;
                return c;
            }
            constraint_type gas_transition(const zkevm_circuit_type &zkevm_circuit) override {
                constraint_type c;
                return c;
            }
            constraint_type pc_transition(const zkevm_circuit_type &zkevm_circuit) override {
                constraint_type c;
                return c;
            }
        };
    }   // namespace blueprint
}   // namespace nil
