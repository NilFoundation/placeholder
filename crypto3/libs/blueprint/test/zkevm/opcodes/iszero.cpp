//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE zkevm_iszero_test

#include <boost/test/unit_test.hpp>

// #include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks.hpp>
#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm/zkevm_table.hpp>
#include "../opcode_tester.hpp"

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(zkevm_iszero_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_iszero_test) {
    using field_type = fields::pallas_base_field;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    assignment_type assignment(0, 0, 0, 0);
    circuit_type circuit;
    zkevm_circuit<field_type> evm_circuit(assignment, circuit, 25, 100);
    nil::crypto3::zk::snark::pack_lookup_tables_horizontal(
        circuit.get_reserved_indices(),
        circuit.get_reserved_tables(),
        circuit.get_reserved_dynamic_tables(),
        circuit, assignment,
        assignment.rows_amount(),
        65536
    );

    zkevm_table<field_type> zkevm_table(evm_circuit, assignment);
    zkevm_opcode_tester opcode_tester;
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, 1234567890);
    opcode_tester.push_opcode(zkevm_opcode::ISZERO);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, 0);
    opcode_tester.push_opcode(zkevm_opcode::ISZERO);
    opcode_tester.push_opcode(zkevm_opcode::RETURN);

    zkevm_machine_type machine = get_empty_machine(opcode_tester.get_bytecode(), zkevm_keccak_hash(opcode_tester.get_bytecode()));
    while(true) {
        machine.apply_opcode(opcode_tester.get_opcode_by_pc(machine.pc_next()).first, opcode_tester.get_opcode_by_pc(machine.pc_next()).second);
        zkevm_table.assign_opcode(machine);
        if( machine.tx_finish()) break;
    }

    typename zkevm_circuit<field_type>::bytecode_table_component::input_type bytecode_input;
    bytecode_input.new_bytecode(opcode_tester.get_bytecode());
    bytecode_input.new_bytecode({0x60,0x40,0x60,0x80, 0xF3});

    zkevm_table.finalize_test(bytecode_input);
    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
    nil::crypto3::zk::snark::basic_padding(assignment);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}
BOOST_AUTO_TEST_SUITE_END()
