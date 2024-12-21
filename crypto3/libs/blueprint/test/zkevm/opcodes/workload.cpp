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

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"
#define BOOST_TEST_MODULE zkevm_workload_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include "nil/blueprint/zkevm/zkevm_word.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include "../opcode_tester.hpp"

#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

#include <ios>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>
#include "../../test_plonk_component.hpp"

#include <future>
#include <thread>
#include <chrono>

using namespace nil;
using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::crypto3::algebra;


BOOST_AUTO_TEST_SUITE(zkevm_workload_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_workload_test) {
    using field_type = fields::pallas_base_field;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using table_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    const std::vector<zkevm_opcode> implemented_opcodes = {
        zkevm_opcode::ADD, zkevm_opcode::SUB, zkevm_opcode::AND, zkevm_opcode::OR, zkevm_opcode::XOR
        ,zkevm_opcode::BYTE, zkevm_opcode::SHL, zkevm_opcode::SHR
        ,zkevm_opcode::SAR, zkevm_opcode::SIGNEXTEND
        ,zkevm_opcode::EQ, zkevm_opcode::GT, zkevm_opcode::LT, zkevm_opcode::SGT, zkevm_opcode::SLT
        ,zkevm_opcode::DIV, zkevm_opcode::MOD, zkevm_opcode::SDIV, zkevm_opcode::SMOD, zkevm_opcode::ISZERO
        ,zkevm_opcode::ADDMOD, zkevm_opcode::MULMOD, zkevm_opcode::MUL, zkevm_opcode::NOT
    };
    const std::size_t num_of_opcodes = implemented_opcodes.size(),
        workload = 32767;
//        workload = 63;

    assignment_type assignment(0, 0, 0, 0);
    circuit_type circuit;
    zkevm_circuit<field_type> evm_circuit(assignment, circuit, workload * 12 + 1 , workload * 12 + 10);
    zk::snark::pack_lookup_tables_horizontal(
        circuit.get_reserved_indices(),
        circuit.get_reserved_tables(),
        circuit.get_reserved_dynamic_tables(),
        circuit, assignment,
        assignment.rows_amount(),
        30000000
    );

    zkevm_table<field_type> zkevm_table(evm_circuit, assignment);
    zkevm_opcode_tester opcode_tester;

    // incorrect test logic, but we have no memory operations so
    for(std::size_t i = 0; i < workload; i++) {
        opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x11_big_uint256);
        opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x22_big_uint256);
        opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x33_big_uint256);
        opcode_tester.push_opcode(implemented_opcodes[i % num_of_opcodes]);
    }
    opcode_tester.push_opcode(zkevm_opcode::RETURN);

    zkevm_machine_type machine = get_empty_machine(zkevm_keccak_hash(opcode_tester.get_bytecode()));
    auto opcodes = opcode_tester.get_opcodes();
    for( std::size_t i = 0; i < opcodes.size(); i++ ){
        machine.apply_opcode(opcodes[i].first, opcodes[i].second);  zkevm_table.assign_opcode(machine);
    }

    typename zkevm_circuit<field_type>::bytecode_table_component::input_type bytecode_input;
    bytecode_input.new_bytecode(opcode_tester.get_bytecode());
    bytecode_input.new_bytecode({0x60,0x40,0x60,0x80, 0xF3});

    zkevm_table.finalize_test(bytecode_input);

    // Prepare table description for table printing
    table_description_type desc(
        assignment.witnesses_amount(), assignment.public_inputs_amount(),
        assignment.constants_amount(), assignment.selectors_amount()
    );
    desc.usable_rows_amount = assignment.rows_amount();
    nil::crypto3::zk::snark::basic_padding(assignment);
    desc.rows_amount = assignment.rows_amount();

    print_zk_circuit_and_table_to_file(
        "opcode_workload",
        circuit,
        desc,
        assignment
    );
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}

BOOST_AUTO_TEST_SUITE_END()
