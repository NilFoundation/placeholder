//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE blueprint_plonk_bytecode_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/l1_wrapper.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>

#include "./test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

std::string bytecode_for = "0x60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6103188061009c6000396000f3fe6080604052348015610019576000806100166100bb565b50505b50600436106100345760003560e01c806347b0b31c14610042575b60008061003f6100bb565b50505b61005c600480360381019061005791906101a3565b610072565b60405161006991906101f7565b60405180910390f35b60006001905060005b828110156100a457838261008f9190610212565b9150808061009c90610276565b91505061007b565b5080600081906100b2610129565b50505092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b868110156100f65780860151816040840101526020810190506100d8565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b60408110156101895760008183015260208101905061016f565b505050565b60008135905061019d816102f8565b92915050565b600080604083850312156101bf576000806101bc6100bb565b50505b60006101cd8582860161018e565b92505060206101de8582860161018e565b9150509250929050565b6101f18161026c565b82525050565b600060208201905061020c60008301846101e8565b92915050565b600061021d8261026c565b91506102288361026c565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615610261576102606102bf565b5b828202905092915050565b6000819050919050565b60006102818261026c565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156102b4576102b36102bf565b5b600182019050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000006000526011600452602460006102f46100bb565b5050565b6103018161026c565b8114610315576000806103126100bb565b50505b5056";
std::string bytecode_addition = "0x60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6102b38061009c6000396000f3fe6080604052348015610019576000806100166100a3565b50505b50600436106100345760003560e01c8063f080118c14610042575b60008061003f6100a3565b50505b61005c6004803603810190610057919061018b565b610072565b60405161006991906101df565b60405180910390f35b6000818361008091906101fa565b6000819061008c610111565b505050818361009b91906101fa565b905092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b868110156100de5780860151816040840101526020810190506100c0565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b604081101561017157600081830152602081019050610157565b505050565b60008135905061018581610293565b92915050565b600080604083850312156101a7576000806101a46100a3565b50505b60006101b585828601610176565b92505060206101c685828601610176565b9150509250929050565b6101d981610250565b82525050565b60006020820190506101f460008301846101d0565b92915050565b600061020582610250565b915061021083610250565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156102455761024461025a565b5b828201905092915050565b6000819050919050565b7f4e487b710000000000000000000000000000000000000000000000000000000060005260116004526024600061028f6100a3565b5050565b61029c81610250565b81146102b0576000806102ad6100a3565b50505b5056";

template <typename field_type>
void test_zkevm_bytecode(
    const nil::blueprint::bbf::zkevm_keccak_buffers &bytecodes,
    const nil::blueprint::bbf::zkevm_keccak_buffers &keccak_buffers,
    std::size_t max_bytecode_size,
    std::size_t max_keccak_blocks,
    bool expected_result = true
){
    typename nil::blueprint::bbf::bytecode<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
    typename nil::blueprint::bbf::bytecode<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type bytecode_constraint_input;

    bytecode_assignment_input.rlc_challenge = 7;
    bytecode_assignment_input.bytecodes = bytecodes;
    bytecode_assignment_input.keccak_buffers = keccak_buffers;

    bool result = test_l1_wrapper<field_type, nil::blueprint::bbf::bytecode>(
        {7},                        //  Public input
        bytecode_assignment_input,  //  Assignment input
        bytecode_constraint_input,  //  Circuit input
        max_bytecode_size,          //  Sizes
        max_keccak_blocks           //  Keccak blocks amount
    );
    BOOST_CHECK(result == expected_result); // Max_rw, Max_mpt
}


BOOST_AUTO_TEST_SUITE(blueprint_bn_test_suite)
    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_for));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa12312384710283470321894798234702918470189347"));
    test_zkevm_bytecode<field_type>(input, keccak_input, 1000, 30);
}
BOOST_AUTO_TEST_CASE(two_small_contracts){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_for));
    input.new_buffer(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_addition));

    test_zkevm_bytecode<field_type>(input, keccak_input, 2046, 30);
}
BOOST_AUTO_TEST_CASE(not_hashed_test){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_for));
    input.new_buffer(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa12312384710283470321894798234702918470189347"));

    test_zkevm_bytecode<field_type>(input, keccak_input, 2046, 30, false);
}
BOOST_AUTO_TEST_SUITE_END()
