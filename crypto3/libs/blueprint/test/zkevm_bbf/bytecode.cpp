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

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/babybear.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/bytecode.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

std::string bytecode_for = "0x60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6103188061009c6000396000f3fe6080604052348015610019576000806100166100bb565b50505b50600436106100345760003560e01c806347b0b31c14610042575b60008061003f6100bb565b50505b61005c600480360381019061005791906101a3565b610072565b60405161006991906101f7565b60405180910390f35b60006001905060005b828110156100a457838261008f9190610212565b9150808061009c90610276565b91505061007b565b5080600081906100b2610129565b50505092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b868110156100f65780860151816040840101526020810190506100d8565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b60408110156101895760008183015260208101905061016f565b505050565b60008135905061019d816102f8565b92915050565b600080604083850312156101bf576000806101bc6100bb565b50505b60006101cd8582860161018e565b92505060206101de8582860161018e565b9150509250929050565b6101f18161026c565b82525050565b600060208201905061020c60008301846101e8565b92915050565b600061021d8261026c565b91506102288361026c565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615610261576102606102bf565b5b828202905092915050565b6000819050919050565b60006102818261026c565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156102b4576102b36102bf565b5b600182019050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000006000526011600452602460006102f46100bb565b5050565b6103018161026c565b8114610315576000806103126100bb565b50505b5056";
std::string bytecode_addition = "0x60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6102b38061009c6000396000f3fe6080604052348015610019576000806100166100a3565b50505b50600436106100345760003560e01c8063f080118c14610042575b60008061003f6100a3565b50505b61005c6004803603810190610057919061018b565b610072565b60405161006991906101df565b60405180910390f35b6000818361008091906101fa565b6000819061008c610111565b505050818361009b91906101fa565b905092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b868110156100de5780860151816040840101526020810190506100c0565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b604081101561017157600081830152602081019050610157565b505050565b60008135905061018581610293565b92915050565b600080604083850312156101a7576000806101a46100a3565b50505b60006101b585828601610176565b92505060206101c685828601610176565b9150509250929050565b6101d981610250565b82525050565b60006020820190506101f460008301846101d0565b92915050565b600061020582610250565b915061021083610250565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156102455761024461025a565b5b828201905092915050565b6000819050919050565b7f4e487b710000000000000000000000000000000000000000000000000000000060005260116004526024600061028f6100a3565b5050565b61029c81610250565b81146102b0576000806102ad6100a3565b50505b5056";
std::string bytecode_mstore8 = "0x608060405234801561001057600080fd5b506004361061002b5760003560e01c8063ec66f8b914610030575b600080fd5b61003861004a565b60405190815260200160405180910390f35b60408051602080825281830190925260009160609190602082018180368337019050509050600160005461007e91906106b4565b60008190555060005460ff1660f81b816000815181106100a0576100a06106cd565b60200101906001600160f81b031916908160001a905350600860005461ff0016901c60f81b816001815181106100d8576100d86106cd565b60200101906001600160f81b031916908160001a905350601060005462ff000016901c60f81b81600281518110610111576101116106cd565b60200101906001600160f81b031916908160001a905350601860005463ff00000016901c60f81b8160038151811061014b5761014b6106cd565b60200101906001600160f81b031916908160001a905350602060005464ff0000000016901c60f81b81600481518110610186576101866106cd565b60200101906001600160f81b031916908160001a905350602860005465ff000000000016901c60f81b816005815181106101c2576101c26106cd565b60200101906001600160f81b031916908160001a905350603060005466ff00000000000016901c60f81b816006815181106101ff576101ff6106cd565b60200101906001600160f81b031916908160001a905350603860005467ff0000000000000016901c60f81b8160078151811061023d5761023d6106cd565b60200101906001600160f81b031916908160001a905350604060005468ff000000000000000016901c60f81b8160088151811061027c5761027c6106cd565b60200101906001600160f81b031916908160001a905350604860005469ff00000000000000000016901c60f81b816009815181106102bc576102bc6106cd565b60200101906001600160f81b031916908160001a905350605060005460ff604c1b16901c60f81b81600a815181106102f6576102f66106cd565b60200101906001600160f81b031916908160001a905350605860005460ff60541b16901c60f81b81600b81518110610330576103306106cd565b60200101906001600160f81b031916908160001a905350606060005460ff605c1b16901c60f81b81600c8151811061036a5761036a6106cd565b60200101906001600160f81b031916908160001a905350606860005460ff60641b16901c60f81b81600d815181106103a4576103a46106cd565b60200101906001600160f81b031916908160001a905350607060005460ff606c1b16901c60f81b81600e815181106103de576103de6106cd565b60200101906001600160f81b031916908160001a905350607860005460ff60741b16901c60f81b81600f81518110610418576104186106cd565b60200101906001600160f81b031916908160001a90535080600081518110610442576104426106cd565b0160200151815160f89190911c925081906001908110610464576104646106cd565b01602001516104769060f81c836106e3565b91508060028151811061048b5761048b6106cd565b016020015161049d9060f81c836106e3565b9150806003815181106104b2576104b26106cd565b01602001516104c49060f81c836106e3565b9150806004815181106104d9576104d96106cd565b01602001516104eb9060f81c836106e3565b915080600581518110610500576105006106cd565b01602001516105129060f81c836106e3565b915080600681518110610527576105276106cd565b01602001516105399060f81c836106e3565b91508060078151811061054e5761054e6106cd565b01602001516105609060f81c836106e3565b915080600881518110610575576105756106cd565b01602001516105879060f81c836106e3565b91508060098151811061059c5761059c6106cd565b01602001516105ae9060f81c836106e3565b915080600a815181106105c3576105c36106cd565b01602001516105d59060f81c836106e3565b915080600b815181106105ea576105ea6106cd565b01602001516105fc9060f81c836106e3565b915080600c81518110610611576106116106cd565b01602001516106239060f81c836106e3565b915080600d81518110610638576106386106cd565b016020015161064a9060f81c836106e3565b915080600e8151811061065f5761065f6106cd565b01602001516106719060f81c836106e3565b915080600f81518110610686576106866106cd565b01602001516106989060f81c836106e3565b91505090565b634e487b7160e01b600052601160045260246000fd5b818103818111156106c7576106c761069e565b92915050565b634e487b7160e01b600052603260045260246000fd5b80820281158282048414176106c7576106c761069e56fea2646970667358";

class zkEVMBytecodeTestFixture: public CircuitTestFixture {
public:
    template <typename FieldType>
    void test_big_zkevm_bytecode(
        const nil::blueprint::bbf::zkevm_keccak_buffers &bytecodes,
        const nil::blueprint::bbf::zkevm_keccak_buffers &keccak_buffers,
        std::size_t max_bytecode_size,
        std::size_t max_keccak_blocks,
        bool expected_result = true
    ){
        using SmallFieldType = typename FieldType::small_subfield;
        typename zkevm_big_field::bytecode<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
        bytecode_assignment_input.rlc_challenge = 7;
        bytecode_assignment_input.bytecodes = bytecodes;
        bytecode_assignment_input.keccak_buffers = keccak_buffers;

        bool result = test_bbf_component<FieldType, zkevm_big_field::bytecode>(
            "bytecode",
            {7},                        //  Public input
            bytecode_assignment_input,  //  Assignment input
            max_bytecode_size,          //  Sizes
            max_keccak_blocks           //  Keccak blocks amount
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt
    }


    template <typename FieldType>
    void test_small_zkevm_bytecode(
        const nil::blueprint::bbf::zkevm_keccak_buffers &bytecodes,
        const nil::blueprint::bbf::zkevm_keccak_buffers &keccak_buffers,
        std::size_t max_bytecode_size,
        std::size_t max_keccak_blocks,
        bool expected_result = true
    ){
        using SmallFieldType = typename FieldType::small_subfield;
        typename zkevm_small_field::bytecode<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
        bytecode_assignment_input.rlc_challenge = 7;
        bytecode_assignment_input.bytecodes = bytecodes;
        bytecode_assignment_input.keccak_buffers = keccak_buffers;

        bool result = test_bbf_component<FieldType, zkevm_small_field::bytecode>(
            "bytecode-s",
            {7},                        //  Public input
            bytecode_assignment_input,  //  Assignment input
            max_bytecode_size,          //  Sizes
            max_keccak_blocks,          //  Keccak blocks amount
            5                           //  Max bytecodes amount
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt
    }
};

BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);
BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_bytecode, zkEVMBytecodeTestFixture)
    using big_field_type = nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
    using small_field_type = nil::crypto3::algebra::fields::babybear_fp4;
BOOST_AUTO_TEST_CASE(one_contract){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_for));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa12312384710283470321894798234702918470189347"));
    test_big_zkevm_bytecode<big_field_type>(input, keccak_input, 1000, 30);
    test_small_zkevm_bytecode<small_field_type>(input, keccak_input, 1000, 30);
}

BOOST_AUTO_TEST_CASE(two_contracts){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_for));
    input.new_buffer(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_addition));

    test_big_zkevm_bytecode<big_field_type>(input, keccak_input, 5000, 30);
    test_small_zkevm_bytecode<small_field_type>(input, keccak_input, 5000, 30);
}

BOOST_AUTO_TEST_CASE(mstore8){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_mstore8));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_mstore8));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa12312384710283470321894798234702918470189347"));
    test_big_zkevm_bytecode<big_field_type>(input, keccak_input, 10000, 50);
    test_small_zkevm_bytecode<small_field_type>(input, keccak_input, 10000, 50);
}

BOOST_AUTO_TEST_CASE(not_hashed){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    input.new_buffer(hex_string_to_bytes(bytecode_for));
    input.new_buffer(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa12312384710283470321894798234702918470189347"));

    test_big_zkevm_bytecode<big_field_type>(input, keccak_input, 5000, 50, false);
    test_small_zkevm_bytecode<small_field_type>(input, keccak_input, 5000, 50, false);
}

BOOST_AUTO_TEST_CASE(new_error, *boost::unit_test::disabled()){
    nil::blueprint::bbf::zkevm_keccak_buffers input;
    std::string bytecode2 = "0x608060405234801561000f575f80fd5b5060043610610029575f3560e01c806364b3cfe61461002d575b5f80fd5b610047600480360381019061004291906100d6565b61005d565b6040516100549190610110565b60405180910390f35b5f8060405180606001604052806029815260200161019e6029913990505f835190505f8081548092919061009090610156565b91905055508092505050919050565b5f80fd5b5f819050919050565b6100b5816100a3565b81146100bf575f80fd5b50565b5f813590506100d0816100ac565b92915050565b5f602082840312156100eb576100ea61009f565b5b5f6100f8848285016100c2565b91505092915050565b61010a816100a3565b82525050565b5f6020820190506101235f830184610101565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610160826100a3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361019257610191610129565b5b60018201905091905056fe112233445566778899ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    input.new_buffer(hex_string_to_bytes(bytecode2));

    nil::blueprint::bbf::zkevm_keccak_buffers keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode2));
    test_small_zkevm_bytecode<small_field_type>(input, keccak_input, 5000, 50);
}

BOOST_AUTO_TEST_SUITE_END()
