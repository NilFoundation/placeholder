//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_detail_mpt_nonce_changed_test

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <typeinfo>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/zkevm/mpt/mpt_verifier.hpp>

#include "../../test_plonk_component.hpp"

#include <iostream>  
#include <sstream> // use stringstream class  

using namespace nil;
using namespace nil::crypto3::hashes::detail;

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length, std::size_t WitnessColumns>
void test_mpt_nonce_changed(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t WitnessesAmount = 3; // May be changed in next version
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 8;
    constexpr std::size_t SelectorColumns = 8;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;
 
    using component_type = blueprint::components::mpt_nonce_changed<ArithmetizationType, BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length>;

    size_t public_input_index = 0;

    typename component_type::input_type instance_input;
    instance_input.eth_address    = var(0, public_input_index, false, var::column_type::public_input);
    instance_input.mpt_proof_type = var(0, public_input_index + 1, false, var::column_type::public_input); // mpt_proof_type = nonce_changed = 1
    // old_root = (old_root_hi, old_root_lo)
    instance_input.old_root = {var(0, public_input_index + 2, false, var::column_type::public_input), var(0, public_input_index + 3, false, var::column_type::public_input)}; 
    // new_root = (new_root_hi, new_root_lo)
    instance_input.new_root = {var(0, public_input_index + 4, false, var::column_type::public_input), var(0, public_input_index + 5, false, var::column_type::public_input)}; 
    // nonce = (old_nonce, new_nonce)
    instance_input.nonce    = {var(0, public_input_index + 6, false, var::column_type::public_input), var(0, public_input_index + 7, false, var::column_type::public_input)}; 
    // address_hash_traces = (direction[i], domain[i], old_h[i], new_h[i], s[i], is_open_padding[i], is_close_padding[i])
    public_input_index += 7; 
    for(std::size_t i = 0; i < account_trie_length; i++) {
        instance_input.address_hash_traces.push_back({var(0,  public_input_index + 1 + 7*i, false, var::column_type::public_input), 
                                                      var(0,  public_input_index + 2 + 7*i, false, var::column_type::public_input),
                                                      var(0,  public_input_index + 3 + 7*i, false, var::column_type::public_input),
                                                      var(0,  public_input_index + 4 + 7*i, false, var::column_type::public_input),
                                                      var(0,  public_input_index + 5 + 7*i, false, var::column_type::public_input),
                                                      var(0,  public_input_index + 6 + 7*i, false, var::column_type::public_input),
                                                      var(0,  public_input_index + 7 + 7*i, false, var::column_type::public_input)});
    }
    // leafs = (old_leaf, new_leaf) = [(old_h3, s3, 4), (new_h3, s3, 4)]
    public_input_index = public_input_index + 7*account_trie_length; 
    instance_input.leafs.push_back({var(0, public_input_index + 1, false, var::column_type::public_input), 
                                    var(0, public_input_index + 2, false, var::column_type::public_input), 
                                    var(0, public_input_index + 3, false, var::column_type::public_input)});
    instance_input.leafs.push_back({var(0, public_input_index + 4, false, var::column_type::public_input), 
                                    var(0, public_input_index + 5, false, var::column_type::public_input), 
                                    var(0, public_input_index + 6, false, var::column_type::public_input)});
    // old_account_hash_traces and new_account_hash_traces 
    public_input_index += 6; 
    for(std::size_t i = 0; i < 7; i++) {
        instance_input.old_account_hash_traces.push_back({var(0,   public_input_index + 1 + 3*i, false, var::column_type::public_input), 
                                                          var(0,   public_input_index + 2 + 3*i, false, var::column_type::public_input),
                                                          var(0,   public_input_index + 3 + 3*i, false, var::column_type::public_input)});
    }
    public_input_index = public_input_index + 3*7; 
    for(std::size_t i = 0; i < 7; i++) {
        instance_input.new_account_hash_traces.push_back({var(0,   public_input_index + 1 + 3*i, false, var::column_type::public_input), 
                                                          var(0,   public_input_index + 2 + 3*i, false, var::column_type::public_input),
                                                          var(0,   public_input_index + 3 + 3*i, false, var::column_type::public_input)});
    }
    // old_account = [old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
    // new_account = [new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
    public_input_index = public_input_index + 3*7; 
    for(std::size_t i = 0; i < 6; i++) {
        instance_input.old_account.push_back(var(0, public_input_index + 1 + i, false, var::column_type::public_input));
        instance_input.new_account.push_back(var(0, public_input_index + 7 + i, false, var::column_type::public_input));
    }
    public_input_index += 12; 
    instance_input.storage = var(0, public_input_index + 1, false, var::column_type::public_input);
    instance_input.account_key = var(0, public_input_index + 2, false, var::column_type::public_input);
    public_input_index += 2; 
    // instance_input.storage_hash_traces.push_back(var(0, public_input_index + 1, false, var::column_type::public_input));
    // instance_input.old_storage_key_value_hash_traces.push_back(var(0, public_input_index + 2, false, var::column_type::public_input));
    // instance_input.new_storage_key_value_hash_traces.push_back(var(0, public_input_index + 3, false, var::column_type::public_input));
    // public_input_index += 3; 

    integral_type B = integral_type(1) << bit_size_chunk; // the representation base
    value_type expected_res[num_chunks], carry[num_chunks];

    auto result_check = [&expected_res, &carry, &public_input](AssignmentType &assignment, typename component_type::result_type &real_res) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            // BOOST_ASSERT(var_value(assignment, real_res.z[i]) == expected_res[i]);
        }
        // BOOST_ASSERT(var_value(assignment, real_res.ck) == carry[num_chunks-1]);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input);
}



template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length, std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void mpt_nonce_changed_case_1_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;
    integral_type chunk_size = (integral_type(1) << bit_size_chunk);

    using policy = poseidon_policy<BlueprintFieldType, 128, /*Rate=*/ 4>;
    using hash_t = hashes::poseidon<policy>;   

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    std::random_device rd;
    std::mt19937_64 gen(rd());

    //random 160-bit integer for ethereum address
    using namespace boost::random;
    typedef independent_bits_engine<mt19937, 160, uint256_t> generator_type;
    generator_type gen_160;

    for (std::size_t test_count = 0; test_count < RandomTestsAmount; test_count++) {
        std::cout << "==================" << std::endl;  
        std::cout << "Example Number: " << test_count << std::endl;  
        std::cout << "==================" << std::endl;  

        std::cout << "\nInitialize the eth_account" << std::endl;  
        std::cout << "--------------------------" << std::endl;  
        
        std::cout << "account_trie_length = " << account_trie_length << std::endl;
        // ethereumAddress: first 160-bits of user's public key
        uint256_t ethAddress = gen_160();
        std::string address_string = boost::multiprecision::to_string(ethAddress);

        // convert strings to value_type
        nil::marshalling::status_type status;
        typedef typename boost::multiprecision::cpp_int_modular_backend<255> modular_backend_of_required_size;
        value_type eth_address = nil::marshalling::pack(ethAddress, status);
        std::cout << "eth_address = " << eth_address << std::endl;

        // account_key = Poseidon(eth_address)
        typename policy::digest_type account_key = hash<hash_t>(eth_address);        
        std::cout << "account_key = Poseidon(eth_address) = " << account_key << std::endl;

        // previous account: ethereumAccount = [old_nonce, balance, storage_root, keccak_code_hash, poseidon_code_hash, code_size]
        // updated account:  ethereumAccount = [new_nonce, balance, storage_root, keccak_code_hash, poseidon_code_hash, code_size]
        // where keccak_code_hash = (keccak_code_hash_hi, keccak_code_hash_lo)
        value_type old_nonce = value_type(gen());
        value_type new_nonce = value_type(gen());
        value_type code_size = value_type(gen());
        value_type storage_root = 0;  
        value_type balance = generate_random();
        uint64_t byte_code = gen();

        hashes::keccak_1600<256>::digest_type d = hash<hashes::keccak_1600<256>>(byte_code);
        integral_type n(d);
        std::cout << "d = " << d << std::endl;
        std::cout << "n_hi = " << (n >> 128) << std::endl;
        std::cout << "n_lo = " << (n & ((integral_type(1) << 128) - 1)) << std::endl;

        // keccak_code_hash = Keccak-256(byte_code)
        std::string Keccak_code_hash = hash<hashes::keccak_1600<256>>(byte_code);
        // poseidon_code_hash = Poseidon(byte_code)
        typename policy::digest_type poseidon_code_hash = hash<hash_t>(byte_code);

        std::cout << "ethereum_account = [ old_nonce = " << old_nonce << " <----> new_nonce = " << new_nonce << "," << std::endl;
        std::cout << "                     balance = " << balance << "," << std::endl;
        std::cout << "                     storage_root = " << storage_root << "," << std::endl;
        std::cout << "                     Keccak_code_hash = 0x" << Keccak_code_hash << "," << std::endl;
        std::cout << "                     poseidon_code_hash = " << poseidon_code_hash << "," << std::endl;
        std::cout << "                     code_size = " << code_size << " ]" << std::endl;

        // split Keccak_code_hash into two chunks of size 128-bits
        // Keccak_code_hash = (keccak_code_hash_hi, keccak_code_hash_lo)
        std::string keccak_str_hi = Keccak_code_hash.substr(0, Keccak_code_hash.size()-32);
        std::string keccak_str_lo = Keccak_code_hash.substr(Keccak_code_hash.size()-32, 32);
        value_type keccak_code_hash_hi;
        value_type keccak_code_hash_lo;
        for( std::size_t j = 0; j < keccak_str_hi.size(); j++ ){
            keccak_code_hash_hi *=16; keccak_code_hash_hi += keccak_str_hi[j] >= '0' && keccak_str_hi[j] <= '9'? keccak_str_hi[j] - '0' : keccak_str_hi[j] - 'a' + 10;
        }
        for( std::size_t j = 0; j < keccak_str_lo.size(); j++ ){
            keccak_code_hash_lo *=16; keccak_code_hash_lo += keccak_str_lo[j] >= '0' && keccak_str_lo[j] <= '9'? keccak_str_lo[j] - '0' : keccak_str_lo[j] - 'a' + 10;
        }
        std::cout << "keccak_code_hash = ( keccak_code_hash_hi = " << keccak_code_hash_hi << "," << std::endl;
        std::cout << "                     keccak_code_hash_lo = " << keccak_code_hash_lo << " )" << std::endl;

        // mpt_table = [eth_address, storage_key, mpt_proof_type, new_root, old_root, new_nonce, old_nonce, flag]
        std::cout << "\nInitialize the mpt_table" << std::endl;  
        std::cout << "------------------------" << std::endl;  

        // MPT proof type 1 corresponds to nonce_changed
        size_t mpt_proof_type = 1;

        // AccountLeaf4
        // keccak_code_hash_hi and keccak_code_hash_lo are used in the construction of the MPT
        // std::cout << "account_leaf_4: " << std::endl;
        // std::cout << "---------------" << std::endl;  
        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> keccak_code_hash = {keccak_code_hash_hi, keccak_code_hash_lo};
        // std::cout << "keccak_code_hash_hi = " << keccak_code_hash_hi << std::endl;
        // std::cout << "keccak_code_hash_lo = " << keccak_code_hash_lo << std::endl;

        // AccountLeaf3
        // std::cout << "account_leaf_3: " << std::endl;
        // std::cout << "---------------" << std::endl;  
        typename policy::digest_type old_h0 = hash<hash_t>({keccak_code_hash_hi, keccak_code_hash_lo});
        typename policy::digest_type new_h0 = hash<hash_t>({keccak_code_hash_hi, keccak_code_hash_lo});
        // std::cout << "old_h0 = Poseidon(keccak_code_hash_hi, keccak_code_hash_lo) = " << old_h0 << std::endl;
        // std::cout << "new_h0 = Poseidon(keccak_code_hash_hi, keccak_code_hash_lo) = " << new_h0 << std::endl;
        BOOST_ASSERT_MSG(old_h0 == new_h0, "!!!old_h0 not equal to new_h0!!!");

        // AccountLeaf2
        // std::cout << "account_leaf_2: " << std::endl;
        // std::cout << "---------------" << std::endl;  
        typename policy::digest_type old_h1 = hash<hash_t>({old_nonce*(integral_type(1) << 64) + code_size, balance});
        typename policy::digest_type new_h1 = hash<hash_t>({new_nonce*(integral_type(1) << 64) + code_size, balance});
        typename policy::digest_type s1 = hash<hash_t>({storage_root, old_h0});
        // std::cout << "old_h1 = Poseidon(old_nonce||code_size, balance) = " << old_h1 << std::endl;
        // std::cout << "new_h1 = Poseidon(new_nonce||code_size, balance) = " << new_h1 << std::endl;
        // std::cout << "s1 = Poseidon(storage_root, old_h0) = " << s1 << std::endl;

        // AccountLeaf1
        // std::cout << "account_leaf_1: " << std::endl;
        // std::cout << "---------------" << std::endl;  
        typename policy::digest_type old_h2 = hash<hash_t>({s1, old_h1});
        typename policy::digest_type new_h2 = hash<hash_t>({s1, new_h1});
        // std::cout << "old_h2 = Poseidon(s1, old_h1) = " << old_h2 << std::endl;
        // std::cout << "new_h2 = Poseidon(s1, new_h1) = " << new_h2 << std::endl;

        // AccountLeaf0
        // std::cout << "account_leaf_0: " << std::endl;
        // std::cout << "---------------" << std::endl;  
        typename policy::digest_type old_h3 = hash<hash_t>({old_h2, poseidon_code_hash});
        typename policy::digest_type new_h3 = hash<hash_t>({new_h2, poseidon_code_hash});
        typename policy::digest_type s3 = hash<hash_t>({value_type(1), account_key});
        // std::cout << "old_h3 = Poseidon(old_h2, poseidon_code_hash) = " << old_h3 << std::endl;
        // std::cout << "new_h3 = Poseidon(new_h2, poseidon_code_hash) = " << new_h3 << std::endl;
        // std::cout << "s3 = Poseidon(1, acount_key) = " << s3 << std::endl;

        // AccountTrie
        // std::cout << "account_trie: " << std::endl;
        // std::cout << "-------------" << std::endl;  
        value_type old_h[account_trie_length], new_h[account_trie_length], s[account_trie_length]; 
        value_type old_child, new_child, sibling, old_hash, new_hash;   
        old_child = old_h3; new_child = new_h3; sibling = s3;
        for (int i = 0; i < account_trie_length; i++) {
            typename policy::digest_type old_hash = hash<hash_t>({sibling, old_child});
            typename policy::digest_type new_hash = hash<hash_t>({sibling, new_child});
            old_h[i] = old_hash; new_h[i] = new_hash; s[i] = generate_random();
            old_child = old_hash; new_child = new_hash; sibling = s[i];
            // std::cout << "old_h[" << i << "] = " << old_h[i] << std::endl;
            // std::cout << "new_h[" << i << "] = " << new_h[i] << std::endl;
            // std::cout << "s[" << i << "] = " << s[i] << std::endl;
            // std::cout << "-------" << std::endl;
        } 

        // std::cout << "old_h[account_trie_length] = " << old_h[account_trie_length - 1] << std::endl;

        std::ostringstream string_s, string_old_h, string_new_h;
        string_s << s[account_trie_length - 1];
        string_old_h << old_h[account_trie_length - 1];
        string_new_h << new_h[account_trie_length - 1];     

        std::string old_root_input = string_s.str() + string_old_h.str();
        std::string new_root_input = string_s.str() + string_new_h.str();

        // std::cout << "old_root_input = " << old_root_input << std::endl;
        // std::cout << "new_root_input = " << new_root_input << std::endl;

        std::string old_state_root = hash<hashes::keccak_1600<256>>(old_root_input);
        std::string new_state_root = hash<hashes::keccak_1600<256>>(new_root_input);

        // std::cout << "old_state_root = " << old_state_root << std::endl;
        // std::cout << "new_state_root = " << new_state_root << std::endl;

        // split old_root into two chunks of size 128-bits
        // old_root = (old_root_hi, old_root_lo)
        std::string old_root_str_hi = old_state_root.substr(0, old_state_root.size()-32);
        std::string old_root_str_lo = old_state_root.substr(old_state_root.size()-32, 32);
        value_type old_root_hi;
        value_type old_root_lo;
        for( std::size_t j = 0; j < old_root_str_hi.size(); j++ ){
            old_root_hi *=16; old_root_hi += old_root_str_hi[j] >= '0' && old_root_str_hi[j] <= '9'? old_root_str_hi[j] - '0' : old_root_str_hi[j] - 'a' + 10;
        }
        for( std::size_t j = 0; j < old_root_str_lo.size(); j++ ){
            old_root_lo *=16; old_root_lo += old_root_str_lo[j] >= '0' && old_root_str_lo[j] <= '9'? old_root_str_lo[j] - '0' : old_root_str_lo[j] - 'a' + 10;
        }
        // std::cout << "old_root_hi = " << old_root_hi << std::endl;
        // std::cout << "old_root_lo = " << old_root_lo << std::endl;

        // split new_root into two chunks of size 128-bits
        // new_root = (new_root_hi, new_root_lo)
        std::string new_root_str_hi = new_state_root.substr(0, new_state_root.size()-32);
        std::string new_root_str_lo = new_state_root.substr(new_state_root.size()-32, 32);
        value_type new_root_hi;
        value_type new_root_lo;
        for( std::size_t j = 0; j < new_root_str_hi.size(); j++ ){
            new_root_hi *=16; new_root_hi += new_root_str_hi[j] >= '0' && new_root_str_hi[j] <= '9'? new_root_str_hi[j] - '0' : new_root_str_hi[j] - 'a' + 10;
        }
        for( std::size_t j = 0; j < new_root_str_lo.size(); j++ ){
            new_root_lo *=16; new_root_lo += new_root_str_lo[j] >= '0' && new_root_str_lo[j] <= '9'? new_root_str_lo[j] - '0' : new_root_str_lo[j] - 'a' + 10;
        }
        // std::cout << "new_root_hi = " << new_root_hi << std::endl;
        // std::cout << "new_root_lo = " << new_root_lo << std::endl;

        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> old_root = {old_root_hi, old_root_lo};    
        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> new_root = {new_root_hi, new_root_lo};

        std::cout << "mpt_table = [ eth_address = " << eth_address << "," << std::endl;
        std::cout << "              storage_key = " << 0 << "," << std::endl;
        std::cout << "              mpt_proof_type = " << mpt_proof_type << "," << std::endl;
        std::cout << "              new_root = ( 0x" << new_root_str_hi << ", 0x" << new_root_str_lo << " ), " << std::endl;
        std::cout << "              old_root = ( 0x" << old_root_str_hi << ", 0x" << old_root_str_lo << " ), " << std::endl;
        std::cout << "              new_nonce = " << new_nonce << "," << std::endl;
        std::cout << "              old_nonce = " << old_nonce << " ]" << std::endl;

        // constructing the trace 
        // trace = [eth_address, account_key, old_root, new_root, old_leaf, new_leaf, old_account_path, new_account_path, old_account_update, new_account_update, storage_root
        //          old_state_path, new_state_path, old_state_update, new_state_update, state_key]
        // std::cout << "\nConstruct the trace which represents the MPT update" << std::endl;  
        // std::cout << "---------------------------------------------------" << std::endl;  
        // each leaf is of the form [leaf_value, sibling_value, node_type] 
        // leaf node type: node_type = 4
        std::vector<typename BlueprintFieldType::value_type> old_leaf = {old_h3, s3, 4};
        std::vector<typename BlueprintFieldType::value_type> new_leaf = {new_h3, s3, 4};

        BOOST_ASSERT_MSG(old_leaf[1] == new_leaf[1], "!!!Leaf siblings are not equal!!!");
        BOOST_ASSERT_MSG(old_leaf[2] == new_leaf[2], "!!!Leaf node type is not the same!!!");

        // construction of old_account_path and new_account_path
        std::vector<std::vector<typename BlueprintFieldType::value_type>> old_account_path = {};
        std::vector<std::vector<typename BlueprintFieldType::value_type>> new_account_path = {};
        for (int i = 0; i < account_trie_length; i++) {
            old_account_path.push_back({old_h[account_trie_length - 1 - i], s[account_trie_length - 1 - i], value_type(6)});
            new_account_path.push_back({new_h[account_trie_length - 1 - i], s[account_trie_length - 1 - i], value_type(6)});
        }

        size_t old_path_length = old_account_path.size();
        size_t new_path_length = new_account_path.size();
        BOOST_ASSERT_MSG(old_account_path.size() == new_account_path.size(), "!!!old_path/new_path DO NOT have the same length!!!");

        // std::cout << "old_path_length = " << old_path_length << std::endl;
        // std::cout << "new_path_length = " << new_path_length << std::endl;

        for (int i = 0; i < account_trie_length; i++) {
            BOOST_ASSERT_MSG(old_account_path[i][1] == new_account_path[i][1], "!!!Sibling nodes are not equal in old_path/new_path!!!");
            BOOST_ASSERT_MSG(old_account_path[i][2] == new_account_path[i][2], "!!!Node types are not equal in old_path/new_path!!!");
        } 

        // old_path_part and new_path_part show the direction from root to leaf in the two paths
        integral_type key_integral = integral_type(account_key.data);
        std::vector<typename BlueprintFieldType::value_type> old_path_part = {};
        std::vector<typename BlueprintFieldType::value_type> new_path_part = {};

        for (std::size_t i = 0; i < account_trie_length; i++) {
            old_path_part.push_back(value_type(key_integral % 2));
            key_integral = key_integral >> 1;
        }
        new_path_part = old_path_part;

        // old_account_update = [old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
        // new_account_update = [new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
        std::vector<typename BlueprintFieldType::value_type> old_account_update = {old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size};
        std::vector<typename BlueprintFieldType::value_type> new_account_update = {new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size};

        // common_state_root
        value_type common_state_root = storage_root;

        // construction of old_state_path and new_state_path (NULL in this case)
        std::vector<std::vector<typename BlueprintFieldType::value_type>> old_state_path = {};
        std::vector<std::vector<typename BlueprintFieldType::value_type>> new_state_path = {};

        BOOST_ASSERT_MSG(old_state_path.empty() == new_state_path.empty(), "!!!old_state_path/new_state_path NOT both null!!!");

        size_t old_state_path_length = old_state_path.size();
        size_t new_state_path_length = new_state_path.size();

        // std::cout << "old_state_path_length = " << old_state_path_length << std::endl;
        // std::cout << "new_state_path_length = " << new_state_path_length << std::endl;
        // std::cout << "empty old_state_path test = " << old_state_path.empty() << std::endl;
        // std::cout << "empty new_state_path test = " << new_state_path.empty() << std::endl;

        // construct the proof
        // proof = [claim, address_hash_traces, leafs, old_account_hash_traces, new_account_hash_traces, old_account, new_account, storage, account_key
        //          storage_hash_traces, old_storage_key_value_hash_traces, new_storage_key_value_hash_traces]
        // where claim = (old_root, new_root, nonce, claim_kind) s.t. nonce = (old_nonce, new_nonce) and claim_kind = (eth_account, mpt_proof_type)
        // std::cout << "\nConstruct the proof which will be used to create the assignment table" << std::endl;  
        // std::cout << "---------------------------------------------------------------------" << std::endl;  

        // claim 
        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> nonce = {old_account_update[0], new_account_update[0]};
        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> claim_kind = {eth_address, mpt_proof_type};
        std::vector<std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>> claim = {old_root, new_root, nonce, claim_kind};

        BOOST_ASSERT(old_account_update[0] == old_nonce);
        BOOST_ASSERT(new_account_update[0] == new_nonce);

        // address_hash_traces 
        std::vector<typename BlueprintFieldType::value_type> direction = old_path_part;
        std::vector<typename BlueprintFieldType::value_type> domain = {};
        for (std::size_t i = 0; i < account_trie_length; i++) {
            domain.push_back(0);
        } 
        std::vector<std::vector<typename BlueprintFieldType::value_type>> address_hash_traces = {};
        for (std::size_t i = 0; i < account_trie_length; i++) {
            address_hash_traces.push_back({direction[i], domain[i], old_account_path[i][0], new_account_path[i][0], old_account_path[i][1], 0, 0});
        } 

        // leafs
        std::vector<std::vector<typename BlueprintFieldType::value_type>> leafs = {old_leaf, new_leaf}; 

        // old_account_hash_traces
        typename policy::digest_type h1_old = hash<hash_t>({old_account_update[2], old_account_update[3]});
        typename policy::digest_type h2_old = hash<hash_t>({common_state_root, h1_old});
        typename policy::digest_type h3_old = hash<hash_t>({old_account_update[0]*(integral_type(1) << 64) + old_account_update[5], old_account_update[1]});
        typename policy::digest_type h4_old = hash<hash_t>({h2_old, h3_old});
        typename policy::digest_type h5_old = hash<hash_t>({value_type(1), account_key});
        typename policy::digest_type h6_old = hash<hash_t>({h4_old, old_account_update[4]});
        typename policy::digest_type h7_old = hash<hash_t>({h5_old, h6_old});

        BOOST_ASSERT(h1_old == old_h0);
        BOOST_ASSERT(h2_old == s1);
        BOOST_ASSERT(h3_old == old_h1);
        BOOST_ASSERT(h4_old == old_h2);
        BOOST_ASSERT(h5_old == s3);
        BOOST_ASSERT(h6_old == old_h3);
        BOOST_ASSERT(h7_old == old_h[0]);
    
        std::vector<std::vector<typename BlueprintFieldType::value_type>> old_account_hash_traces = {};
        old_account_hash_traces.push_back({old_account_update[2], old_account_update[3], h1_old});
        old_account_hash_traces.push_back({h1_old, common_state_root, h2_old});
        old_account_hash_traces.push_back({old_account_update[0]*(integral_type(1) << 64) + old_account_update[5], old_account_update[1], h3_old});
        old_account_hash_traces.push_back({h3_old, h2_old, h4_old});
        old_account_hash_traces.push_back({1, account_key, h5_old});
        old_account_hash_traces.push_back({h4_old, old_account_update[4], h6_old});
        old_account_hash_traces.push_back({h5_old, h6_old, h7_old});

        // new_account_hash_traces
        typename policy::digest_type h1_new = hash<hash_t>({new_account_update[2], new_account_update[3]});
        typename policy::digest_type h2_new = hash<hash_t>({common_state_root, h1_new});
        typename policy::digest_type h3_new = hash<hash_t>({new_account_update[0]*(integral_type(1) << 64) + new_account_update[5], new_account_update[1]});
        typename policy::digest_type h4_new = hash<hash_t>({h2_new, h3_new});
        typename policy::digest_type h5_new = hash<hash_t>({value_type(1), account_key});
        typename policy::digest_type h6_new = hash<hash_t>({h4_new, new_account_update[4]});
        typename policy::digest_type h7_new = hash<hash_t>({h5_new, h6_new});

        BOOST_ASSERT(h1_new == new_h0);
        BOOST_ASSERT(h2_new == s1);
        BOOST_ASSERT(h3_new == new_h1);
        BOOST_ASSERT(h4_new == new_h2);
        BOOST_ASSERT(h5_new == s3);
        BOOST_ASSERT(h6_new == new_h3);
        BOOST_ASSERT(h7_new == new_h[0]);
        
        std::vector<std::vector<typename BlueprintFieldType::value_type>> new_account_hash_traces = {};
        new_account_hash_traces.push_back({new_account_update[2], new_account_update[3], h1_new});
        new_account_hash_traces.push_back({h1_new, common_state_root, h2_new});
        new_account_hash_traces.push_back({new_account_update[0]*(integral_type(1) << 64) + new_account_update[5], new_account_update[1], h3_new});
        new_account_hash_traces.push_back({h3_new, h2_new, h4_new});
        new_account_hash_traces.push_back({1, account_key, h5_new});
        new_account_hash_traces.push_back({h4_new, new_account_update[4], h6_new});
        new_account_hash_traces.push_back({h5_new, h6_new, h7_new});

        BOOST_ASSERT(h1_new == h1_old);
        BOOST_ASSERT(h2_new == h2_old);
        BOOST_ASSERT(h5_new == h5_old);

        // old_account, new_account
        std::vector<typename BlueprintFieldType::value_type> old_account = old_account_update;
        std::vector<typename BlueprintFieldType::value_type> new_account = new_account_update;

        // storage
        value_type storage = common_state_root;

        // account_key
        typename policy::digest_type key = hash<hash_t>({claim[3].first});
        BOOST_ASSERT(key == account_key);

        // storage_hash_traces: NULL vector
        std::vector<std::vector<typename BlueprintFieldType::value_type>> storage_hash_traces = {};

        // old_storage_key_value_hash_traces: NULL vector
        std::vector<std::vector<typename BlueprintFieldType::value_type>> old_storage_key_value_hash_traces = {};
        // new_storage_key_value_hash_traces: NULL vector
        std::vector<std::vector<typename BlueprintFieldType::value_type>> new_storage_key_value_hash_traces = {};

        // fill in public_input
        std::vector<typename BlueprintFieldType::value_type> public_input = {};
        for (std::size_t i = 0; i < claim.size(); i++) {
            public_input.push_back(claim[(3 + i) % 4].first);
            public_input.push_back(claim[(3 + i) % 4].second);
        }
        for (std::size_t i = 0; i < account_trie_length; i++) {
            for (std::size_t j = 0; j < address_hash_traces[i].size(); j++) {
                public_input.push_back(address_hash_traces[i][j]);
            }
        } 
        for (std::size_t i = 0; i < 2; i++) {
            for (std::size_t j = 0; j < 3; j++) {
                public_input.push_back(leafs[i][j]);
            }
        }
        for (std::size_t i = 0; i < old_account_hash_traces.size(); i++) {
            for (std::size_t j = 0; j < old_account_hash_traces[i].size(); j++) {
                public_input.push_back(old_account_hash_traces[i][j]);
            }
        }        
        for (std::size_t i = 0; i < new_account_hash_traces.size(); i++) {
            for (std::size_t j = 0; j < new_account_hash_traces[i].size(); j++) {
                public_input.push_back(new_account_hash_traces[i][j]);
            }
        }
        for (std::size_t i = 0; i < old_account.size(); i++) {
            public_input.push_back(old_account[i]);
        }
        for (std::size_t i = 0; i < new_account.size(); i++) {
            public_input.push_back(new_account[i]);
        }
        public_input.push_back(storage);
        public_input.push_back(key);
        // if (storage_hash_traces.empty() == 1){
        //     public_input.push_back(0);
        //     public_input.push_back(0);
        //     public_input.push_back(0);
        // }
        // else{
        //     for (std::size_t i = 0; i < storage_hash_traces.size(); i++) {
        //         for (std::size_t j = 0; j < storage_hash_traces[i].size(); j++) {
        //             public_input.push_back(storage_hash_traces[i][j]);
        //         }
        //     } 
        //     for (std::size_t i = 0; i < old_storage_key_value_hash_traces.size(); i++) {
        //         for (std::size_t j = 0; j < old_storage_key_value_hash_traces[i].size(); j++) {
        //             public_input.push_back(old_storage_key_value_hash_traces[i][j]);
        //         }
        //     }        
        //     for (std::size_t i = 0; i < new_storage_key_value_hash_traces.size(); i++) {
        //         for (std::size_t j = 0; j < new_storage_key_value_hash_traces[i].size(); j++) {
        //             public_input.push_back(new_storage_key_value_hash_traces[i][j]);
        //         }
        //     }     
        // }

        // Verifying correctness of public_input construction
        BOOST_ASSERT(public_input[0] == eth_address); BOOST_ASSERT(public_input[1] == mpt_proof_type);
        BOOST_ASSERT(public_input[2] == old_root_hi); BOOST_ASSERT(public_input[3] == old_root_lo); 
        BOOST_ASSERT(public_input[4] == new_root_hi); BOOST_ASSERT(public_input[5] == new_root_lo);
        BOOST_ASSERT(public_input[6] == old_nonce);   BOOST_ASSERT(public_input[7] == new_nonce);
        for (std::size_t i = 0; i < account_trie_length; i++) {
            BOOST_ASSERT(public_input[8 + i*7] == direction[i]);
            BOOST_ASSERT(public_input[9 + i*7] == domain[i]);
            BOOST_ASSERT(public_input[10 + i*7] == old_h[account_trie_length - 1 - i]);
            BOOST_ASSERT(public_input[11 + i*7] == new_h[account_trie_length - 1 - i]);
            BOOST_ASSERT(public_input[12 + i*7] == s[account_trie_length - 1 - i]);
            BOOST_ASSERT(public_input[13 + i*7] == 0);
            BOOST_ASSERT(public_input[14 + i*7] == 0);
        }
        BOOST_ASSERT(public_input[15 + (account_trie_length - 1)*7] == old_h3);
        BOOST_ASSERT(public_input[16 + (account_trie_length - 1)*7] == s3);
        BOOST_ASSERT(public_input[17 + (account_trie_length - 1)*7] == 4);
        BOOST_ASSERT(public_input[18 + (account_trie_length - 1)*7] == new_h3);
        BOOST_ASSERT(public_input[19 + (account_trie_length - 1)*7] == s3);
        BOOST_ASSERT(public_input[20 + (account_trie_length - 1)*7] == 4);
        size_t index = 20 + (account_trie_length - 1)*7;
        BOOST_ASSERT(public_input[index + 1] == keccak_code_hash_hi);
        BOOST_ASSERT(public_input[index + 2] == keccak_code_hash_lo);
        BOOST_ASSERT(public_input[index + 3] == old_h0);
        BOOST_ASSERT(public_input[index + 4] == old_h0);
        BOOST_ASSERT(public_input[index + 5] == storage_root);
        BOOST_ASSERT(public_input[index + 6] == s1);
        BOOST_ASSERT(public_input[index + 7] == old_nonce*(integral_type(1) << 64) + code_size);
        BOOST_ASSERT(public_input[index + 8] == balance);
        BOOST_ASSERT(public_input[index + 9] == old_h1);
        BOOST_ASSERT(public_input[index + 10] == old_h1);
        BOOST_ASSERT(public_input[index + 11] == s1);
        BOOST_ASSERT(public_input[index + 12] == old_h2);
        BOOST_ASSERT(public_input[index + 13] == 1);
        BOOST_ASSERT(public_input[index + 14] == account_key);
        BOOST_ASSERT(public_input[index + 15] == s3);
        BOOST_ASSERT(public_input[index + 16] == old_h2);
        BOOST_ASSERT(public_input[index + 17] == poseidon_code_hash);
        BOOST_ASSERT(public_input[index + 18] == old_h3);
        BOOST_ASSERT(public_input[index + 19] == s3);
        BOOST_ASSERT(public_input[index + 20] == old_h3);
        BOOST_ASSERT(public_input[index + 21] == old_h[0]);
        index += 21; 
        BOOST_ASSERT(public_input[index + 1] == keccak_code_hash_hi);
        BOOST_ASSERT(public_input[index + 2] == keccak_code_hash_lo);
        BOOST_ASSERT(public_input[index + 3] == new_h0);
        BOOST_ASSERT(public_input[index + 4] == new_h0);
        BOOST_ASSERT(public_input[index + 5] == storage_root);
        BOOST_ASSERT(public_input[index + 6] == s1);
        BOOST_ASSERT(public_input[index + 7] == new_nonce*(integral_type(1) << 64) + code_size);
        BOOST_ASSERT(public_input[index + 8] == balance);
        BOOST_ASSERT(public_input[index + 9] == new_h1);
        BOOST_ASSERT(public_input[index + 10] == new_h1);
        BOOST_ASSERT(public_input[index + 11] == s1);
        BOOST_ASSERT(public_input[index + 12] == new_h2);
        BOOST_ASSERT(public_input[index + 13] == 1);
        BOOST_ASSERT(public_input[index + 14] == account_key);
        BOOST_ASSERT(public_input[index + 15] == s3);
        BOOST_ASSERT(public_input[index + 16] == new_h2);
        BOOST_ASSERT(public_input[index + 17] == poseidon_code_hash);
        BOOST_ASSERT(public_input[index + 18] == new_h3);
        BOOST_ASSERT(public_input[index + 19] == s3);
        BOOST_ASSERT(public_input[index + 20] == new_h3);
        BOOST_ASSERT(public_input[index + 21] == new_h[0]);
        index += 21; 
        BOOST_ASSERT(public_input[index + 1] == old_nonce);
        BOOST_ASSERT(public_input[index + 2] == balance);
        BOOST_ASSERT(public_input[index + 3] == keccak_code_hash_hi);
        BOOST_ASSERT(public_input[index + 4] == keccak_code_hash_lo);
        BOOST_ASSERT(public_input[index + 5] == poseidon_code_hash);
        BOOST_ASSERT(public_input[index + 6] == code_size);
        index += 6; 
        BOOST_ASSERT(public_input[index + 1] == new_nonce);
        BOOST_ASSERT(public_input[index + 2] == balance);
        BOOST_ASSERT(public_input[index + 3] == keccak_code_hash_hi);
        BOOST_ASSERT(public_input[index + 4] == keccak_code_hash_lo);
        BOOST_ASSERT(public_input[index + 5] == poseidon_code_hash);
        BOOST_ASSERT(public_input[index + 6] == code_size);
        index += 6;
        BOOST_ASSERT(public_input[index + 1] == storage_root);
        BOOST_ASSERT(public_input[index + 2] == account_key);
        index += 2;
        // index += 3;
        BOOST_ASSERT(public_input.size() == index + 1);

        std::cout << "#public_input = " << public_input.size() << std::endl;

        test_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length,WitnessColumns>(public_input);
        std::cout << "\n" << std::endl;
    }
}

constexpr static const std::size_t random_tests_amount = 20;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test) {
    using bls12_381_field_type = typename crypto3::algebra::curves::bls12<381>::scalar_field_type;
    using bn_254_field_type = nil::crypto3::algebra::fields::alt_bn128_scalar_field<254>;

    std::cout << "*** Case 1: BLS12-381 scalar field\n";
    mpt_nonce_changed_case_1_tests<bls12_381_field_type, 4, 16, 12, 30, random_tests_amount>();

    std::cout << "*** Case 2: BN-254 scalar field\n";
    mpt_nonce_changed_case_1_tests<bn_254_field_type, 4, 16, 1, 30, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()