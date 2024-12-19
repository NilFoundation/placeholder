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
                            
#define BOOST_TEST_MODULE blueprint_plonk_bbf_mpt_nonce_changed_test

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
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/hardhat_input_generator.hpp>
#include <nil/blueprint/zkevm_bbf/mpt/mpt_verifier.hpp>

#include "../test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::crypto3::hashes::detail;

class MPTTestFixture: public BBFTestFixture {
public:
    MPTTestFixture():BBFTestFixture(){}

    template <typename field_type>
    void test_mpt_nonce_changed(std::vector<typename field_type::value_type> proof, std::size_t account_trie_length, std::size_t max_mpt){
        typename nil::blueprint::bbf::mpt_verifier<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type mpt_nonce_changed_assignment_input;
        typename nil::blueprint::bbf::mpt_verifier<field_type, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type mpt_nonce_changed_constraint_input;

        mpt_nonce_changed_assignment_input.proof = proof;

        bool result = test_bbf_component<field_type, nil::blueprint::bbf::mpt_verifier>(
            "MPT",
            {},                        //  Public input
            mpt_nonce_changed_assignment_input,  //  Assignment input
            mpt_nonce_changed_constraint_input,  //  Circuit input
            max_mpt,                             //  Sizes
            account_trie_length                  
        );
        BOOST_CHECK(result); // Max_rw, Max_mpt
    }

    template <typename field_type, std::size_t account_trie_length, std::size_t RandomTestsAmount>
    void mpt_nonce_changed_case_1_tests(){
        using integral_type = typename field_type::integral_type;
        using value_type = typename field_type::value_type;

        using policy = poseidon_policy<field_type, 128, /*Rate=*/ 4>;
        using hash_t = hashes::poseidon<policy>;   

        // nil::crypto3::random::algebraic_engine<field_type> generate_random;
        // boost::random::mt19937 seed_seq;
        // generate_random.seed(seed_seq);

        static boost::random::mt19937 seed_seq;
        static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);
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
            std::cout << "ethAddress = " << ethAddress << std::endl;
            std::string address_string = boost::multiprecision::to_string(ethAddress);
            std::cout << "address_string = " << address_string << std::endl;

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

            // keccak_code_hash = Keccak-256(byte_code)
            hashes::keccak_1600<256>::digest_type Keccak_code_hash = hash<hashes::keccak_1600<256>>(byte_code);
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
            integral_type n(Keccak_code_hash);
            value_type keccak_code_hash_hi = value_type(n >> 128);  
            value_type keccak_code_hash_lo = value_type((n & ((integral_type(1) << 128) - 1)));
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
            std::pair<typename field_type::value_type, typename field_type::value_type> keccak_code_hash = {keccak_code_hash_hi, keccak_code_hash_lo};
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

            std::cout << "old_root_input = " << old_root_input << std::endl;
            std::cout << "new_root_input = " << new_root_input << std::endl;

            hashes::keccak_1600<256>::digest_type old_state_root = hash<hashes::keccak_1600<256>>(old_root_input);
            hashes::keccak_1600<256>::digest_type new_state_root = hash<hashes::keccak_1600<256>>(new_root_input);
            std::cout << "old_state_root = " << old_state_root << std::endl;
            std::cout << "new_state_root = " << new_state_root << std::endl;

            // split new_root into two chunks of size 128-bits
            // old_root = (old_root_hi, old_root_lo)
            integral_type n1(old_state_root);
            value_type old_root_hi = value_type(n1 >> 128);  
            value_type old_root_lo = value_type((n1 & ((integral_type(1) << 128) - 1)));
            std::cout << "old_root_hi = " << old_root_hi << std::endl;
            std::cout << "old_root_lo = " << old_root_lo << std::endl;    

            // split new_root into two chunks of size 128-bits
            // new_root = (new_root_hi, new_root_lo)        
            integral_type n2(new_state_root);
            value_type new_root_hi = value_type(n2 >> 128);  
            value_type new_root_lo = value_type((n2 & ((integral_type(1) << 128) - 1)));
            std::cout << "new_root_hi = " << new_root_hi << std::endl;
            std::cout << "new_root_lo = " << new_root_lo << std::endl; 

            std::string old_root_string = to_string(old_state_root);
            std::string old_root_str_hi = old_root_string.substr(0, old_root_string.size()-32);
            std::string old_root_str_lo = old_root_string.substr(old_root_string.size()-32, 32);

            std::string new_root_string = to_string(new_state_root);
            std::string new_root_str_hi = new_root_string.substr(0, new_root_string.size()-32);
            std::string new_root_str_lo = new_root_string.substr(new_root_string.size()-32, 32);

            std::pair<typename field_type::value_type, typename field_type::value_type> old_root = {old_root_hi, old_root_lo};    
            std::pair<typename field_type::value_type, typename field_type::value_type> new_root = {new_root_hi, new_root_lo};

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
            std::vector<typename field_type::value_type> old_leaf = {old_h3, s3, 4};
            std::vector<typename field_type::value_type> new_leaf = {new_h3, s3, 4};

            BOOST_ASSERT_MSG(old_leaf[1] == new_leaf[1], "!!!Leaf siblings are not equal!!!");
            BOOST_ASSERT_MSG(old_leaf[2] == new_leaf[2], "!!!Leaf node type is not the same!!!");

            // construction of old_account_path and new_account_path
            std::vector<std::vector<typename field_type::value_type>> old_account_path = {};
            std::vector<std::vector<typename field_type::value_type>> new_account_path = {};
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
            std::vector<typename field_type::value_type> old_path_part = {};
            std::vector<typename field_type::value_type> new_path_part = {};

            for (std::size_t i = 0; i < account_trie_length; i++) {
                old_path_part.push_back(value_type(key_integral % 2));
                key_integral = key_integral >> 1;
            }
            new_path_part = old_path_part;

            // old_account_update = [old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
            // new_account_update = [new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
            std::vector<typename field_type::value_type> old_account_update = {old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size};
            std::vector<typename field_type::value_type> new_account_update = {new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size};

            // common_state_root
            value_type common_state_root = storage_root;

            // construction of old_state_path and new_state_path (NULL in this case)
            std::vector<std::vector<typename field_type::value_type>> old_state_path = {};
            std::vector<std::vector<typename field_type::value_type>> new_state_path = {};

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
            std::pair<typename field_type::value_type, typename field_type::value_type> nonce = {old_account_update[0], new_account_update[0]};
            std::pair<typename field_type::value_type, typename field_type::value_type> claim_kind = {eth_address, mpt_proof_type};
            std::vector<std::pair<typename field_type::value_type, typename field_type::value_type>> claim = {old_root, new_root, nonce, claim_kind};

            BOOST_ASSERT(old_account_update[0] == old_nonce);
            BOOST_ASSERT(new_account_update[0] == new_nonce);

            // address_hash_traces 
            std::vector<typename field_type::value_type> direction = old_path_part;
            std::vector<typename field_type::value_type> domain = {};
            for (std::size_t i = 0; i < account_trie_length; i++) {
                domain.push_back(0);
            } 
            std::vector<std::vector<typename field_type::value_type>> address_hash_traces = {};
            for (std::size_t i = 0; i < account_trie_length; i++) {
                address_hash_traces.push_back({direction[i], domain[i], old_account_path[i][0], new_account_path[i][0], old_account_path[i][1], 0, 0});
            } 

            // leafs
            std::vector<std::vector<typename field_type::value_type>> leafs = {old_leaf, new_leaf}; 

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

            std::vector<std::vector<typename field_type::value_type>> old_account_hash_traces = {};
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
            
            std::vector<std::vector<typename field_type::value_type>> new_account_hash_traces = {};
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
            std::vector<typename field_type::value_type> old_account = old_account_update;
            std::vector<typename field_type::value_type> new_account = new_account_update;

            // storage
            value_type storage = common_state_root;

            // account_key
            typename policy::digest_type key = hash<hash_t>({claim[3].first});
            BOOST_ASSERT(key == account_key);

            // storage_hash_traces: NULL vector
            std::vector<std::vector<typename field_type::value_type>> storage_hash_traces = {};

            // old_storage_key_value_hash_traces: NULL vector
            std::vector<std::vector<typename field_type::value_type>> old_storage_key_value_hash_traces = {};
            // new_storage_key_value_hash_traces: NULL vector
            std::vector<std::vector<typename field_type::value_type>> new_storage_key_value_hash_traces = {};

            // fill in MPT circuit input: proof
            std::vector<typename field_type::value_type> proof;
            for (std::size_t i = 0; i < claim.size(); i++) {
                proof.push_back(claim[(3 + i) % 4].first);
                proof.push_back(claim[(3 + i) % 4].second);
            }
            for (std::size_t i = 0; i < account_trie_length; i++) {
                for (std::size_t j = 0; j < address_hash_traces[i].size(); j++) {
                    proof.push_back(address_hash_traces[i][j]);
                }
            } 
            for (std::size_t i = 0; i < 2; i++) {
                for (std::size_t j = 0; j < 3; j++) {
                    proof.push_back(leafs[i][j]);
                }
            }
            for (std::size_t i = 0; i < old_account_hash_traces.size(); i++) {
                for (std::size_t j = 0; j < old_account_hash_traces[i].size(); j++) {
                    proof.push_back(old_account_hash_traces[i][j]);
                }
            }  
            for (std::size_t i = 0; i < new_account_hash_traces.size(); i++) {
                for (std::size_t j = 0; j < new_account_hash_traces[i].size(); j++) {
                    proof.push_back(new_account_hash_traces[i][j]);
                }
            }
            for (std::size_t i = 0; i < old_account.size(); i++) {
                proof.push_back(old_account[i]);
            }
            for (std::size_t i = 0; i < new_account.size(); i++) {
                proof.push_back(new_account[i]);
            }
            proof.push_back(storage);
            proof.push_back(key);

            // Verifying correctness of proof construction
            BOOST_ASSERT(proof[0] == eth_address); BOOST_ASSERT(proof[1] == mpt_proof_type);
            BOOST_ASSERT(proof[2] == old_root_hi); BOOST_ASSERT(proof[3] == old_root_lo); 
            BOOST_ASSERT(proof[4] == new_root_hi); BOOST_ASSERT(proof[5] == new_root_lo);
            BOOST_ASSERT(proof[6] == old_nonce);   BOOST_ASSERT(proof[7] == new_nonce);
            for (std::size_t i = 0; i < account_trie_length; i++) {
                BOOST_ASSERT(proof[8 + i*7] == direction[i]);
                BOOST_ASSERT(proof[9 + i*7] == domain[i]);
                BOOST_ASSERT(proof[10 + i*7] == old_h[account_trie_length - 1 - i]);
                BOOST_ASSERT(proof[11 + i*7] == new_h[account_trie_length - 1 - i]);
                BOOST_ASSERT(proof[12 + i*7] == s[account_trie_length - 1 - i]);
                BOOST_ASSERT(proof[13 + i*7] == 0);
                BOOST_ASSERT(proof[14 + i*7] == 0);
            }
            BOOST_ASSERT(proof[15 + (account_trie_length - 1)*7] == old_h3);
            BOOST_ASSERT(proof[16 + (account_trie_length - 1)*7] == s3);
            BOOST_ASSERT(proof[17 + (account_trie_length - 1)*7] == 4);
            BOOST_ASSERT(proof[18 + (account_trie_length - 1)*7] == new_h3);
            BOOST_ASSERT(proof[19 + (account_trie_length - 1)*7] == s3);
            BOOST_ASSERT(proof[20 + (account_trie_length - 1)*7] == 4);
            size_t index = 20 + (account_trie_length - 1)*7;
            BOOST_ASSERT(proof[index + 1] == keccak_code_hash_hi);
            BOOST_ASSERT(proof[index + 2] == keccak_code_hash_lo);
            BOOST_ASSERT(proof[index + 3] == old_h0);
            BOOST_ASSERT(proof[index + 4] == old_h0);
            BOOST_ASSERT(proof[index + 5] == storage_root);
            BOOST_ASSERT(proof[index + 6] == s1);
            BOOST_ASSERT(proof[index + 7] == old_nonce*(integral_type(1) << 64) + code_size);
            BOOST_ASSERT(proof[index + 8] == balance);
            BOOST_ASSERT(proof[index + 9] == old_h1);
            BOOST_ASSERT(proof[index + 10] == old_h1);
            BOOST_ASSERT(proof[index + 11] == s1);
            BOOST_ASSERT(proof[index + 12] == old_h2);
            BOOST_ASSERT(proof[index + 13] == 1);
            BOOST_ASSERT(proof[index + 14] == account_key);
            BOOST_ASSERT(proof[index + 15] == s3);
            BOOST_ASSERT(proof[index + 16] == old_h2);
            BOOST_ASSERT(proof[index + 17] == poseidon_code_hash);
            BOOST_ASSERT(proof[index + 18] == old_h3);
            BOOST_ASSERT(proof[index + 19] == s3);
            BOOST_ASSERT(proof[index + 20] == old_h3);
            BOOST_ASSERT(proof[index + 21] == old_h[0]);
            index += 21; 
            BOOST_ASSERT(proof[index + 1] == keccak_code_hash_hi);
            BOOST_ASSERT(proof[index + 2] == keccak_code_hash_lo);
            BOOST_ASSERT(proof[index + 3] == new_h0);
            BOOST_ASSERT(proof[index + 4] == new_h0);
            BOOST_ASSERT(proof[index + 5] == storage_root);
            BOOST_ASSERT(proof[index + 6] == s1);
            BOOST_ASSERT(proof[index + 7] == new_nonce*(integral_type(1) << 64) + code_size);
            BOOST_ASSERT(proof[index + 8] == balance);
            BOOST_ASSERT(proof[index + 9] == new_h1);
            BOOST_ASSERT(proof[index + 10] == new_h1);
            BOOST_ASSERT(proof[index + 11] == s1);
            BOOST_ASSERT(proof[index + 12] == new_h2);
            BOOST_ASSERT(proof[index + 13] == 1);
            BOOST_ASSERT(proof[index + 14] == account_key);
            BOOST_ASSERT(proof[index + 15] == s3);
            BOOST_ASSERT(proof[index + 16] == new_h2);
            BOOST_ASSERT(proof[index + 17] == poseidon_code_hash);
            BOOST_ASSERT(proof[index + 18] == new_h3);
            BOOST_ASSERT(proof[index + 19] == s3);
            BOOST_ASSERT(proof[index + 20] == new_h3);
            BOOST_ASSERT(proof[index + 21] == new_h[0]);
            index += 21; 
            BOOST_ASSERT(proof[index + 1] == old_nonce);
            BOOST_ASSERT(proof[index + 2] == balance);
            BOOST_ASSERT(proof[index + 3] == keccak_code_hash_hi);
            BOOST_ASSERT(proof[index + 4] == keccak_code_hash_lo);
            BOOST_ASSERT(proof[index + 5] == poseidon_code_hash);
            BOOST_ASSERT(proof[index + 6] == code_size);
            index += 6; 
            BOOST_ASSERT(proof[index + 1] == new_nonce);
            BOOST_ASSERT(proof[index + 2] == balance);
            BOOST_ASSERT(proof[index + 3] == keccak_code_hash_hi);
            BOOST_ASSERT(proof[index + 4] == keccak_code_hash_lo);
            BOOST_ASSERT(proof[index + 5] == poseidon_code_hash);
            BOOST_ASSERT(proof[index + 6] == code_size);
            index += 6;
            BOOST_ASSERT(proof[index + 1] == storage_root);
            BOOST_ASSERT(proof[index + 2] == account_key);
            index += 2;
            // index += 3;
            BOOST_ASSERT(proof.size() == index + 1);

            std::cout << "#proof = " << proof.size() << std::endl;

            test_mpt_nonce_changed<field_type>(proof, account_trie_length, 100);

            std::cout << "\n" << std::endl;
        }

        // integral_type base16 = integral_type(1) << 16;
        // auto random_input = value_type(integral_type(generate_random().data) % base16);

        // std::vector<typename field_type::value_type> public_input = {};

        // for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        //     std::cout << "random_input = " << random_input << std::endl;
        //     for (std::size_t j = 0; j < 20; j++) {
        //         public_input.push_back(random_input);
        //     }
        //     test_mpt_nonce_changed<field_type>(public_input, 100);
        // }
        // std::cout << "\n" << std::endl;
    }
};

static const std::size_t random_tests_amount = 10;

BOOST_FIXTURE_TEST_SUITE(blueprint_plonk_test_suite, MPTTestFixture)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_mpt_nonce_changed_test) {
    using pallas_field_type = typename algebra::curves::pallas::base_field_type;
    using bn_254_field_type = nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;

    // std::cout << "*** Case 1: Pallas base field\n";
    // mpt_nonce_changed_case_1_tests<pallas_field_type, 70, random_tests_amount>();

    std::cout << "*** Case 2: BN-254 scalar field\n";
    mpt_nonce_changed_case_1_tests<bn_254_field_type, 70, random_tests_amount>();
    mpt_nonce_changed_case_1_tests<bn_254_field_type, 1, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()