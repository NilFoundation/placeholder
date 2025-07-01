//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2025 Georgios Fotiadis <gfotiadis@nil.foundation>
// Copyright (c) 2025 Amirhossein Khajehpour <a.khajepour@nil.foundation>
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

#include <nil/blueprint/zkevm_bbf/types/mpt_trie.hpp>

namespace nil::blueprint::bbf {

template<typename FieldType, GenerationStage stage>
class mpt_extension : public generic_component<FieldType, stage> {
    using typename generic_component<FieldType, stage>::context_type;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

/*
    using private_input = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_node, std::nullptr_t>::type;

    struct mpt_node_input_type {
        TYPE node_type;
        std::array<TYPE,32> node_key_prefix;
        TYPE key_prefix_length;
        private_input node_data;
    };
*/
    using input_type = mpt_node_input_type<FieldType, stage>;

    using value_type = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

/*
    // will probably be never used
    static table_params get_minimal_requirements() {
        return {
            .witnesses = 850,
            .public_inputs = 0,
            .constants = 0,
            .rows = 1
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input) {}
*/

    static std::size_t get_witness_amount(){
        return 294;
    }

    std::array<TYPE,32> parent_hash;
    std::array<TYPE, 32> ext_value;  // ext_value[32]

    std::array<TYPE, 32> child_accumulated_key;
    TYPE child_nibble_present;
    TYPE child_last_nibble;

    mpt_extension(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        TYPE key_length_bytes;
        TYPE node_length;
        std::array<TYPE, 32> key_part;   // key_part[32]

        TYPE value_length_bytes = 32; // instead of allocating we use it as a constant for now
        TYPE node_num_of_bytes = 1; // node_num_of_bytes: number of bytes that compose the size of node = 1 or 2. Always 1 for extensions?

        TYPE key_length_inverse; // the inverse of key_length, if exists
        TYPE node_length_inverse; // the inverse of node_length, if exists

        TYPE rlc_value_node_prefix;
        std::array<TYPE, 32> rlc_key;
        std::array<TYPE, 32> rlc_value;
        std::array<TYPE, 32> rlc_key_new;

        // cells for computing the accumulated key
        std::array<TYPE,32> key_part_lower;   // the lower 4 bits of each key_part byte
        std::array<TYPE,32> shifted_key_part; // key_part >> 4
        TYPE key_part_length;
        TYPE key_part_length_is_odd;
        TYPE key_part_length_half;
        // auxiliary cells for defining I(x) = 1 iff x == key_part_length_half
        // I(x) = I1(x / 8) * I2(x % 8)
        std::array<TYPE, 4> kplh_indic_1 = {0,0,0,0};     // I1 indicator function for key_part_length_half
        std::array<TYPE, 8> kplh_indic_2 = {0,0,0,0,0,0,0,0}; // I2 indicator function for key_part_length_half

        std::array<TYPE, 5> rlc_indic_1 = {0,0,0,0,0};     // I1 indicator function for key_part_length_half
        std::array<TYPE, 8> rlc_indic_2 = {0,0,0,0,0,0,0,0}; // I2 indicator function for key_part_length_half
        // ====

        std::size_t node_key_bytes;

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            mpt_node n = input.node_data;

            std::vector<uint8_t> hash_input;
            std::size_t node_key_length = n.len.at(0);
            node_key_bytes = ceil(node_key_length/2);

            // different indicators for RLC key
            BOOST_ASSERT_MSG(node_key_length <= 64, "Extension node key part can't be more than 32 bytes!");
            rlc_indic_1[(node_key_length / 2) / 8] = 1;
            rlc_indic_2[(node_key_length / 2) % 8] = 1;

            key_length_bytes = node_key_bytes;

            std::array<uint8_t,32> key_value = w_to_8(n.value.at(0));
            std::array<uint8_t,32> shifted_key_value = w_to_8(n.value.at(0) >> 4);
            std::vector<uint8_t> byte_vector;
            size_t rlp_prefix; // RLP for the key in extension node

            for(std::size_t i = (32 - node_key_bytes); i < 32; i++) {
                byte_vector.push_back(key_value[i]);
            }

            if (node_key_bytes != 1) { // if size of key is not 1-byte, RLP is (128 + size of key)
                rlp_prefix = 128 + node_key_bytes;
                byte_vector.emplace(byte_vector.begin(), rlp_prefix);
            } else { // if size of key is 1-byte, there is no RLP prefix
                rlp_prefix = 0;
            }

            hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );

            auto k0 = n.value.at(0) >> 4*(node_key_length - 1);
            BOOST_ASSERT_MSG(k0 == 1 || k0 == 0, "k0 is wrong in extension node!");
            if (k0 == 1) {
                node_key_length--; // then we only skip the first hex symbol
            } else if (k0 == 0) {
                node_key_length -= 2; // otherwise, the second hex is 0 and we skip it too
            }
            key_part_length = node_key_length; // now store it in a cell for further use
            key_part_length_is_odd = node_key_length % 2;
            key_part_length_half = node_key_length / 2;

            kplh_indic_1[(node_key_length / 2) / 8] = 1;
            kplh_indic_2[(node_key_length / 2) % 8] = 1;

            size_t rlp_node_prefix0, rlp_node_prefix1; // RLP prefixes for the whole node (2-bytes)
            std::array<uint8_t,32> node_value = w_to_8(n.value.at(1));

            std::vector<uint8_t> value_byte_vector(node_value.begin(), node_value.end());
            rlp_prefix = 128 + 32; // value in ext node is a hash, so always 32-bytes, hence RLP = 0xa0
            value_byte_vector.emplace(value_byte_vector.begin(), rlp_prefix);
            hash_input.insert( hash_input.end(), value_byte_vector.begin(), value_byte_vector.end() );
            std::size_t total_value_length = hash_input.size(); // size of value to be hashed: rlp_key||key||rlp_value||value

            // here...
            // TODO this must be fixed
            // BOOST_ASSERT_MSG(total_value_length <= 55, "Current implementation is underconstrained for extension nodes with length more than 55 bytes!");
            if (total_value_length <= 55) {
                rlp_node_prefix0 = 192 + total_value_length;
                node_length = total_value_length;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            } else {
                rlp_node_prefix1 = node_key_bytes + 34;
                rlp_node_prefix0 = 247 + 1;
                node_length = total_value_length;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            }

            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
            input.keccak_buffers->new_buffer({hash_input, hash_value});

            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
            for(std::size_t i = 0; i < 32; i++) {
                parent_hash[i] = hash_value_byte[i];
            }

            for(std::size_t i = 0; i < 32; i++) {
                key_part[i] = key_value[i];
                key_part_lower[i] = key_value[i] & 0xF;
                shifted_key_part[i] = shifted_key_value[i];
                ext_value[i] = node_value[i];
            }

            // std::cout << "[" << std::endl;
            // for(auto &v : n.value) {
            //     std::cout << "    value = " << std::hex << v << std::dec << std::endl;
            // }
            // std::cout << "]" << std::endl;
        }

        // NB: parent_hash allocations should precede everything else according to mpt_dynamic structure
        for(std::size_t i = 0; i < 32; i++) {
            allocate(parent_hash[i]);
        }
        allocate(key_length_bytes);
        lookup(key_length_bytes, "chunk_16_bits/8bits");
        allocate(value_length_bytes);
        allocate(node_length);
        lookup(node_length, "chunk_16_bits/8bits");
        for(std::size_t i = 0; i < 32; i++) {
            allocate(key_part[i]);
        }
        for(std::size_t i = 0; i < 32; i++) {
            allocate(key_part_lower[i]);
        }
        for(std::size_t i = 0; i < 32; i++) {
            allocate(shifted_key_part[i]);
            // per-byte constraints of the relation: shifted_key_part * 16 + key_part_lower[31] = key_part
            constrain(shifted_key_part[i] * 16 + key_part_lower[i]
                       - (( i > 0 ? key_part_lower[i-1] : 0 ) * 256 + key_part[i]));
        }
        allocate(key_part_length); // 6-bit
        allocate(key_part_length_is_odd);
        allocate(key_part_length_half); // 5-bit
        constrain(key_part_length_is_odd * (1 - key_part_length_is_odd));
        constrain(2 * key_part_length_half + key_part_length_is_odd - key_part_length);

        child_nibble_present = input.node_nibble_present * (1 - key_part_length_is_odd) +
                               (1 - input.node_nibble_present) * key_part_length_is_odd;
        allocate(child_nibble_present);
        child_last_nibble = key_part_lower[31] * child_nibble_present;
        allocate(child_last_nibble);

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            BOOST_LOG_TRIVIAL(trace) << "nibbles_present " << input.node_nibble_present << " " << key_part_length_is_odd << std::endl;
        }
        std::stringstream ss;
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            ss << "\nkey_part:\n";
            for(std::size_t i = 0; i < 32; i++) {
                ss << std::hex << key_part[i] << std::dec << " ";
            }
            
            ss << "\nnode_accum:\n";
            for(std::size_t i = 0; i < 32; i++) {
                ss << std::hex << input.node_accumulated_key[i] << std::dec << " ";
            }
            ss << "\nshifted:\n";
            for(std::size_t i = 0; i < 32; i++) {
                ss << std::hex << shifted_key_part[i] << std::dec << " ";
            }
            ss << key_part_lower[31];
            
            
            BOOST_LOG_TRIVIAL(trace) << ss.str();
        }
        TYPE indic1_sum;
        TYPE indic1_value;
        for(std::size_t i = 0; i < 4; i++) {
            allocate(kplh_indic_1[i]);
            constrain( kplh_indic_1[i] * (1 - kplh_indic_1[i]), "length selector dimentions must be binary!" );
            indic1_sum += kplh_indic_1[i];
            indic1_value += kplh_indic_1[i] * i;
        }
        constrain(indic1_sum - 1, "length selector dimension one!" );

        TYPE indic2_sum;
        TYPE indic2_value;
        for(std::size_t i = 0; i < 8; i++) {
            allocate(kplh_indic_2[i]);
            constrain(kplh_indic_2[i] * (1 - kplh_indic_2[i]), "length selector dimentions must be binary!" );
            indic2_sum += kplh_indic_2[i];
            indic2_value += kplh_indic_2[i] * i;
        }
        constrain(indic2_sum - 1, "length selector dimension two!" );
        constrain( indic1_value * 8 + indic2_value - key_part_length_half );

        TYPE rlc_indi1_sum;
        TYPE rlc_indic1_value;
        for(std::size_t i = 0; i < 5; i++) {
            allocate(rlc_indic_1[i]);
            constrain( rlc_indic_1[i] * (1 - rlc_indic_1[i]) );
            rlc_indi1_sum += rlc_indic_1[i];
            rlc_indic1_value += rlc_indic_1[i] * i;
        }
        constrain(1 - rlc_indi1_sum);

        TYPE rlc_indic2_sum;
        TYPE rlc_indic2_value;
        for(std::size_t i = 0; i < 8; i++) {
            allocate(rlc_indic_2[i]);
            constrain(rlc_indic_2[i] * (1 - rlc_indic_2[i]) );
            rlc_indic2_sum += rlc_indic_2[i];
            rlc_indic2_value += rlc_indic_2[i] * i;
        }
        constrain( 1 - rlc_indic2_sum);
        constrain( rlc_indic1_value * 8 + rlc_indic2_value - key_length_bytes );
        constrain(rlc_indic_2[4] * (1 - rlc_indic_1[0])); // length can be at most 32

        // different possible values for key_part_length_half
        for(std::size_t l = 0; l < 32; l++) {
            TYPE selector = kplh_indic_1[l / 8] * kplh_indic_2[l % 8]; // selector == 1  <=>  key_part_length_half == l
            // k0 and k1 related constraints:
            constrain(selector * key_part_length_is_odd * (shifted_key_part[31 - l] - 1), "if nibble exist k0 must be 1");
            constrain(selector * (1 - key_part_length_is_odd) * key_part[32 - l - 1], "if nibble doesn't exist k0 and k1 are 0");

            for(std::size_t i = 0; i < 32; i++) {
                // parent share of the final child_accumulated_key:
                    // there is no extra byte in the end
                    if (i <= 31 - l) {
                        child_accumulated_key[i] += selector * 
                            (1 - input.node_nibble_present * key_part_length_is_odd) * 
                            input.node_accumulated_key[i + l];
                    }
                    if (i == 32 - l) {
                        // only parent has an extra nibble
                        child_accumulated_key[i] += selector * 
                            input.node_nibble_present * (1 - key_part_length_is_odd) * 
                            (input.node_last_nibble * 0x10 + shifted_key_part[32 - l]);
                        
                        // only key_part has an extra nibble
                        child_accumulated_key[i] += selector *
                            (1 - input.node_nibble_present) * key_part_length_is_odd *
                            (l >= 1 ? shifted_key_part[32 - l]: child_last_nibble);

                        // none of them has an extra nibble
                        child_accumulated_key[i] += selector *
                            (1 - input.node_nibble_present) * (1 - key_part_length_is_odd) *
                            key_part[32 - l];
                    }
                    // there is an extra byte in the end
                    if (l < 31 && i < 31 - l) {
                        // both parent and key_part have the extra nibble
                        child_accumulated_key[i] += selector * 
                            input.node_nibble_present * key_part_length_is_odd * 
                            input.node_accumulated_key[i + l + 1];
                    }
                    if (i == 31 - l) {
                        // both parent and key_part have the extra nibble
                        child_accumulated_key[i] += selector * 
                            input.node_nibble_present * key_part_length_is_odd * 
                            (input.node_last_nibble * 0x10 + key_part[31 - l] - 0x10);
                    }
                // key_part share of the final child_accumulated_key
                    // there was no extra byte in the end
                    if (i > 32 - l) {
                        // one of them has an extra nibble
                        child_accumulated_key[i] += selector * 
                            ((1 - input.node_nibble_present) * key_part_length_is_odd + input.node_nibble_present * (1 - key_part_length_is_odd)) *
                            shifted_key_part[i];
                        // none has extra nibble
                        child_accumulated_key[i] += selector * 
                            ((1 - input.node_nibble_present) * (1 - key_part_length_is_odd)) *
                            key_part[i];
                    }
                    // there was an extra byte in the end
                    if (i > 31 - l) {
                        // both parent and key_part have the extra nibble
                        child_accumulated_key[i] += selector * 
                            input.node_nibble_present * key_part_length_is_odd * 
                            key_part[i];
                    }
            }
            // std::cout << std::endl;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                if (selector == 1)
                    BOOST_LOG_TRIVIAL(trace) << "length: " << l << std::endl;
            }
        }
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            BOOST_LOG_TRIVIAL(trace) << "\nchild_accumulated_key:\n";
            std::stringstream ss;
            for (size_t i = 0; i < child_accumulated_key.size(); i++)
                ss << std::hex << child_accumulated_key[i] << std::dec << " ";
            BOOST_LOG_TRIVIAL(trace) << ss.str() << "\n";
        }
        for(std::size_t i = 0; i < 32; i++) {
            allocate(child_accumulated_key[i]);
        }

        for(std::size_t i = 0; i < 32; i++) {
            allocate(ext_value[i]);
        }

        TYPE rlp_key_prefix;
        TYPE rlp_value_prefix = 128 + value_length_bytes;
        std::array<TYPE, 2> rlp_node; // rlp_node prefix for an extension node fits into 2 values

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            key_length_inverse = (key_length_bytes == 1) ? 0 : key_length_bytes.inversed();
            node_length_inverse = (node_length < 55) ? 0 : node_length.inversed();
        }
        allocate(key_length_inverse);
        TYPE key_length_is_one_byte = 1 - key_length_bytes * key_length_inverse;
        constrain(key_length_bytes * key_length_is_one_byte * (1 - key_length_bytes * key_length_is_one_byte));
        rlp_key_prefix = (1 - key_length_is_one_byte) * (128 + key_length_bytes);

        allocate(node_length_inverse);
        TYPE node_length_less_than_55 = 1 - node_length * node_length_inverse;
        constrain(node_length * node_length_less_than_55 * (node_length - node_length * node_length_less_than_55));

        rlp_node[0] = 192 + node_length_less_than_55 * node_length + (1 - node_length_less_than_55) * 56;
        rlp_node[1] = (1 - node_length_less_than_55) * node_length;

        constrain(rlp_key_prefix - ( (1 - key_length_is_one_byte) * (128 + key_length_bytes) ));
        constrain(rlp_node[1] - ( (1 - node_length_less_than_55) * node_length ));
        constrain(rlp_node[0] - ( 192 + node_length_less_than_55 * node_length + (1 - node_length_less_than_55) * 56 ));
        constrain((192 + node_length - rlp_node[0]) * (247 + node_num_of_bytes - rlp_node[0]) );
        constrain(node_length - (1 - key_length_is_one_byte) - key_length_bytes - (value_length_bytes + 1));

        // RLC value computation
        TYPE RLC = input.rlc_challenge;

        // total length of hashed sequence = node_length + (1 or 2, depending on node_length_less_than_55)
        rlc_value_node_prefix = node_length + 2 - node_length_less_than_55;

        // RLP node prefix
        // the first byte of RLP node prefix is always present
        rlc_value_node_prefix *= RLC;
        rlc_value_node_prefix += rlp_node[0];
        // std::cout << "rlc_value_node_prefix = " << rlc_value_node_prefix << std::endl;

        // the second byte is optional
        rlc_value_node_prefix *= node_length_less_than_55 + (1 - node_length_less_than_55)*RLC;
        rlc_value_node_prefix += (1 - node_length_less_than_55) * rlp_node[1];
        allocate(rlc_value_node_prefix); 

        TYPE rlc_key_prefix, rlc_value_prefix; // non-allocated expressions for RLC of the RLP child prefix

        rlc_key_prefix = rlc_value_node_prefix;
        rlc_key_prefix *= key_length_is_one_byte + (1 - key_length_is_one_byte) * RLC;
        rlc_key_prefix += rlp_key_prefix;
        allocate(rlc_key_prefix); 

        for(std::size_t l = 1; l <= 32; l++) {
            TYPE selector = rlc_indic_1[l / 8] * rlc_indic_2[l % 8]; // selector == 1  <=>  node_key_length == l (bytes)
            TYPE rlc_prev = rlc_key_prefix;
            for(std::size_t b = 0; b < 32; b++) {
                rlc_key[b] += (rlc_prev * selector);
                if (b >= 32 - l) {
                    rlc_key[b] *= RLC * selector + (1 - selector);
                    rlc_key[b] += key_part[b] * selector;
                    rlc_prev *= RLC * selector + (1 - selector);
                    rlc_prev += key_part[b] * selector;
                }
            }            
        }
        for(std::size_t b = 0; b < 32; b++) { 
            allocate(rlc_key[b]);
        }   

        rlc_value_prefix = rlc_key[31];
        rlc_value_prefix *= RLC;
        rlc_value_prefix += rlp_value_prefix;
        allocate(rlc_value_prefix); 

        // we store only _one_ RLC for each _pair_ of bytes in a child hash
        // loop through pairs of bytes
        for(std::size_t b = 0; b < 32; b++) { 
            rlc_value[b] = (b == 0) ? rlc_value_prefix : rlc_value[b-1];
            rlc_value[b] *= RLC;
            rlc_value[b] += ext_value[b]; // first byte in pair
            allocate(rlc_value[b]);
        }

        TYPE rlc_result = rlc_value[31] ;

        BOOST_LOG_TRIVIAL(trace) << "rlc_result = " << rlc_result << std::endl;

        // zkevm_word_type power_of_2 = zkevm_word_type(1) << (31 * 8);
        auto keccak_tuple = chunks8_to_chunks16<TYPE>(parent_hash);
        keccak_tuple.emplace(keccak_tuple.begin(), rlc_result);
        lookup(keccak_tuple, "keccak_table");
    }
};
} // namespace nil::blueprint::bbf
