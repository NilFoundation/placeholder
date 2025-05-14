//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// #include <nil/blueprint/zkevm_bbf/subcomponents/child_hash_table.hpp>

#include <nil/blueprint/zkevm_bbf/types/mpt_trie.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_branch.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_extension.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_subtree.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_leaf.hpp>

namespace nil::blueprint::bbf {

template<typename FieldType, GenerationStage stage>
class mpt_dynamic : public generic_component<FieldType, stage> {
    using typename generic_component<FieldType, stage>::context_type;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

    using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_paths_vector, std::nullptr_t>::type;

    using value_type = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

    static const std::size_t max_mpt_columns = 900;

    static table_params get_minimal_requirements(std::size_t max_mpt_size) {
        return {
            .witnesses = max_mpt_columns,
            .public_inputs = 0,
            .constants = 0,
            .rows = max_mpt_size
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_mpt_size) {}

    mpt_dynamic(context_type &context_object,
        const input_type &input,
        std::size_t max_mpt_size) : generic_component<FieldType,stage>(context_object) {

        // listed by order of allocation into the table
        std::vector<TYPE> trie_id(max_mpt_size);                         // The id's of the tries (to store all tries in the same table)
        std::vector<std::array<TYPE, NODE_TYPE_COUNT>> node_selector(max_mpt_size); // node type selector columns (0/1)
        std::vector<std::array<TYPE,32>> node_key_prefix(max_mpt_size);  // The part of the key that is the path to the node in the row

        // columns for proving that the key prefix has indeed length = key_prefix_length
        std::size_t column_skip = 8; // skip the columns for proving correct prefix length
        std::vector<std::array<TYPE,6>> key_prefix_length_bit(max_mpt_size); // bitwise decomposition of key_prefix_length < 64
        std::vector<TYPE> high_byte_lo(max_mpt_size);      // highest byte in key_prefix, low 4-bits
        std::vector<TYPE> high_byte_hi(max_mpt_size);      // highest byte in key_prefix, high 4-bits
        std::vector<TYPE> key_prefix_length(max_mpt_size); // Length of the prefix in half-bytes (i.e. 4-bit chunks)

        //                                                    /======= Excluded from key_to_hash lookup table ======\
        // +---------+------------------+--------------------+-------------------------+--------------+--------------+-------------------+
        // | trie_id | node_selector(~3)| node_key_prefix(32)| key_prefix_length_bit(6)| high_byte_lo | high_byte_hi | key_prefix_length |
        // +---------+------------------+--------------------+-------------------------+--------------+--------------+-------------------+

        // All other columns are delegated to node-specific subcomponents. For them we'll create subcontexts.
        std::vector<std::size_t> subcontext_columns;
        for(std::size_t i = 1 + NODE_TYPE_COUNT + 33 + column_skip; i < max_mpt_columns; i++) {
            subcontext_columns.push_back(i);
        }

        // Connections between rows are achieved via lookups. For this we define a "key_to_hash" table:
        std::vector<std::size_t> k2h_lookup_columns = {0}; // trie_id column included
        for(std::size_t i = 0; i < 32; i++) {
            // skip NODE_TYPE_COUNT columns, add following 32 node_key_prefix cols into the table
            k2h_lookup_columns.push_back(1 + NODE_TYPE_COUNT + i);
        }
        k2h_lookup_columns.push_back(1 + NODE_TYPE_COUNT + column_skip); // key_prefix_length column included
        // 32 more columns: hash for use in parent node
        for(std::size_t i = 0; i < 32; i++) {
            k2h_lookup_columns.push_back(1 + NODE_TYPE_COUNT + 32 + column_skip + 1 + i);
        }
        lookup_table("key_to_hash", k2h_lookup_columns, 0, max_mpt_size);

        // Now prepare a list of nodes to be processed (compatible with both assignment and constraints stages)
        // For the assignment stage we convert a list of paths into a unified list of nodes,
        // appending the additional "subtree" nodes.
        std::unordered_map<mpt_node_id, mpt_node> deploy_plan;

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
           for(auto &p : input) { // enumerate paths
               std::size_t trie_id = 0; // TODO : adjust later
               zkevm_word_type path_key;
               std::size_t accumulated_length = 0;

               std::cout << "slot number = " << std::hex << p.slotNumber << std::dec << std::endl;
               std::array<uint8_t,32> slotNumber = w_to_8(p.slotNumber);
               std::vector<uint8_t> buffer(slotNumber.begin(), slotNumber.end());
               path_key = nil::blueprint::zkevm_keccak_hash(buffer);
               std::cout << "path key = " << std::hex << path_key << std::dec << std::endl;

               zkevm_word_type key_suffix = path_key;
               zkevm_word_type accumulated_key = path_key;
               for(auto &n : p.proof) {
                   std::cout << "\nnode type = " << n.type << std::endl;

                   // determine the node key prefix, depending on the node type
                   std::size_t node_key_length = 0;     // size of key in each node (bytes)- for branch = 1

                   if (n.type != branch) { // extension or leaf
                       zkevm_word_type first_value = n.value.at(0);
                       node_key_length = n.len.at(0);

                       zkevm_word_type k0 = n.value.at(0) >> 4*(node_key_length - 1);
                       if ((k0 == 1) || (k0 == 3)) {
                           node_key_length--; // then we only skip the first hex symbol
                       } else {
                           node_key_length -= 2; // otherwise, the second hex is 0 and we skip it too
                       }
                   } else {
                       node_key_length = 1;
                   }

                   zkevm_word_type node_key_before_accum = path_key >> 4*(64 - accumulated_length);

                   mpt_node_id n_id = { trie_id, node_key_before_accum, accumulated_length };
                   if (deploy_plan.find(n_id) != deploy_plan.end()) {
                       // TODO process node _replacement_
                       std::cout << "We have a replacement" << std::endl;
                   } else {
                       deploy_plan[n_id] = n;
                   }

                   if (n.type == branch) {
                       // create subtree nodes
                       std::cout << "Branch node requires planning subtrees" << std::endl;
                       std::size_t followed_branch_key = static_cast<std::size_t>((path_key << 4*accumulated_length) >> 4*63);
                       for(std::size_t i = 0; i < 16; i++) {
                           if (i != followed_branch_key) {
                               zkevm_word_type subtree_prefix = node_key_before_accum * 16 + i;
                               zkevm_word_type parent_hash = n.value.at(i);

                               mpt_node_id subtree_node_id = { trie_id, subtree_prefix, accumulated_length + 1 };
                               mpt_node subtree_node = { subtree, {parent_hash}, {static_cast<std::size_t>(parent_hash.is_zero() ? 0 : 64)}};

                               std::unordered_map<mpt_node_id, mpt_node>::const_iterator preexisting = deploy_plan.find(subtree_node_id);
                               if (preexisting != deploy_plan.end()) {
                                   // normally we shouldn't be doing anything, but for a subtree we can check consistency
                                   if (preexisting->second.type == subtree) {
                                       BOOST_ASSERT(preexisting->second.value.at(0) == subtree_node.value.at(0) &&
                                                    preexisting->second.len.at(0) == subtree_node.len.at(0));
                                   }
                               } else {
                                   deploy_plan[subtree_node_id] = subtree_node;
                               }
                           }
                       }
                   }
                   accumulated_length += node_key_length; // for the next node
                }
           }
        } else {
           mpt_node_id n_id = {0, 0, 0};
           for(std::size_t virtual_node = 0; virtual_node < NODE_TYPE_COUNT; virtual_node++) {
               n_id.key_prefix_length = virtual_node; // just smth to ensure all node ids are different
               deploy_plan[n_id] = mpt_node({mpt_node_type(virtual_node), {0}, {0}});
           }
        }
        // at this point deploy_plan contains all the information we need

        // Some bit-decompositions we'll need in the process. Computed here to save time.
        std::array<std::array<TYPE,6>,32> J;
        for(std::size_t i = 0; i < 32; i++) {
            std::size_t to_decompose = 2*(31-i);
            for(std::size_t l = 0; l < 6; l++) {
                J[i][l] = to_decompose & 1;
                to_decompose >>= 1;
            }
        }

        // the main cycle (Assignments & constraints)
        std::size_t node_num = 0; // = row number, since we have 1 row per node
        for(auto nr : deploy_plan) {
            mpt_node_id n_id = nr.first;
            mpt_node n = nr.second;
            std::cout << "\nnode " << node_num << " type = " << n.type << std::endl;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::array<std::uint8_t,32> node_key_prefix_byte = w_to_8(n_id.key_prefix);
                for(std::size_t i = 0; i < 32; i++) {
                    node_key_prefix[node_num][i] = node_key_prefix_byte[i];
                }
                std::size_t length_to_decompose = n_id.key_prefix_length;
                for(std::size_t i = 0; i < 6; i++) {
                    key_prefix_length_bit[node_num][i] = length_to_decompose & 1;
                    length_to_decompose >>= 1;
                }

                trie_id[node_num] = n_id.trie_id;
                // TODO : is this necessary? They are probably 0-initialized anyway.
                for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                    node_selector[node_num][type_index] = 0;
                }
                node_selector[node_num][n.type] = 1; // put a 1 into the selector column that corresponds to our node type
            } // end Assignment-specific code

            allocate(trie_id[node_num], 0, node_num);
            for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                allocate(node_selector[node_num][type_index], 1 + type_index, node_num);
            }
            for(std::size_t i = 0; i < 32; i++) {
                allocate(node_key_prefix[node_num][i], 1 + NODE_TYPE_COUNT + i, node_num);
            }
            for(std::size_t i = 0; i < 6; i++) {
                allocate(key_prefix_length_bit[node_num][i], 1 + NODE_TYPE_COUNT + 32 + i, node_num);
                constrain(key_prefix_length_bit[node_num][i] * (key_prefix_length_bit[node_num][i] - 1));
                // recompose key_prefix_length from its bits
                key_prefix_length[node_num] += key_prefix_length_bit[node_num][i] * (1 << i);
            }

            // Constraints that assure key_prefix_length is consistent:
            // bytes with numbers 0,..., 31 - [key_prefix_length / 2] should be zero.
            // j = 31 - i > [key_prefix_length / 2]   =>   node_key_prefix[i] = 0
            // key_prefix_length % 2 = 0, j = [key_prefix_length / 2]   =>   node_key_prefix[i] = 0
            // (key_prefix_length % 2 = 0) = (1 - b[0])
            //
            // key_prefix_length_bit[1],...,key_prefix_length_bit[5] = b[1],..,b[5] are the bit decomposition of [key_prefix_length/2]
            // Let j[1],..,j[5] be the bit decomposition of j = 31 - i
            // Expression to multiply node_key_prefix[i] by:
            // (j[5] > b[5]) V (j[5] = b[5]) * ( (j[4] > b[4]) V (j[4] = b[4]) *
            //                               * ( ....  ((j[1] > b[1]) V (j[1] = b[1])*(1-b[0]) )...))
            //
            // we use the decompositions stored in the array J, see definition before the cycle; j[l] = J[i][l]

            TYPE highest_byte; // expression for the highest non-zero byte in node_key_prefix
            for(std::size_t i = 0; i < 32; i++) {
                TYPE expr = 1 - key_prefix_length_bit[node_num][0];
                TYPE highest_byte_selector = TYPE(1);
                for(std::size_t l = 1; l < 6; l++) { // Note, that we start from 1, not 0
                    // (j[l] == b[l]):
                    // j[l] = 0: (j[l] == b[l]) = (1 - b[l])
                    // j[l] = 1: (j[l] == b[l]) = b[l]
                    //
                    // (j[l] > b[l]):
                    // j[l] = 0: (j[l] > b[l]) = 0
                    // j[l] = 1: (j[l] > b[l]) = (b[l] == 0) = (1 - b[l])
                    //
                    expr *= (J[i][l] == 0) ? (1 - key_prefix_length_bit[node_num][l]) : key_prefix_length_bit[node_num][l];
                    expr += (J[i][l] == 0) ? 0 : (1 - key_prefix_length_bit[node_num][l]);

                    highest_byte_selector *= (J[i][l] == 0) ? (1 - key_prefix_length_bit[node_num][l]) : key_prefix_length_bit[node_num][l];
                }
                constrain(expr * node_key_prefix[node_num][i]);

                highest_byte += highest_byte_selector * (
                   // If (key_prefix_length % 2 == 1), the highest byte is the one where j == key_prefix_length
                   key_prefix_length_bit[node_num][0] * node_key_prefix[node_num][i]
                   // If (key_prefix_length % 2 == 0), the highest byte is the next one after the one where j == key_prefix_length.
                   // Of course, this is only valid if there is indeed a next byte
                    + (1 - key_prefix_length_bit[node_num][0]) * ((i < 31) ? node_key_prefix[node_num][i+1] : TYPE(0))
                   );
            }

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                high_byte_lo[node_num] = highest_byte.data.base() & 0xf;
                high_byte_hi[node_num] = highest_byte.data.base() >> 4;
                // std::cout << "Highest byte = " << std::hex << highest_byte <<
                //             " = " << high_byte_hi[node_num] << " " << high_byte_lo[node_num] << std::dec << std::endl;
            }
            allocate(high_byte_lo[node_num], 1 + NODE_TYPE_COUNT + 32 + 6, node_num); // TODO : lookup in 8bit cell and cell*16
            allocate(high_byte_hi[node_num], 1 + NODE_TYPE_COUNT + 32 + 7, node_num); // TODO : lookup in 8bit cell and cell*16
            allocate(key_prefix_length[node_num], 1 + NODE_TYPE_COUNT + 32 + column_skip, node_num);

            // assure correct decomposition of highest_byte
            constrain(highest_byte - (high_byte_lo[node_num] + 16*high_byte_hi[node_num]));

            // if key_prefix_length is odd, the high 4 bits of the highest key prefix byte should be 0
            constrain(key_prefix_length_bit[node_num][0] * high_byte_hi[node_num]);

            // NB: allocation of parent_hash is the subcomponent's business, although it's part of the key_to_hash table

            // allocate one row as a fresh subcontext:
            context_type node_row_context = context_object.fresh_subcontext(subcontext_columns, node_num, 1);

            // preparing input for the subcomponents
            mpt_node_input_type<FieldType, stage> node_input;
            for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                // a selector-based expression for node_type
                node_input.node_type += node_selector[node_num][type_index]*type_index;
            }
            node_input.node_key_prefix = node_key_prefix[node_num];
            node_input.key_prefix_length = key_prefix_length[node_num];
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // actual node data is only available at assignment stage
                node_input.node_data = n;
            }

            switch(n.type) {
                case branch:    mpt_branch(node_row_context, node_input); break;
                case extension: mpt_extension(node_row_context, node_input); break;
                case subtree:   mpt_subtree(node_row_context, node_input); break;
                case leaf:      mpt_leaf(node_row_context, node_input); break;
                default: break;
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
               auto selector = context_object.relativize(node_selector[0][static_cast<std::size_t>(n.type)], 0);
               auto row_constraints = node_row_context.get_constraints();
               for (const auto &constr_list: row_constraints) {
                    BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                    for (auto [constraint, name]: constr_list.second) {
                        context_object.relative_constrain(constraint * selector, 0, max_mpt_size - 1, name);
                    }
               }
               auto row_lookup_constraints = node_row_context.get_lookup_constraints();
            }
            node_num++;
        }
    }
};
} // namespace nil::blueprint::bbf
