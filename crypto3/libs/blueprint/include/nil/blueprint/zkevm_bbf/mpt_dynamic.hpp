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

#include <nil/blueprint/zkevm_bbf/types/mpt_trie.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_branch.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_extension.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_leaf_proxy.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_nodes/mpt_node_common.hpp>

#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/keccak_table.hpp>

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

    using input_paths = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_paths_vector, std::nullptr_t>::type;
    struct input_type {
        TYPE rlc_challenge;

        input_paths paths_vector;
    };

    using value_type = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

    static const std::size_t max_mpt_columns = 950;

    static table_params get_minimal_requirements(std::size_t max_mpt_size) {
        return {
            .witnesses = max_mpt_columns,
            .public_inputs = 1,
            .constants = 0,
            .rows = max_mpt_size
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_mpt_size) {
        context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
    }

    std::size_t get_column(const TYPE &V) {
        std::size_t res = 0;
        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            using var = context<FieldType, stage>::var;
            auto is_var = nil::crypto3::zk::snark::expression_is_variable_visitor<var>::is_var;
            BOOST_ASSERT(is_var(V));
            var V_var = boost::get<crypto3::zk::snark::term<var>>(V.get_expr()).get_vars()[0];
            res = V_var.index;
        } else {
            throw std::runtime_error("get_column function used at assignment stage.");
        }
        return res;
    }

    mpt_dynamic(context_type &context_object,
        const input_type &input,
        std::size_t max_mpt_size) : generic_component<FieldType,stage>(context_object) {

        // Table columns, listed by order of allocation into the table
        std::vector<TYPE> rlc_challenge(max_mpt_size);     // copies of RLC challenge from public input

        std::size_t column_skip = 72; // number of columns in a part of the common part TODO: change this

        // Columns for storing information common to all node types
        std::vector<std::size_t> node_common_columns;
        for(std::size_t i = 1; i < 1 + NODE_TYPE_COUNT + 1 + 32 + 1 + column_skip; i++) {
            node_common_columns.push_back(i);
        }

        // All other columns are delegated to node-specific subcomponents. For them we'll create subcontexts
        std::vector<std::size_t> node_specific_columns;
        for(std::size_t i = 1 + NODE_TYPE_COUNT + 1 + 32 + 1 + column_skip; i < max_mpt_columns - 4; i++) {
            node_specific_columns.push_back(i);
        }

        // The last four columns are for Keccak lookup table
        std::vector<std::size_t> keccak_columns;
        for(std::size_t i = max_mpt_columns - 4; i < max_mpt_columns; i++) {
            keccak_columns.push_back(i);
        }

        // Now prepare a list of nodes to be processed (compatible with both assignment and constraints stages)
        // For the assignment stage we convert a list of paths into a unified list of nodes,
        // appending the additional "subtree" nodes.
        std::unordered_map<mpt_node_id, mpt_node> deploy_plan;

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
           for(auto &p : input.paths_vector) { // enumerate paths
               std::size_t trie_id = 1; // TODO : adjust later
               zkevm_word_type path_key;
               std::size_t accumulated_length = 0;

               std::cout << "slot number = " << std::hex << p.slotNumber << std::dec << std::endl;
               std::array<uint8_t,32> slotNumber = w_to_8(p.slotNumber);
               std::vector<uint8_t> buffer(slotNumber.begin(), slotNumber.end());
               path_key = nil::blueprint::zkevm_keccak_hash(buffer);
               std::cout << "path key = " << std::hex << path_key << std::dec << std::endl;

               zkevm_word_type key_suffix = path_key;
               zkevm_word_type accumulated_key = path_key;
               bool is_parent_ext = false;
               std::size_t prev_key_length = 0;
               for(auto &n : p.proof) {
                   std::cout << "\nnode type = " << n.type << std::endl;

                   // determine the node key prefix, depending on the node type
                   std::size_t key_length = 0;     // size of key in each node (bytes)- for branch = 1

                   if (n.type != branch) { // extension or leaf
                       zkevm_word_type first_value = n.value.at(0);
                       key_length = n.len.at(0);

                       zkevm_word_type k0 = n.value.at(0) >> 4*(key_length - 1);
                       if ((k0 == 1) || (k0 == 3)) {
                           key_length--; // then we only skip the first hex symbol
                       } else {
                           key_length -= 2; // otherwise, the second hex is 0 and we skip it too
                       }
                   } else {
                       key_length = 1;
                   }

                   zkevm_word_type key_before_accum = path_key >> 4*(64 - accumulated_length);
                   std::cout << "key prefix : " << std::hex << key_before_accum << std::dec << std::endl;

                   mpt_node_id n_id = { trie_id, key_before_accum, accumulated_length, prev_key_length, n.type, is_parent_ext };
                   is_parent_ext = (n.type == extension);
                   prev_key_length = key_length;

                   if (deploy_plan.find(n_id) != deploy_plan.end()) {
                       // TODO process node _replacement_
                       std::cout << "We have a replacement" << std::endl;
                       BOOST_ASSERT(0); // When we encounter such a situation, we need code here
                   } else {
                       deploy_plan[n_id] = n;
                   }

                   accumulated_length += key_length; // for the next node
                }
           }
        } else {
           for(std::size_t virtual_node = 0; virtual_node < NODE_TYPE_COUNT; virtual_node++) {
               mpt_node_id n_id = {
                   .trie_id = 0,
                   .key_prefix = 0,
                   .key_prefix_length = 0,
                   .parent_key_length = 0,
                   .type = mpt_node_type(virtual_node)
               };
               deploy_plan[n_id] = mpt_node({mpt_node_type(virtual_node), {0}, {0}});
           }
        }
        // at this point deploy_plan contains all the information we need

        // a place to store all the sequences that are to be hashed via keccak
        typename zkevm_big_field::keccak_table<FieldType,stage>::private_input_type keccak_buffers;
        // we need the hash of an empty string as a fallback for some lookups
        static const auto zerohash = zkevm_keccak_hash({});

        // prepare the RLC column (independent of everything else)
        for(std::size_t i = 0; i < max_mpt_size; i++) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                rlc_challenge[i] = input.rlc_challenge; // all challenges are equal :)
            }
            allocate(rlc_challenge[i], 0, i);
            copy_constrain(input.rlc_challenge, rlc_challenge[i]);
        }

        // the main cycle (Assignments & constraints)
        std::size_t node_num = 0; // = row number, since we have 1 row per node
        for(auto nr : deploy_plan) {
            mpt_node_id n_id = nr.first;
            mpt_node n = nr.second;
            // std::cout << "\nnode " << node_num << " type = " << n.type << std::endl;

            // allocate first part of row for common information
            context_type common_row_context = context_object.fresh_subcontext(node_common_columns, node_num, 1);
            typename mpt_node_common<FieldType, stage>::input_type common_input;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                common_input = n_id;
            }
            auto Res = mpt_node_common<FieldType, stage>(common_row_context, common_input);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                TYPE padding;
                for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                    TYPE type_selector = context_object.relativize(Res.type_selector[type_index], -node_num);
                    context_object.relative_constrain( type_selector * (1 - type_selector), 0, max_mpt_size - 1);
                    padding += type_selector;
                }
                context_object.relative_constrain( padding * (padding - 1), 0, max_mpt_size - 1);

                auto row_constraints = common_row_context.get_constraints();
                for (const auto &constr_list: row_constraints) {
                     BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                     for (auto [constraint, name]: constr_list.second) {
                         context_object.relative_constrain(constraint * padding, 0, max_mpt_size - 1, name);
                     }
                }
                // NB: if there are range-check lookups, we should define them externally
            }

            // allocate second part of row for node-specific information
            context_type node_row_context = context_object.fresh_subcontext(node_specific_columns, node_num, 1);

            // preparing input for the subcomponents
            node_private_input<FieldType, stage> node_data;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // actual node data is only available at assignment stage
                node_data = n;
            }

            mpt_node_input_type<FieldType, stage> node_input = {
                .trie_id = Res.trie_id,
                .rlc_challenge = rlc_challenge[node_num],
                .node_key_prefix = Res.key_prefix,
                .key_prefix_length = Res.key_prefix_length,
                .parent_key_length = Res.parent_key_length,
                .shifted_key_prefix = Res.shifted_key_prefix,
                .branch_key = Res.key_prefix_lower[31], // the last symbol in the key
                .node_data = node_data,
                .keccak_buffers = &keccak_buffers
            };

            std::array<TYPE, 32> parent_hash; // allocated by node-specific code
            std::array<std::array<TYPE, 32>, 16> child; // 16 32-byte child hashes for branch nodes

            if (n.type == branch) {
                auto res = mpt_branch(node_row_context, node_input);
                parent_hash = res.parent_hash;
                child = res.child;
            } else if (n.type == extension) {
                parent_hash = mpt_extension(node_row_context, node_input).parent_hash;
            } else if (n.type == leaf) {
                parent_hash = mpt_leaf_proxy(node_row_context, node_input).parent_hash;
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
               auto selector = context_object.relativize(Res.type_selector[static_cast<std::size_t>(n.type)], -node_num);

               auto row_constraints = node_row_context.get_constraints();
               for (const auto &constr_list: row_constraints) {
                    BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                    for (auto [constraint, name]: constr_list.second) {
                        context_object.relative_constrain(constraint * selector, 0, max_mpt_size - 1, name);
                    }
               }
               auto row_lookup_constraints = node_row_context.get_lookup_constraints();
               for (const auto &constr_list: row_lookup_constraints) {
                    BOOST_ASSERT(constr_list.first.size() == 1); // there should only be one row in the subcomponent
                    for (auto lookup_constraint: constr_list.second) {
                        auto exprs = lookup_constraint.second;
                        if (lookup_constraint.first != "keccak_table") {
                            for(auto &e : exprs) {
                                e *= selector;
                            }
                        } else {
                            exprs[1] *= selector;
                            exprs[2] = exprs[2]*selector + (1 - selector)*w_hi<FieldType>(zerohash);
                            exprs[3] = exprs[3]*selector + (1 - selector)*w_lo<FieldType>(zerohash);
                        }
                        context_object.relative_lookup(exprs, lookup_constraint.first, 0, max_mpt_size - 1);
                    }
               }

               std::array<std::string, 16> table_name;
               for(std::size_t j = 0; j < 16; j++) {
                   std::stringstream table_num;
                   table_num << std::hex << j;
                   table_name[j] = "key_to_child_hash_" + table_num.str();
               }

               // declare key_child_hash tables
               if (n.type == branch) {
                   for(std::size_t j = 0; j < 16; j++) {
                       std::vector<std::size_t> k2ch_lookup_columns = {
                           get_column(Res.type_selector[branch]),
                           get_column(Res.trie_id)
                       };
                       // add 32 key_prefix cols into the table
                       for(std::size_t i = 0; i < 32; i++) {
                           k2ch_lookup_columns.push_back(get_column(Res.key_prefix[i]));
                       }
                       // key_prefix_length column included
                       k2ch_lookup_columns.push_back(get_column(Res.key_prefix_length));

                       // 32 more columns: the j's child hash from the branch node
                       for(std::size_t i = 0; i < 32; i++) {
                           k2ch_lookup_columns.push_back(get_column(child[j][i]));
                       }
/*
std::cout << "Lookup columns for table " << std::hex << j << std::dec << std::endl;
for(auto c : k2ch_lookup_columns) {
std::cout << c << ", ";
}
std::cout << std::endl;
*/
                       lookup_table(table_name[j], k2ch_lookup_columns, 0, max_mpt_size);
                   }
               }

                // Inter-row connections: any node type can have a branch node as parent.
                // Hence we define here conditional lookups to child_hash tables
                TYPE padding;
                for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                    padding += Res.type_selector[type_index];
                }

                for(std::size_t j = 0; j < 16; j++) {
                    std::vector<TYPE> query = {
                        padding * Res.branch_selector[j],
                        padding * Res.trie_id * Res.branch_selector[j]
                    };
                    for(std::size_t i = 0; i < 32; i++) {
                        query.push_back(padding * Res.shifted_key_prefix[i] * Res.branch_selector[j]); // the parent's key_prefix
                    }
                    query.push_back(padding * (Res.key_prefix_length - 1) * Res.branch_selector[j]); // the parent's key_prefix length
                    for(std::size_t i = 0; i < 32; i++) {
                        query.push_back(padding * parent_hash[i] * Res.branch_selector[j]); // the parent hash bytes
                    }

                    for(auto &e : query) {
                        e = context_object.relativize(e, -node_num);
                    }
                    context_object.relative_lookup(query, table_name[j], 0, max_mpt_size - 1);
                }
            }
/*
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
std::vector<std::size_t> cols2print = { 3, 1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397};
std::cout << "ROW " << node_num << std::endl;
for(auto c : cols2print) {
    std::cout << context_object.W(c, node_num) << " ";
}
std::cout << std::endl;
}
*/
            node_num++;
        }

        context_type keccak_ct = context_object.subcontext(keccak_columns, 0, max_mpt_size);
        zkevm_big_field::keccak_table<FieldType,stage>(keccak_ct, {input.rlc_challenge, keccak_buffers}, max_mpt_size);
        // TODO: last parameter ^^^ should be max_keccak_blocks, but for now max_mpt_size is ok
    }
};
} // namespace nil::blueprint::bbf
