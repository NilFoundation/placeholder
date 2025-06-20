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
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>

namespace nil::blueprint::bbf {

enum mpt_node_type { extension = 0, branch = 1, leaf = 2, NODE_TYPE_COUNT = 3 }; // just to be sure it's sequential, we rely on that

struct mpt_node {
   enum mpt_node_type type;
   std::vector<zkevm_word_type> value;
   std::vector<std::size_t> len;
   zkevm_word_type hash;
};

struct mpt_node_id {
   std::size_t trie_id;
   zkevm_word_type accumulated_key;
   std::size_t accumulated_key_length;
   // not really needed for identification, but it's convenient to store it here
   std::size_t parent_key_length;
   enum mpt_node_type type;
   bool parent_is_ext;

   bool operator==(const mpt_node_id& other) const {
       return ((trie_id == other.trie_id) &&
               (accumulated_key == other.accumulated_key) &&
               (accumulated_key_length == other.accumulated_key_length) &&
               (parent_key_length == other.parent_key_length) &&
               (type == other.type) &&
               (parent_is_ext == other.parent_is_ext));
   }
};

// struct mpt_path {
//     zkevm_word_type slotNumber; // TODO change this
//     std::vector<mpt_node> proof;
// };

class mpt_nodes_vector : public std::vector <mpt_node> {
};

template<typename FieldType, GenerationStage stage>
using node_private_input = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_node, std::nullptr_t>::type;

template<typename FieldType, GenerationStage stage>
struct mpt_node_input_type {
    using TYPE = typename generic_component<FieldType, stage>::TYPE;
    using keccak_buffer_type = typename zkevm_small_field::keccak_table<FieldType,stage>::private_input_type;

    TYPE rlc_challenge;

    std::array<TYPE,32> node_accumulated_key;
    TYPE node_last_nibble;
    TYPE node_nibble_present;

    node_private_input<FieldType, stage> node_data;

    keccak_buffer_type* keccak_buffers;
};

} // namespace nil::blueprint::bbf

template<>
struct std::hash<nil::blueprint::bbf::mpt_node_id> {
    std::size_t operator()(const nil::blueprint::bbf::mpt_node_id &var) const {
        std::size_t result = std::hash<std::size_t>()(var.trie_id);
        boost::hash_combine(result, std::hash<nil::blueprint::zkevm_word_type>()(var.accumulated_key));
        boost::hash_combine(result, std::hash<std::size_t>()(var.accumulated_key_length));
        boost::hash_combine(result, std::hash<std::size_t>()(var.parent_key_length));
        boost::hash_combine(result, std::hash<std::size_t>()(static_cast<std::size_t>(var.type)));
        boost::hash_combine(result, std::hash<std::size_t>()(static_cast<std::size_t>(var.parent_is_ext)));
        return result;
    }
};