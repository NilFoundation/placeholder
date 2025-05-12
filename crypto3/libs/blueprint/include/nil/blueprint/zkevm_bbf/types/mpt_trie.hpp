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

namespace nil::blueprint::bbf {

enum mpt_node_type { extension = 0, branch = 1, leaf = 2, subtree = 3, NODE_TYPE_COUNT = 4 }; // just to be sure it's sequential, we rely on that

struct mpt_node {
   enum mpt_node_type type;
   std::vector<zkevm_word_type> value;
   std::vector<std::size_t> len;
};

struct mpt_node_id {
   std::size_t trie_id;
   zkevm_word_type key_prefix;
   std::size_t key_prefix_length;

   bool operator==(const mpt_node_id& other) const {
       return ((trie_id == other.trie_id) &&
               (key_prefix == other.key_prefix) &&
               (key_prefix_length == other.key_prefix_length));
   }
};

struct mpt_path {
    zkevm_word_type slotNumber; // TODO change this
    std::vector<mpt_node> proof;
};

class mpt_paths_vector : public std::vector<mpt_path> {
};
} // namespace nil::blueprint::bbf

template<>
struct std::hash<nil::blueprint::bbf::mpt_node_id> {
    std::size_t operator()(const nil::blueprint::bbf::mpt_node_id &var) const {
        std::size_t result = std::hash<std::size_t>()(var.trie_id);
        boost::hash_combine(result, std::hash<nil::blueprint::zkevm_word_type>()(var.key_prefix));
        boost::hash_combine(result, std::hash<std::size_t>()(var.key_prefix_length));
        return result;
    }
};

