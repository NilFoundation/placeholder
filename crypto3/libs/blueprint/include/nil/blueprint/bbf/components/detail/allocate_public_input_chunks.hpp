//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexander Vasilyev <mizabrik@nil.foundation>
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

#ifndef CRYPTO3_BBF_COMPONENTS_DETAIL_ALLOCATE_PUBLIC_INPUT_CHUNKS_HPP_
#define CRYPTO3_BBF_COMPONENTS_DETAIL_ALLOCATE_PUBLIC_INPUT_CHUNKS_HPP_

#include <vector>

#include <nil/blueprint/bbf/generic.hpp>

namespace nil::blueprint::bbf::components {

template <typename FieldType, GenerationStage stage>
class AllocatePublicInputChunks {
 public:
  using Context = context<FieldType, stage>;
  using Value = generic_component<FieldType, stage>::TYPE;

  AllocatePublicInputChunks(Context &context, size_t num_chunks)
      : context_(context), num_chunks_(num_chunks) {}

  void operator()(std::vector<Value> &chunks, size_t col, size_t start_row) {
    if constexpr (stage == GenerationStage::ASSIGNMENT) {
      assert(chunks.size() == num_chunks_);
    } else {
      chunks.resize(num_chunks_);
    }

    for (size_t i = 0; i < num_chunks_; ++i)
      context_.allocate(chunks[i], col, start_row + i,
                        column_type::public_input);
  }

  // Helper that advances the start_row
  void operator()(std::vector<Value> &chunks, size_t col, size_t *start_row) {
    operator()(chunks, col, *start_row);
    *start_row += num_chunks_;
  }

 private:
  Context &context_;
  const size_t num_chunks_;
};

}  // namespace nil::blueprint::bbf::components

#endif  // CRYPTO3_BBF_COMPONENTS_DETAIL_ALLOCATE_PUBLIC_INPUT_CHUNKS_HPP_
