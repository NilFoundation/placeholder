//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoinecyr@nil.foundation>
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
// @file Declaration of interfaces for PLONK component wrapping the BBF-component
// interface
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_RANGE_CHECK_MULTI_HPP
#define CRYPTO3_BBF_COMPONENTS_RANGE_CHECK_MULTI_HPP

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/components/detail/allocate_public_input_chunks.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Constraints value to be of a certain bit size at most
                // Parameters: num_chunks, bit_size_chunk
                // Input: x
                // Output: none

                template<typename FieldType, GenerationStage stage>
                class range_check_multi : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using generic_component<FieldType, stage>::lookup;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;

                    using input_type = std::vector<TYPE>;

                    static const std::size_t bit_size_rc = 16;

                  public:
                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) +
                                                    (bit_size_chunk % bit_size_rc > 0);
                        std::size_t witness = (num_rc_chunks + 1) / 2 + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        // rows = 4096-1 so that lookup table is not too hard to fit and
                        // padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static void allocate_public_inputs(
                            context_type& ctx, input_type& input,
                            std::size_t num_chunks, std::size_t bit_size_chunk) {
                        AllocatePublicInputChunks allocate_chunks(ctx, num_chunks);

                        std::size_t row = 0;
                        allocate_chunks(input, 0, &row);
                    }

                    range_check_multi(context_type &context_object,
                                      const std::vector<TYPE> &input_x,
                                      std::size_t num_chunks,
                                      std::size_t bit_size_chunk,
                                      bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;
                        std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) +
                                                    (bit_size_chunk % bit_size_rc > 0);
                        std::size_t first_chunk_size = bit_size_chunk % bit_size_rc;
                        integral_type mask = (1 << bit_size_rc) - 1;

                        TYPE Y[num_chunks][num_rc_chunks];
                        TYPE X[num_chunks];
                        TYPE C[num_chunks];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            integral_type x_integral;
                            integral_type y_integral;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                X[i] = input_x[i];
                                x_integral = integral_type(X[i].to_integral());
                                for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                    y_integral = x_integral & mask;
                                    Y[i][j] = y_integral;
                                    x_integral >>= bit_size_rc;
                                }
                            }
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            integral_type power = 1;
                            allocate(X[i]);
                            C[i] = X[i];
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                allocate(Y[i][j]);
                                lookup(Y[i][j], "chunk_16_bits/full");
                                C[i] -= Y[i][j] * power;
                                power <<= bit_size_rc;
                            }
                            constrain(C[i]);

                            if (first_chunk_size != 0) {
                                lookup(Y[i][num_rc_chunks - 1] *
                                           (integral_type(1)
                                            << (bit_size_rc - first_chunk_size)),
                                       "chunk_16_bits/full");
                            }

                            if (make_links) {
                                copy_constrain(X[i], input_x[i]);
                            }
                        }
                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_RANGE_CHECK_MULTI_HPP
