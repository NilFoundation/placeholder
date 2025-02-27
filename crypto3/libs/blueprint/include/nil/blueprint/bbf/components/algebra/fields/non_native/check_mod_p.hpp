//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#ifndef CRYPTO3_BBF_COMPONENTS_CHECK_MOD_P_HPP
#define CRYPTO3_BBF_COMPONENTS_CHECK_MOD_P_HPP

#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: num_chunks = k, bit_size_chunk = b
                // Checking that x is in the interval [0;p-1]
                // operates on k-chunked x and p' = 2^(kb) - p
                // Input: x[0], ..., x[k-1], pp[0], ..., pp[k-1], 0
                // (expects zero constant as input)
                // Output: none

                template<typename FieldType, GenerationStage stage>
                class check_mod_p : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;

                    struct input_type {
                      std::vector<TYPE> x;
                      std::vector<TYPE> pp;
                      TYPE zero;
                    };

                  public:
                    TYPE output;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk,
                        bool expect_output = false) {
                        static const std::size_t bit_size_rc = 16;
                        std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) +
                                                    (bit_size_chunk % bit_size_rc > 0);

                        // Same witness columns as range_check_multi
                        std::size_t witness = (num_rc_chunks + 1) / 2 + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        // rows = 4096-1 so that lookup table is not too hard to fit and
                        // padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static void allocate_public_inputs(
                            context_type& ctx, input_type& input, std::size_t num_chunks,
                            std::size_t bit_size_chunk, bool expect_output = false) {
                        AllocatePublicInputChunks allocate_chunks(ctx, num_chunks);

                        std::size_t row = 0;
                        allocate_chunks(input.x, 0, &row);
                        allocate_chunks(input.pp, 0, &row);
                        ctx.allocate(input.zero, 0, row++, column_type::public_input);
                    }

                    check_mod_p(context_type &context_object, const input_type &input,
                                std::size_t num_chunks, std::size_t bit_size_chunk,
                                bool expect_output = false, bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;

                        using Carry_On_Addition =
                            typename bbf::components::carry_on_addition<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;

                        Carry_On_Addition ca = Carry_On_Addition(
                            context_object, {input.x, input.pp}, num_chunks, bit_size_chunk);
                        Range_Check rc = Range_Check(
                            context_object, ca.r, num_chunks, bit_size_chunk);
                        
                        if (expect_output) {
                            output = ca.c;
                        }
                        else {
                            copy_constrain(ca.c, input.zero);
                        }
                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_CHECK_MOD_P_HPP
