//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for PLONK BBF exp table class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_EXP_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_EXP_TABLE_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <functional>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
// #include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            class exp_table_input_type {
                typedef std::vector<std::array<zkevm_word_type, 3>> data_type;

              public:
                void add_triplet(zkevm_word_type a, zkevm_word_type d, zkevm_word_type A) {
                    triplets.push_back({a, d, A});
                }
                void add_triplets(data_type _triplets){
                    triplets = _triplets;
                }

                const data_type &get_triplets() const { return triplets; }

              private:
                data_type triplets;
            };

            template<typename FieldType, GenerationStage stage>
            class exp_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using word_type = zkevm_word_type;
                constexpr static std::size_t num_chunks = 2;

                std::size_t max_exponentiations;
                std::vector<std::array<TYPE, num_chunks>> base           = std::vector<std::array<TYPE, num_chunks>>(max_exponentiations);
                std::vector<std::array<TYPE, num_chunks>> exponent       = std::vector<std::array<TYPE, num_chunks>>(max_exponentiations);
                std::vector<std::array<TYPE, num_chunks>> exponentiation = std::vector<std::array<TYPE, num_chunks>>(max_exponentiations);

              public:
                exp_table(context_type &context_object, const exp_table_input_type &input,
                          std::size_t max_exponentiations_, bool make_links = true)
                    : max_exponentiations(max_exponentiations_),
                      generic_component<FieldType, stage>(context_object) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto triplets = input.get_triplets();
                        BOOST_ASSERT(triplets.size() <= max_exponentiations);

                        std::size_t i = 0;
                        for (i = 0; i < triplets.size(); i++) {
                            base[i][0] = w_hi<FieldType>(triplets[i][0]);
                            base[i][1] = w_lo<FieldType>(triplets[i][0]);
                            exponent[i][0] = w_hi<FieldType>(triplets[i][1]);
                            exponent[i][1] = w_lo<FieldType>(triplets[i][1]);
                            exponentiation[i][0] = w_hi<FieldType>(triplets[i][2]);
                            exponentiation[i][1] = w_lo<FieldType>(triplets[i][2]);
                        }

                        // if there are unused rows, fill in with valid exp triplets (0^1 = 0)
                        while (i < max_exponentiations) {
                            base[i][0] = 0;
                            base[i][1] = 0;

                            exponent[i][0] = 0;
                            exponent[i][1] = 1;

                            exponentiation[i][0] = 0;
                            exponentiation[i][1] = 0;

                            i++;
                        }

                    }

                    for (std::size_t i = 0; i < max_exponentiations; i++) {
                        for (std::size_t j = 0; j < num_chunks; j++) {
                            allocate(base[i][j], j, i);
                            allocate(exponent[i][j], num_chunks + j, i);
                            allocate(exponentiation[i][j], 2 * num_chunks + j, i);
                        }
                    }

                    lookup_table("exp_table", {0, 1, 2, 3, 4, 5}, 0, max_exponentiations);
                };
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_PLONK_BBF_EXP_TABLE_HPP
