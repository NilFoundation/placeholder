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

#pragma once

#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
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

        using input_type = std::conditional_t<
            stage == GenerationStage::ASSIGNMENT,
            std::vector<std::pair<zkevm_word_type, zkevm_word_type>>,
            std::monostate
        >;

        std::size_t max_exponentiations;
        std::vector<TYPE> selector;
        std::vector<TYPE> base_hi;
        std::vector<TYPE> base_lo;
        std::vector<TYPE> exponent_hi;
        std::vector<TYPE> exponent_lo;
        std::vector<TYPE> exponentiation_hi;
        std::vector<TYPE> exponentiation_lo;

        public:
        static std::size_t get_witness_amount(){
            return 7;
        }

        exp_table(
            context_type &context_object,
            const input_type &input,
            std::size_t max_exponentiations_
        ): max_exponentiations(max_exponentiations_),
            generic_component<FieldType, stage>(context_object),
            selector(max_exponentiations),
            base_hi(max_exponentiations),
            base_lo(max_exponentiations),
            exponent_hi(max_exponentiations),
            exponent_lo(max_exponentiations),
            exponentiation_hi(max_exponentiations),
            exponentiation_lo(max_exponentiations)
        {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input.size() <= max_exponentiations);

                std::size_t i = 0;
                std::cout << "Exp table:" << std::endl;
                for (i = 0; i < input.size(); i++) {
                    zkevm_word_type base = input[i].first;
                    zkevm_word_type exponent = input[i].second;
                    zkevm_word_type exponentiation = exp_by_squaring(base, exponent);
                    // We don't prove zero and one exponent by lookup table
                    if( exponent == 0 || exponent == 1 ) continue;
                    std::cout <<"\t" << base << " ^ " << exponent << " = " << exponentiation << std::endl;

                    selector[i] = 1;
                    base_hi[i] = w_hi<FieldType>(base); base_lo[i] = w_lo<FieldType>(base);
                    exponent_hi[i] = w_hi<FieldType>(exponent); exponent_lo[i] = w_lo<FieldType>(exponent);
                    exponentiation_hi[i] = w_hi<FieldType>(exponentiation); exponentiation_lo[i] = w_lo<FieldType>(exponentiation);
                }
            }

            for (std::size_t i = 0; i < max_exponentiations; i++) {
                allocate(selector[i], 0, i);
                allocate(base_hi[i], 1, i);
                allocate(base_lo[i], 2, i);
                allocate(exponent_hi[i], 3, i);
                allocate(exponent_lo[i], 4, i);
                allocate(exponentiation_hi[i], 5, i);
                allocate(exponentiation_lo[i], 6, i);
            }

            lookup_table("zkevm_exp", {0, 1, 2, 3, 4, 5, 6}, 0, max_exponentiations);
        };
    };
}