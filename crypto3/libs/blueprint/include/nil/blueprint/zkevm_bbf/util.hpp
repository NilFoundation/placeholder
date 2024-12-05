//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks16_to_chunks128(const std::vector<TYPE> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 8; i++){
                    result_hi *= 0x10000;
                    result_hi += chunks[i];
                    result_lo *= 0x10000;
                    result_lo += chunks[i+8];
                }
                return {result_hi, result_lo};
            }

            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks16_to_chunks128_reversed(const std::vector<TYPE> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 8; i++){
                    result_lo *= 0x10000;
                    result_lo += chunks[7 - i];
                    result_hi *= 0x10000;
                    result_hi += chunks[15 - i];
                }
                return {result_hi, result_lo};
            }

            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks8_to_chunks128(const std::vector<TYPE> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 16; i++){
                    result_hi *= 0x100;
                    result_hi += chunks[i];
                    result_lo *= 0x100;
                    result_lo += chunks[i+16];
                }
                return {result_hi, result_lo};
            }
        }
    }
}