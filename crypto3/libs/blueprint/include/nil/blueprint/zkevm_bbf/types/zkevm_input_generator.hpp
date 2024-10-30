//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
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
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/zkevm_bbf/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm_state.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_abstract_input_generator{
            public:
                virtual zkevm_keccak_buffers keccaks() = 0;
                virtual zkevm_keccak_buffers bytecodes() = 0;
                virtual std::vector<rw_operation> rw_operations() = 0;
                virtual std::vector<copy_event> copy_events() = 0;
                virtual std::vector<zkevm_state> zkemv_states() = 0;
                virtual std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exponentiations() = 0;
            };

            class zkevm_hardhat_input_generator:zkevm_abstract_input_generator{
            public:
                zkevm_keccak_buffers keccaks() override {return _keccaks;}
                zkevm_keccak_buffers bytecodes() override { return _bytecodes;}
                std::vector<rw_operation> rw_operations() override {return _rw_operations;}
                std::vector<copy_event> copy_events() override { return _copy_events;}
                std::vector<zkevm_state> zkemv_states() override{ return _zkevm_states};
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exponentiations()override{return exponentiations;}
            private:
                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                std::vector<rw_operation>                                _rw_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
            }
        } // namespace bbf
    } // namespace blueprint
} // namespace nil