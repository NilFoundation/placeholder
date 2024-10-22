//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
//#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/zkevm/state.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

//#include <nil/blueprint/components/hashes/keccak/keccak_table.hpp>

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class bytecode_table_input_type {
            public:
                typedef std::vector<std::pair<std::vector<std::uint8_t>, zkevm_word_type>> data_type;

                void fill_bytecodes(const data_type &_bytecodes ){
                    BOOST_ASSERT(bytecodes.size() == 0);
                    bytecodes = _bytecodes;
                }

                const data_type &get_bytecodes() const{
                    return bytecodes;
                }

                // For real usage. Bytecodes order doesn't matter
                std::size_t new_bytecode(std::pair<std::vector<std::uint8_t>, zkevm_word_type> hashed_pair){
                    bytecodes.push_back(hashed_pair);
                    return bytecodes.size() - 1;
                }

                // TODO two versions -- with keccak and poseidon.
                // Keccak is more universal because we have poseidon implementation only for pallas curve
                std::size_t new_bytecode(std::vector<std::uint8_t> code = {}){
                    zkevm_word_type hash = zkevm_keccak_hash(code);
                    bytecodes.push_back({code, hash});
                    return bytecodes.size() - 1;
                }

                // For small tests where we define opcode sequences manually
                void push_byte(std::size_t code_id, std::uint8_t b){
                    BOOST_ASSERT(code_id < bytecodes.size());
                    bytecodes[code_id].first.push_back(b);
                    bytecodes[code_id].second = zkevm_keccak_hash(bytecodes[code_id].first);
                }
            private:
                // TODO: prevent copying
                data_type bytecodes; // EVM contracts bytecodes
            };

            // Component for bytecode table

            template<typename FieldType, GenerationStage stage>
            class zkevm_bytecode_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

                public:
                using typename generic_component<FieldType,stage>::TYPE;

                std::size_t max_bytecode_size;

                // interfaces for interaction with other components:
                std::vector<TYPE> tag = std::vector<TYPE>(max_bytecode_size);
                std::vector<TYPE> index = std::vector<TYPE>(max_bytecode_size);
                std::vector<TYPE> value = std::vector<TYPE>(max_bytecode_size);
                std::vector<TYPE> is_opcode = std::vector<TYPE>(max_bytecode_size);
                std::vector<TYPE> hash_hi = std::vector<TYPE>(max_bytecode_size);
                std::vector<TYPE> hash_lo = std::vector<TYPE>(max_bytecode_size);

                zkevm_bytecode_table(context_type &context_object,
                                     std::size_t max_bytecode_size_,
                                     const bytecode_table_input_type &private_input,
                                     bool make_links = true) :
                    max_bytecode_size(max_bytecode_size_),
                    generic_component<FieldType,stage>(context_object) {

                    // if we're in assignment stage, prepare all the values
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto bytecodes = private_input.get_bytecodes();

                        std::size_t cur = 0;
                        for(std::size_t i = 0; i < bytecodes.size(); i++) {
                            TYPE hash_hi_val = w_hi<FieldType>(bytecodes[i].second);
                            TYPE hash_lo_val = w_lo<FieldType>(bytecodes[i].second);
                            TYPE push_size = 0;
                            const auto &buffer = bytecodes[i].first;
                            for(std::size_t j = 0; j < buffer.size(); j++, cur++){
                                std::uint8_t byte = buffer[j];
                                hash_hi[cur] = hash_hi_val;
                                hash_lo[cur] = hash_lo_val;
                                if( j == 0) { // HEADER
                                    value[cur] = buffer.size();
                                    tag[cur] = 0;
                                    index[cur] = 0;
                                    is_opcode[cur] = 0;
                                    push_size = 0; // might be unnecessary
                                    cur++;
                                }
                                // BYTE
                                value[cur] = byte;
                                hash_hi[cur] = hash_hi_val;
                                hash_lo[cur] = hash_lo_val;
                                tag[cur] = 1;
                                index[cur] = j;
                                if (push_size == 0) {
                                    is_opcode[cur] = 1;
                                    if (byte > 0x5f && byte < 0x80) push_size = byte - 0x5f;
                                } else {
                                    is_opcode[cur] = 0;
                                    push_size--;
                                }
                            }
                        }
                    }
                    // allocate everything. NB: this replaces the map from the original component
                    for(std::size_t i = 0; i < max_bytecode_size; i++) {
                        allocate(tag[i],0,i);
                        allocate(index[i],1,i);
                        allocate(value[i],2,i);
                        allocate(is_opcode[i],3,i);
                        allocate(hash_hi[i],4,i);
                        allocate(hash_lo[i],5,i);
                    }
                    // declare dynamic lookup table
                    lookup_table("zkevm_bytecode",std::vector<std::size_t>({0,1,2,3,4,5}),0,max_bytecode_size);
                };
	    };
        }    // namespace bbf
    }        // namespace blueprint
}    // namespace nil
