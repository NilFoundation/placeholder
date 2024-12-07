//---------------------------------------------------------------------------//
// Elena Tatuzova
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

// #include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class mpt_verifier : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using private_input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<TYPE>, std::nullptr_t>::type;

                struct input_type{
                    TYPE rlc_challenge;
                    private_input_type public_input;
                };

                std::size_t max_mpt;

            public:
                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(std::size_t max_mpt_){
                    std::size_t witness_amount = 3;
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(witness_amount, 1, 3, 5);
                    desc.usable_rows_amount = 20;
                    return desc;
                }
                mpt_verifier(context_type &context_object, const input_type &input, std::size_t max_mpt_
                    ) : max_mpt(max_mpt_),
                         generic_component<FieldType,stage>(context_object) {
                    using value_type = typename FieldType::value_type;

                    // TYPE proof[20], trace[20];
                    std::vector<TYPE> proof(20);
                    std::vector<TYPE> trace(20);
                    std::vector<TYPE> sum(20);

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "MPT assign " << input.public_input.size() << std::endl;
                        for(std::size_t i = 0; i < 20; i++) {
                            proof[i] = input.public_input[i];
                            trace[i] = input.public_input[i];
                            sum[i] = input.public_input[i] + input.public_input[i] ;
                            // std::cout << "proof[" << i << "] = " << proof[i] << std::endl;
                            // std::cout << "trace[" << i << "] = " << trace[i] << std::endl;
                        }
                        std::cout << "#proof = " << proof.size() << std::endl;
                    } 
                    std::cout << "MPT assignment and circuit construction" << std::endl;

                    std::cout << "input.rlc_challenge = " << input.rlc_challenge << std::endl;

                    for(std::size_t i = 0; i < 20; i++) {
                        allocate(proof[i], 0, i);
                        allocate(trace[i], 1, i);
                        allocate(sum[i], 2, i);
                    }

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        std::cout << "MPT circuit " << std::endl;
                        std::vector<TYPE> every;

                        every.push_back(context_object.relativize(proof[0]  - trace[0], 0));
                        every.push_back(context_object.relativize(proof[0] + trace[0] - 2*proof[0], 0));
                        every.push_back(context_object.relativize(sum[0] - trace[0] - proof[0], 0));

                        for( std::size_t i = 0; i < every.size(); i++ ){
                            context_object.relative_constrain(every[i], 0, 20-1);
                        }
                    }

                    for(std::size_t i = 0; i < 20; i++) {
                        copy_constrain(proof[i], trace[i]);
                    }

                    for(std::size_t i = 0; i < 20; i++) {
                        constrain(proof[i] - trace[i]);
                        constrain(proof[i] + trace[i] - 2*proof[i]);
                    }

                    for(std::size_t i = 0; i < 19; i++) {
                        constrain(proof[i] - proof[i + 1]);
                    }
                }
            };
        }
    }
}