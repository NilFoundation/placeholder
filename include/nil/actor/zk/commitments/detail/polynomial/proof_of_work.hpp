//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef ACTOR_PROOF_OF_WORK_HPP
#define ACTOR_PROOF_OF_WORK_HPP

#include <boost/property_tree/ptree.hpp>

#include <cstdint>

#include <nil/actor/math/detail/utility.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/actor/zk/transcript/fiat_shamir.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace commitments {
                template<typename TranscriptHashType, typename OutType = std::uint32_t, std::uint32_t MASK=0xFFFF0000>
                class proof_of_work {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = nil::actor::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using output_type = OutType;

                    constexpr static std::uint32_t mask = MASK;

                    static inline boost::property_tree::ptree get_params() {
                        boost::property_tree::ptree params;
                        params.put("mask", mask);
                        return params;
                    }

                    static inline OutType generate(transcript_type &transcript) {
                        output_type proof_of_work = std::rand();
                        output_type result;
                        std::vector<std::uint8_t> bytes(4);

                        while( true ) {
                            transcript_type tmp_transcript = transcript;
                            bytes[0] = std::uint8_t((proof_of_work&0xFF000000)>>24);
                            bytes[1] = std::uint8_t((proof_of_work&0x00FF0000)>>16);
                            bytes[2] = std::uint8_t((proof_of_work&0x0000FF00)>>8);
                            bytes[3] = std::uint8_t(proof_of_work&0x000000FF);

                            tmp_transcript(bytes);
                            result = tmp_transcript.template int_challenge<output_type>();
                            if ((result & mask) == 0)
                                break;
                            proof_of_work++;
                        }
                        transcript(bytes);
                        result = transcript.template int_challenge<output_type>();
                        return proof_of_work;
                    }

                    static inline bool verify(transcript_type &transcript, output_type proof_of_work) {
                        std::vector<std::uint8_t> bytes(4);
                        bytes[0] = std::uint8_t((proof_of_work&0xFF000000)>>24);
                        bytes[1] = std::uint8_t((proof_of_work&0x00FF0000)>>16);
                        bytes[2] = std::uint8_t((proof_of_work&0x0000FF00)>>8);
                        bytes[3] = std::uint8_t(proof_of_work&0x000000FF);
                        transcript(bytes);
                        output_type result = transcript.template int_challenge<output_type>();
                        return ((result & mask) == 0);
                    }
                };

                // Note that the interface here is slightly different from the one above:
                // amount of bits for grinding instead of the mask.
                // This was done because the actual mask is applied to the high bits instead of the low bits
                // which makes manually setting the mask error-prone.
                template<typename TranscriptHashType, typename FieldType, std::uint8_t GrindingBits=16>
                class field_proof_of_work {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using value_type = typename FieldType::value_type;
                    using integral_type = typename FieldType::integral_type;

                    constexpr static const integral_type mask =
                        (GrindingBits > 0 ?
                            ((integral_type(2) << GrindingBits - 1) - 1) << (FieldType::modulus_bits - GrindingBits)
                            : 0);

                    static inline boost::property_tree::ptree get_params() {
                        boost::property_tree::ptree params;
                        params.put("mask", mask);
                        return params;
                    }

                    static inline value_type generate(transcript_type &transcript, 
                        nil::crypto3::random::algebraic_engine<FieldType> random_engine) {

                        value_type pow_seed = random_engine();
                        value_type init_seed = pow_seed;
                        std::size_t per_core = 2*65536;
                        std::vector<value_type> pow_values(smp::count*per_core);
                        std::atomic<bool> challenge_found = false;
                        value_type pow_value;

                        std::cout << "Starting seed: " << pow_seed << std::endl;
                        std::cout << "Batch size   : " << pow_values.size() << std::endl;
                        std::cout << "SMP count    : " << smp::count << std::endl;

                        while( true ) {

                            /* prepare pow_values for batch */
                            for(std::size_t i = 0; i < pow_values.size(); ++i) {
                                pow_values[i] = ++pow_seed;
                            }

                            /* Execute batch */
                            math::detail::block_execution(
                                pow_values.size(), smp::count,
                                [&transcript, &pow_values, &challenge_found, &pow_value](std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t batch_size = pow_finish - pow_start;
                                    std::size_t ten_percent = batch_size/10;
                                    // std::cout << "Batch item from " << pow_start << " to " << pow_finish << std::endl;
                                    for(std::size_t i = pow_start; i < pow_finish; ++i) {
                                        if (challenge_found)
                                            break;

                                        if ((pow_start == batch_size) && (i-pow_start)%ten_percent == 0) {
                                            std::cout << "Worker #1 processed: " << (i-pow_start)/ten_percent*10 << "%" << std::endl;
                                        }
                                        
                                        transcript_type tmp_transcript = transcript;
                                        tmp_transcript(pow_values[i]);
                                        integral_type pow_result = integral_type(tmp_transcript.template challenge<FieldType>().data);
                                        if (((pow_result & mask) == 0) && !challenge_found) {
                                            challenge_found = true;
                                            pow_value = pow_values[i];
                                            // std::cout << "Challenge found! : " << pow_value << " at " << i << std::endl;
                                            break;
                                        }
                                    }
                                }).get();

                            if (challenge_found)
                                break;
                            std::cout << "Batch with seed " << pow_seed << " (" << pow_seed - init_seed <<" values grinded), gave nothing, starting another..." << std::endl;
                        }
                        std::cout << "Challenge found! : " << pow_value << std::endl;
                        std::cout << "Pow value offset: " << pow_value - init_seed << std::endl;

                        transcript(pow_value);
                        integral_type result = integral_type(transcript.template challenge<FieldType>().data);
                        return pow_value;
                    }

                    static inline bool verify(transcript_type &transcript, value_type proof_of_work) {
                        transcript(proof_of_work);
                        integral_type result = integral_type(transcript.template challenge<FieldType>().data);
                        return ((result & mask) == 0);
                    }
                };
            }
        }
    }
}

#endif  // ACTOR_PROOF_OF_WORK_HPP
