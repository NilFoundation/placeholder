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
#include <optional>

#include <nil/actor/math/detail/utility.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/actor/zk/transcript/fiat_shamir.hpp>


namespace nil {
    namespace actor {
        namespace zk {
            namespace commitments {
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

                        /* Enough work for ~ two minutes */
                        std::size_t per_core = 1<<18;

                        std::atomic<bool> challenge_found = false;
                        value_type pow_value;

                        while( true ) {
                            // std::vector<std::optional<value_type>> 
                            auto results = math::detail::block_execution_vector(
                                per_core*smp::count, smp::count,
                                [&transcript, &pow_seed, &challenge_found](std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t i = pow_start;
                                    while ( i < pow_finish ) {
                                        if (challenge_found)
                                            break;
                                        transcript_type tmp_transcript = transcript;
                                        tmp_transcript(pow_seed + i);
                                        integral_type pow_result = integral_type(tmp_transcript.template challenge<FieldType>().data);
                                        if ( (pow_result & mask) == 0 ) {
                                            challenge_found = true;
                                            break;
                                        }
                                        ++i;
                                    }
                                    if ( i < pow_finish ) {
                                        return std::optional<value_type>{ pow_seed + i };
                                    } else {
                                        return std::optional<value_type>{ };
                                    }
                                });

                            auto found = std::find_if(results.begin(), results.end(),
                                    [](auto x) { return x.get() ; });

                            if (found != results.end()) {
                                pow_value = found->get();
                                break;
                            }

                            pow_seed += per_core * smp::count;
                        }

                        transcript(pow_value);
                        transcript.template challenge<FieldType>();
                        return pow_value;
                    }

                    static inline bool verify(transcript_type &transcript, value_type const& proof_of_work) {
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
