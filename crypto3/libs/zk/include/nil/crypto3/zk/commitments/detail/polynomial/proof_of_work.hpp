//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_PROOF_OF_WORK_HPP
#define CRYPTO3_PROOF_OF_WORK_HPP

#include <boost/property_tree/ptree.hpp>

#include <cstdint>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename TranscriptHashType, typename OutType = std::uint32_t>
                class proof_of_work {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using output_type = OutType;

                    static inline std::array<std::uint8_t, sizeof(OutType)>
                        to_byte_array(OutType v) {
                            std::array<std::uint8_t, sizeof(OutType)> bytes;
                            for(int i = sizeof(v)-1; i>=0; --i) {
                                bytes[i] = v & 0xFF;
                                v >>= 8;
                            }
                            return bytes;
                        }

                    static inline OutType generate(transcript_type &transcript, std::size_t grinding_bits = 16) {
                        BOOST_ASSERT_MSG(grinding_bits < 64, "Grinding parameter should be bits, not mask");
                        output_type mask = grinding_bits > 0 ? ( 1ULL << grinding_bits ) - 1 : 0;
                        output_type pow_seed = std::rand();

                        /* Enough work for ~ two minutes on 48 cores, keccak<512> */
                        std::size_t per_block = 1 << 30;

                        std::atomic<bool> challenge_found = false;
                        std::atomic<std::size_t> pow_value_offset;

                        while( true ) {
                            wait_for_all(parallel_run_in_chunks<void>(
                                per_block,
                                [&transcript, &pow_seed, &challenge_found, &pow_value_offset, &mask](std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t i = pow_start;
                                    while ( i < pow_finish ) {
                                        if (challenge_found) {
                                            break;
                                        }
                                        transcript_type tmp_transcript = transcript;
                                        tmp_transcript(to_byte_array(pow_seed + i));
                                        OutType pow_result = tmp_transcript.template int_challenge<OutType>();
                                        if ( ((pow_result & mask) == 0) && !challenge_found ) {
                                            bool expected = false;
                                            if (challenge_found.compare_exchange_strong(expected, true)) {
                                                pow_value_offset = i;
                                            }
                                            break;
                                        }
                                        ++i;
                                    }
                                }, ThreadPool::PoolLevel::LOW));

                            if (challenge_found) {
                                break;
                            }
                            pow_seed += per_block;
                        }

                        transcript(to_byte_array(pow_seed + (std::size_t)pow_value_offset));
                        transcript.template int_challenge<OutType>();
                        return pow_seed + (std::size_t)pow_value_offset;
                    }

                    static inline bool verify(transcript_type &transcript, output_type proof_of_work, std::size_t grinding_bits = 16) {
                        BOOST_ASSERT_MSG(grinding_bits < 64, "Grinding parameter should be bits, not mask");
                        transcript(to_byte_array(proof_of_work));
                        output_type result = transcript.template int_challenge<output_type>();
                        output_type mask = grinding_bits > 0 ? ( 1ULL << grinding_bits ) - 1 : 0;
                        return ((result & mask) == 0);
                    }
                };

                // Note that the interface here is slightly different from the one above:
                // amount of bits for grinding instead of the mask.
                // This was done because the actual mask is applied to the high bits instead of the low bits
                // which makes manually setting the mask error-prone.
                template<typename TranscriptHashType, typename FieldType>
                class field_proof_of_work {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using value_type = typename FieldType::value_type;
                    using integral_type = typename FieldType::integral_type;

                    static inline value_type generate(transcript_type &transcript, std::size_t GrindingBits=16) {
                        static boost::random::random_device dev;
                        static nil::crypto3::random::algebraic_engine<FieldType> random_engine(dev);
                        value_type pow_seed = random_engine();

                        integral_type mask =
                            (GrindingBits > 0 ?
                                ((integral_type(1) << GrindingBits) - 1) << (FieldType::modulus_bits - GrindingBits)
                                : 0);

                        /* Enough work for ~ two minutes on 48 cores, poseidon<pallas> */
                        std::size_t per_block = 1 << 23;

                        std::atomic<bool> challenge_found = false;
                        std::atomic<std::size_t> pow_value_offset;

                        while( true ) {
                            wait_for_all(parallel_run_in_chunks<void>(
                                per_block,
                                [&transcript, &pow_seed, &challenge_found, &pow_value_offset, &mask](std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t i = pow_start;
                                    while ( i < pow_finish ) {
                                        if (challenge_found) {
                                            break;
                                        }
                                        transcript_type tmp_transcript = transcript;
                                        tmp_transcript(pow_seed + i);
                                        integral_type pow_result = integral_type(
                                            tmp_transcript.template challenge<FieldType>()
                                                .to_integral());
                                        if ( ((pow_result & mask) == 0) && !challenge_found ) {
                                            bool expected = false;
                                            if (challenge_found.compare_exchange_strong(expected, true)) {
                                                pow_value_offset = i;
                                            }
                                            break;
                                        }
                                        ++i;
                                    }
                                }, ThreadPool::PoolLevel::LOW));

                            if (challenge_found) {
                                break;
                            }
                            pow_seed += per_block;
                        }

                        transcript(pow_seed + (std::size_t)pow_value_offset);
                        transcript.template challenge<FieldType>();
                        return pow_seed + (std::size_t)pow_value_offset;
                    }

                    static inline bool verify(transcript_type &transcript, value_type proof_of_work, std::size_t GrindingBits = 16) {
                        transcript(proof_of_work);
                        integral_type mask =
                            (GrindingBits > 0 ?
                                ((integral_type(1) << GrindingBits) - 1) << (FieldType::modulus_bits - GrindingBits)
                                : 0);

                        integral_type result = integral_type(
                            transcript.template challenge<FieldType>().to_integral());
                        return ((result & mask) == 0);
                    }
                };
            }
        }
    }
}

#endif  // CRYPTO3_PROOF_OF_WORK_HPP
