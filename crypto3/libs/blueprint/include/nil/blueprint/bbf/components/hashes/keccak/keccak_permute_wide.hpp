//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <dtabalin@nil.foundation>
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

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            // directly copied from https://crates.io/crates/p3-keccak-air/0.2.2-succinct
            template<typename FieldType, GenerationStage stage>
            class keccak_permute_wide : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using typename generic_component<FieldType, stage>::table_params;
                using value_type = typename FieldType::value_type;
                using integral_type = typename FieldType::integral_type;

                static constexpr std::size_t bits_per_limb = 16;
                static constexpr std::size_t u64_limbs = 64 / bits_per_limb;

                struct input_type {
                    std::array<TYPE, 25> input;
                };

                static constexpr std::size_t R[5][5] = {
                   {0, 36, 3, 41, 18},
                    {1, 44, 10, 45, 2},
                    {62, 6, 43, 15, 61},
                    {28, 55, 25, 21, 56},
                    {27, 20, 39, 8, 14},
                };

                static constexpr std::array<integral_type, 24> round_constants = {
                    0x0000000000000001,
                    0x0000000000008082,
                    0x800000000000808A,
                    0x8000000080008000,
                    0x000000000000808B,
                    0x0000000080000001,
                    0x8000000080008081,
                    0x8000000000008009,
                    0x000000000000008A,
                    0x0000000000000088,
                    0x0000000080008009,
                    0x000000008000000A,
                    0x000000008000808B,
                    0x800000000000008B,
                    0x8000000000008089,
                    0x8000000000008003,
                    0x8000000000008002,
                    0x8000000000000080,
                    0x000000000000800A,
                    0x800000008000000A,
                    0x8000000080008081,
                    0x8000000000008080,
                    0x0000000080000001,
                    0x8000000080008008,
                };

                struct state_type {
                    std::array<TYPE, 24> step_flags;
                    std::array<std::array<std::array<TYPE, u64_limbs>, 5>, 5> preimage;
                    std::array<std::array<std::array<TYPE, u64_limbs>, 5>, 5> a;
                    std::array<std::array<TYPE, 64>, 5> c;
                    std::array<std::array<TYPE, 64>, 5> c_prime;
                    std::array<std::array<std::array<TYPE, 64>, 5>, 5> a_prime;
                    std::array<std::array<std::array<TYPE, u64_limbs>, 5>, 5> a_prime_prime;
                    std::array<TYPE, 64> a_prime_prime_0_0_bits;
                    std::array<TYPE, u64_limbs> a_prime_prime_prime_0_0_limbs;

                    TYPE b(std::size_t x, std::size_t y, std::size_t z) {
                        BOOST_ASSERT(x < 5);
                        BOOST_ASSERT(y < 5);
                        BOOST_ASSERT(z < 64);

                        std::size_t a = (x + 3 * y) % 5;
                        std::size_t b = x;
                        std::size_t rot = R[a][b];
                        return a_prime[b][a][(z + 64 - rot) % 64];
                    }

                    TYPE a_prime_prime_prime(std::size_t y, std::size_t x, std::size_t limb) {
                        BOOST_ASSERT(y < 5);
                        BOOST_ASSERT(x < 5);
                        BOOST_ASSERT(limb < 64);

                        if (y == 0 && x == 0) {
                            return a_prime_prime_prime_0_0_limbs[limb];
                        } else {
                            return a_prime_prime[y][x][limb];
                        }
                    }
                };

                std::array<state_type, 24> states;

                static table_params get_minimal_requirements() {
                    const std::size_t witness = 2632;
                    const std::size_t public_inputs = 2;
                    const std::size_t constants = 1;
                    const std::size_t rows = 24;
                    return {witness, public_inputs, constants, rows};
                }

                static void allocate_public_inputs(
                    context_type &context_object, input_type &input
                ) {
                    for (std::size_t i = 0; i < 24; i++) {
                        context_object.allocate(input.input[i], 0, i, column_type::public_input);
                    }
                    context_object.allocate(input.input[24], 1, 0, column_type::public_input);
                }

                integral_type rc_value_limb(std::size_t round, std::size_t limb) {
                    return (round_constants[round] >> (limb * bits_per_limb)) & 0xffff;
                }

                value_type rc_value_bit(std::size_t round, std::size_t bit) {
                    return (round_constants[round] >> bit) & 1;
                }

                static TYPE xor_constraint(const TYPE &a, const TYPE &b) {
                    return a + b - 2 * a * b;
                }

                static TYPE xor3_constraint(const TYPE &a, const TYPE &b, const TYPE &c) {
                    return xor_constraint(xor_constraint(a, b), c);
                }

                void generate_trace_row_for_round(
                    std::size_t round
                ) {
                    auto &state = states[round];
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        for (std::size_t i = 0; i < 24; i++) {
                            if (i == round) {
                                state.step_flags[i] = value_type::one();
                            } else {
                                state.step_flags[i] = value_type::zero();
                            }
                        }

                        // Populate C[x] = xor(A[x, 0], A[x, 1], A[x, 2], A[x, 3], A[x, 4]).
                        for (std::size_t x = 0; x < 5; x++) {
                            for (std::size_t z = 0; z < 64; z++) {
                                const std::size_t limb = z / bits_per_limb;
                                const std::size_t bit_in_limb = z % bits_per_limb;
                                std::array<bool, 5> a;
                                for (std::size_t y = 0; y < 5; y++) {
                                    const integral_type tmp = integral_type(state.a[y][x][limb].data);
                                    a[y] = ((tmp >> bit_in_limb) & 1) != 0;
                                }
                                state.c[x][z] = value_type(
                                    std::accumulate(a.begin(), a.end(), false, std::bit_xor<bool>())
                                );
                            }
                        }

                        // Populate C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
                        for (std::size_t x = 0; x < 5; x++) {
                            for (std::size_t z = 0; z < 64; z++) {
                                const std::array<bool, 3> tmp = {
                                    state.c[x][z] != value_type::zero(),
                                    state.c[(x + 4) % 5][z] != value_type::zero(),
                                    state.c[(x + 1) % 5][(z + 63) % 64] != value_type::zero(),
                                };
                                state.c_prime[x][z] = value_type(
                                    std::accumulate(tmp.begin(), tmp.end(), false, std::bit_xor<bool>())
                                );
                            }
                        }

                        // Populate A'. To avoid shifting indices, we rewrite
                        //     A'[x, y, z] = xor(A[x, y, z], C[x - 1, z], C[x + 1, z - 1])
                        // as
                        //     A'[x, y, z] = xor(A[x, y, z], C[x, z], C'[x, z]).
                        for (std::size_t x = 0; x < 5; x++) {
                            for (std::size_t y = 0; y < 5; y++) {
                                for (std::size_t z = 0; z < 64; z++) {
                                    const std::size_t limb = z / bits_per_limb;
                                    const std::size_t bit_in_limb = z % bits_per_limb;
                                    const integral_type tmp = integral_type(state.a[y][x][limb].data);
                                    const integral_type a_bit = (tmp >> bit_in_limb) & 1;
                                    state.a_prime[y][x][z] = value_type(
                                        a_bit ^ integral_type(state.c[x][z].data) ^ integral_type(state.c_prime[x][z].data)
                                    );
                                }
                            }
                        }

                        // Populate A''.
                        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
                        for (std::size_t y = 0; y < 5; y++) {
                            for (std::size_t x = 0; x < 5; x++) {
                                for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                    value_type acc = 0;
                                    for (int z = (limb + 1) * bits_per_limb - 1; z >= int(limb * bits_per_limb); z--) {
                                        const bool bool_b = state.b(x, y, z) != 0;
                                        const bool bool_b_plus_1 = state.b((x + 1) % 5, y, z) != 0;
                                        const bool bool_b_plus_2 = state.b((x + 2) % 5, y, z) != 0;
                                        const bool bool_andn_result = !bool_b_plus_1 && bool_b_plus_2;
                                        const bool bit = bool_b ^ bool_andn_result;
                                        acc = (2 * acc) + bit;
                                    }
                                    state.a_prime_prime[y][x][limb] = acc;
                                }
                            }
                        }

                        // For the XOR, we split A''[0, 0] to bits.
                        integral_type val = 0;
                        for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                            const integral_type val_limb = integral_type(state.a_prime_prime[0][0][limb].data);
                            val |= val_limb << (limb * bits_per_limb);
                        }
                        std::array<bool, 64> val_bits;
                        for (std::size_t i = 0; i < 64; i++) {
                            val_bits[i] = (val & 1) != 0;
                            val >>= 1;
                        }
                        for (std::size_t i = 0; i < 64; i++) {
                            state.a_prime_prime_0_0_bits[i] = value_type(val_bits[i]);
                        }

                        // A''[0, 0] is additionally xor'd with round constant.
                        for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                            const integral_type rc_lo = rc_value_limb(round, limb);
                            const integral_type a_prime_prime_val = integral_type(state.a_prime_prime[0][0][limb].data);
                            const integral_type xor_result = a_prime_prime_val ^ rc_lo;
                            state.a_prime_prime_prime_0_0_limbs[limb] = value_type(xor_result);
                        }
                    }
                    // allocate state variables
                    for (std::size_t i = 0; i < 24; i++) {
                        allocate(state.step_flags[i]);
                    }
                    for (std::size_t x = 0; x < 5; x++) {
                        for (std::size_t y = 0; y < 5; y++) {
                            for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                allocate(state.preimage[x][y][limb]);
                                allocate(state.a[x][y][limb]);
                                allocate(state.a_prime_prime[x][y][limb]);
                            }
                            for (std::size_t z = 0; z < 64; z++) {
                                allocate(state.a_prime[x][y][z]);
                            }
                        }
                        for (std::size_t z = 0; z < 64; z++) {
                            allocate(state.c[x][z]);
                            allocate(state.c_prime[x][z]);
                        }
                    }
                    for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                        allocate(state.a_prime_prime_prime_0_0_limbs[limb]);
                    }
                    for (std::size_t i = 0; i < 64; i++) {
                        allocate(state.a_prime_prime_0_0_bits[i]);
                    }

                    if constexpr(stage == GenerationStage::CONSTRAINTS) {
                        for (std::size_t i = 0; i < 24; i++) {
                            if (i == round) {
                                constrain(state.step_flags[i] - value_type::one(),
                                          "keccak step flag enable constraint for round " + std::to_string(round));
                            } else {
                                constrain(state.step_flags[i],
                                          "keccak step flag disable constraint for round " + std::to_string(round));
                            }
                        }
                        // If this is the first step, the input A must match the preimage.
                        if (round == 0) {
                            for (std::size_t y = 0; y < 5; y++) {
                                for (std::size_t x = 0; x < 5; x++) {
                                    for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                        constrain(state.a[y][x][limb] - state.preimage[y][x][limb],
                                                  "keccak first round preimage constraint for x = " + std::to_string(x) +
                                                  ", y = " + std::to_string(y) +
                                                  ", limb = " + std::to_string(limb));
                                    }
                                }
                            }
                        }
                        // If this is not the final step, the local and next preimages must match.
                        if (round > 0) {
                            auto &prev_state = states[round - 1];
                            for (std::size_t y = 0; y < 5; y++) {
                                for (std::size_t x = 0; x < 5; x++) {
                                    for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                        constrain(prev_state.preimage[y][x][limb] - state.preimage[y][x][limb],
                                                  "keccak preimage constraint for round = " + std::to_string(round) +
                                                  ", x = " + std::to_string(x) +
                                                  ", y = " + std::to_string(y) +
                                                  ", limb = " + std::to_string(limb));
                                    }
                                }
                            }
                        }
                        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
                        for (std::size_t x = 0; x < 5; x++) {
                            for (std::size_t z = 0; z < 64; z++) {
                                constrain(state.c[x][z] * (state.c[x][z] - value_type::one()),
                                          "keccak c bool constraint for x = " + std::to_string(x) +
                                          ", z = " + std::to_string(z));
                                constrain(xor3_constraint(
                                    state.c[x][z],
                                    state.c[(x + 4) % 5][z],
                                    state.c[(x + 1) % 5][(z + 63) % 64])
                                - state.c_prime[x][z],
                                "keccak c xor constraint for x = " + std::to_string(x) +
                                ", z = " + std::to_string(z));
                            }
                        }
                        // Check that the input limbs are consistent with A' and D.
                        // A[x, y, z] = xor(A'[x, y, z], D[x, y, z])
                        //            = xor(A'[x, y, z], C[x - 1, z], C[x + 1, z - 1])
                        //            = xor(A'[x, y, z], C[x, z], C'[x, z]).
                        // The last step is valid based on the identity we checked above.
                        // It isn't required, but makes this check a bit cleaner.
                        for (std::size_t y = 0; y < 5; y++) {
                            for (std::size_t x = 0; x < 5; x++) {
                                auto get_bit = [&](int z) -> auto {
                                    auto a_prime = state.a_prime[y][x][z];
                                    auto c = state.c[x][z];
                                    auto c_prime = state.c_prime[x][z];
                                    return xor3_constraint(a_prime, c, c_prime);
                                };
                                for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                    TYPE computed_limb = get_bit((limb + 1) * bits_per_limb - 1);
                                    for (int z = (limb + 1) * bits_per_limb - 2; z >= int(limb * bits_per_limb); z--) {
                                        computed_limb = (2 * computed_limb) + get_bit(z);
                                        constrain(state.a_prime[y][x][z] * (state.a_prime[y][x][z] - value_type::one()),
                                                  "a_prime boolean constraint for x = " + std::to_string(x) +
                                                  ", y = " + std::to_string(y) +
                                                  ", bit = " + std::to_string(z));
                                    }
                                    constrain(state.a[y][x][limb] - computed_limb,
                                              "keccak a limb computation constraint for x = " + std::to_string(x) +
                                              ", y = " + std::to_string(y) +
                                              ", limb = " + std::to_string(limb));
                                }
                            }
                        }
                        // xor_{i=0}^4 A'[x, i, z] = C'[x, z], so for each x, z,
                        // diff * (diff - 2) * (diff - 4) = 0, where
                        // diff = sum_{i=0}^4 A'[x, i, z] - C'[x, z]
                        for (std::size_t x = 0; x < 5; x++) {
                            for (std::size_t z = 0; z < 64; z++) {
                                TYPE sum = state.a_prime[0][x][z];
                                for (std::size_t i = 1; i < 5; i++) {
                                    sum += state.a_prime[i][x][z];
                                }
                                TYPE diff = sum - state.c_prime[x][z];
                                constrain(diff * (diff - value_type(2)) * (diff - value_type(4)),
                                          "keccak sum a' - c' constraint for x = " + std::to_string(x) +
                                          ", z = " + std::to_string(z));
                            }
                        }
                        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
                        for (std::size_t y = 0; y < 5; y++) {
                            for (std::size_t x = 0; x < 5; x++) {
                                for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                    auto get_bit = [&](int z) -> auto {
                                        auto b_plus_1 = state.b((x + 1) % 5, y, z);
                                        auto b_plus_2 = state.b((x + 2) % 5, y, z);
                                        auto andn = (value_type::one() - b_plus_1) * b_plus_2;
                                        return xor_constraint(state.b(x, y, z), andn);
                                    };
                                    TYPE computed_limb = get_bit((limb + 1) * bits_per_limb - 1);
                                    for (int z = (limb + 1) * bits_per_limb - 2; z >= int(limb * bits_per_limb); z--) {
                                        computed_limb = (2 * computed_limb) + get_bit(z);
                                    }
                                    constrain(state.a_prime_prime[y][x][limb] - computed_limb,
                                              "keccak a prime prime computation constraint for x = " + std::to_string(x) + ", y = " + std::to_string(y) + ", limb = " + std::to_string(limb));
                                }
                            }
                        }
                        // A'''[0, 0] = A''[0, 0] XOR RC
                        for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                            TYPE computed_limb = state.a_prime_prime_0_0_bits[(limb + 1) * bits_per_limb - 1];
                            constrain(computed_limb * (computed_limb - value_type::one()),
                                      "keccak a prime prime 0 0 bits bit constraint for limb " + std::to_string(limb) + ", bit " + std::to_string((limb + 1) * bits_per_limb - 1));
                            for (int z = (limb + 1) * bits_per_limb - 2; z >= int(limb * bits_per_limb); z--) {
                                computed_limb = 2 * computed_limb + state.a_prime_prime_0_0_bits[z];
                                constrain(state.a_prime_prime_0_0_bits[z] *
                                          (state.a_prime_prime_0_0_bits[z] - value_type::one()),
                                          "keccak a prime prime 0 0 bits bit constraint for limb " + std::to_string(limb) + ", bit " + std::to_string(z));
                            }
                            constrain(state.a_prime_prime[0][0][limb] - computed_limb,
                                      "keccak a prime prime prime xor round constant constraint for limb " + std::to_string(limb));
                        }
                        auto get_xored_bit = [&](int i) -> auto {
                            TYPE rc_bit_i = state.step_flags[0] * value_type(rc_value_bit(0, i));
                            for (std::size_t r = 1; r < 24; r++) {
                                const auto this_round = state.step_flags[r];
                                const auto this_round_constant = value_type(rc_value_bit(r, i));
                                rc_bit_i = rc_bit_i + this_round * this_round_constant;
                            }
                            return xor_constraint(state.a_prime_prime_0_0_bits[i], rc_bit_i);
                        };
                        for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                            TYPE computed_limb = get_xored_bit((limb + 1) * bits_per_limb - 1);
                            for (int z = (limb + 1) * bits_per_limb - 2; z >= int(limb * bits_per_limb); z--) {
                                computed_limb = (2 * computed_limb) + get_xored_bit(z);
                            }
                            constrain(state.a_prime_prime_prime_0_0_limbs[limb] - computed_limb,
                                      "keccak a prime prime prime 0 0 limbs constraint for limb " + std::to_string(limb));
                        }
                        // Enforce that this round's output equals the next round's input.
                        if (round > 0) {
                            auto &prev_state = states[round - 1];
                            for (std::size_t x = 0; x < 5; x++) {
                                for (std::size_t y = 0; y < 5; y++) {
                                    for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                        constrain(prev_state.a_prime_prime_prime(y, x, limb) - state.a[y][x][limb],
                                                  "keccak a prime prime prime step constraint for x = " + std::to_string(x) +
                                                  ", y = " + std::to_string(y) +
                                                  ", limb = " + std::to_string(limb));
                                    }
                                }
                            }
                        }
                    }
                }

                keccak_permute_wide(
                    context_type &context_object, input_type input
                ) : generic_component<FieldType, stage>(context_object)
                {
                    for (std::size_t round = 0; round < 24; round++) {
                        auto &state = states[round];
                        auto &prev_state = states[round - 1];
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t y = 0; y < 5; y++) {
                                for (std::size_t x = 0; x < 5; x++) {
                                    for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                        state.preimage[y][x][limb] = value_type(
                                            (integral_type(input.input[y * 5 + x].data) >> (16 * limb)) & 0xFFFF
                                        );
                                    }
                                }
                            }
                            if (round == 0) {
                                for (std::size_t y = 0; y < 5; y++) {
                                    for (std::size_t x = 0; x < 5; x++) {
                                        for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                            state.a[y][x][limb] = value_type(
                                                (integral_type(input.input[y * 5 + x].data) >> (16 * limb)) & 0xFFFF
                                            );
                                        }
                                    }
                                }
                            } else {
                                for (std::size_t y = 0; y < 5; y++) {
                                    for (std::size_t x = 0; x < 5; x++) {
                                        for (std::size_t limb = 0; limb < u64_limbs; limb++) {
                                            state.a[y][x][limb] = prev_state.a_prime_prime_prime(y, x, limb);
                                        }
                                    }
                                }
                            }
                        }
                        generate_trace_row_for_round(round);
                    }
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
