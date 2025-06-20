//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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
// @file Declaration of interfaces for ECDSA public key recovery over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ECDSA_RECOVERY_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ECDSA_RECOVERY_HPP

#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_full_add.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_scalar_mult.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/add_sub_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/detail/allocate_public_input_chunks.hpp>
#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/blueprint/bbf/components/detail/choice_function.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: curve (in Weierstrass form, y² = x³ + a),
                //                num_chunks = k, bit_size_chunk = b
                // Takes partial message hash z and extended ECDSA signature (r,s,V)
                // Outputs
                // bit c = signature is valid and
                // QA = (xQA, yQA) = the recovered public key
                // Expects input as k-chunked values with b bits per chunk
                // Input: z[0],...,z[k-1], r[0],...,r[k-1], s[0],...,s[k-1], V
                // Output: c, xQA[0],...,xQA[k-1], yQA[0],...,yQA[k-1]
                //
                template<typename FieldType, GenerationStage stage, typename CurveType>
                class ecdsa_recovery : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;

                    struct input_type {
                      std::vector<TYPE> z;
                      std::vector<TYPE> r;
                      std::vector<TYPE> s;
                      TYPE v;
                    };

                  public:
                    TYPE c;
                    std::vector<TYPE> xQA;
                    std::vector<TYPE> yQA;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::size_t witness = 7 * num_chunks;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 1;
                        std::size_t rows = num_chunks >= 16 ? 150000 : 131072 - 1;
                        return {witness, public_inputs, constants, rows};
                    }

                    static void allocate_public_inputs(
                            context_type &ctx, input_type &input,
                            std::size_t num_chunks, std::size_t bit_size_chunk) {
                        AllocatePublicInputChunks allocate_chunks(ctx, num_chunks);

                        std::size_t row = 0;
                        allocate_chunks(input.z, 0, &row);
                        allocate_chunks(input.r, 0, &row);
                        allocate_chunks(input.s, 0, &row);
                        ctx.allocate(input.v, 0, row++,
                                     column_type::public_input);
                    }

                    ecdsa_recovery(context_type& context_object, const input_type &input,
                                   std::size_t num_chunks, std::size_t bit_size_chunk,
                                   bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;

                        using BaseField = typename CurveType::base_field_type;
                        using BASE_TYPE = typename BaseField::value_type;
                        using base_basic_integral_type =
                            typename BaseField::integral_type;
                        typedef nil::crypto3::multiprecision::big_uint<
                            2 * BaseField::modulus_bits>
                            base_integral_type;

                        using ScalarField = typename CurveType::scalar_field_type;
                        using SCALAR_TYPE = typename ScalarField::value_type;
                        using scalar_basic_integral_type =
                            typename ScalarField::integral_type;
                        typedef nil::crypto3::multiprecision::big_uint<
                            2 * ScalarField::modulus_bits>
                            scalar_integral_type;

                        using ec_point_value_type = typename CurveType::template g1_type<
                            nil::crypto3::algebra::curves::coordinates::affine>::
                            value_type;

                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Carry_On_addition =
                            typename bbf::components::carry_on_addition<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;

                        using Addition_Mod_P =
                            typename bbf::components::add_sub_mod_p<FieldType, stage,
                                                                     BaseField, true>;
                        using Substitution_Mod_P =
                            typename bbf::components::add_sub_mod_p<FieldType, stage,
                                                                     BaseField, false>;
                        using Multiplication_Mod_P =
                            typename bbf::components::flexible_multiplication<
                                FieldType, stage, BaseField>;

                        using Addition_Mod_N =
                            typename bbf::components::add_sub_mod_p<FieldType, stage,
                                                                     ScalarField, true>;
                        using Substitution_Mod_N =
                            typename bbf::components::add_sub_mod_p<FieldType, stage,
                                                                     ScalarField, false>;
                        using Multiplication_Mod_N =
                            typename bbf::components::flexible_multiplication<
                                FieldType, stage, ScalarField>;

                        using Ec_Full_Add =
                            typename bbf::components::ec_full_add<FieldType, stage,
                                                                  BaseField>;
                        using Ec_Scalar_Mult =
                            typename bbf::components::ec_scalar_mult<FieldType, stage,
                                                                     BaseField>;

                        // Definition of constants
                        base_integral_type bB = base_integral_type(1) << bit_size_chunk,
                                           p = BaseField::modulus,
                                           b_ext_pow = base_integral_type(1)
                                                       << num_chunks * bit_size_chunk,
                                           pp = b_ext_pow - p;

                        scalar_integral_type sB = scalar_integral_type(1)
                                                  << bit_size_chunk,
                                             n = ScalarField::modulus,
                                             s_ext_pow = scalar_integral_type(1)
                                                         << num_chunks * bit_size_chunk,
                                             np = s_ext_pow - n, m = (n - 1) / 2 + 1,
                                             mp = s_ext_pow - m;

                        ec_point_value_type G = ec_point_value_type::one();
                        base_integral_type x = base_integral_type(
                                               base_basic_integral_type(
                                                   G.X.to_integral())),
                                           y = base_integral_type(
                                               base_basic_integral_type(
                                                   G.Y.to_integral()));
                        BASE_TYPE a = CurveType::template g1_type<
                            nil::crypto3::algebra::curves::coordinates::affine>::
                            params_type::b;

                        size_t row = 0;

                        // Helper functions for allocating constants
                        auto PushBaseChunks = [&context_object, &row, bB, num_chunks](base_integral_type x) {
                            std::vector<TYPE> X(num_chunks);
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = TYPE(x % bB);
                                context_object.allocate(X[i], 0, row,
                                                        column_type::constant);
                                x /= bB;
                                row++;
                            }
                            return X;
                        };

                        auto PushScalarChunks = [&context_object, &row, sB, num_chunks](scalar_integral_type x) {
                            std::vector<TYPE> X(num_chunks);
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = TYPE(x % sB);
                                context_object.allocate(X[i], 0, row,
                                                        column_type::constant);
                                x /= sB;
                                row++;
                            }
                            return X;
                        };

                        // Allocating constants
                        std::vector<TYPE> P = PushBaseChunks(p);
                        std::vector<TYPE> PP = PushBaseChunks(pp);

                        std::vector<TYPE> N = PushScalarChunks(n);
                        std::vector<TYPE> NP = PushScalarChunks(np);
                        std::vector<TYPE> M = PushScalarChunks(m);
                        std::vector<TYPE> MP = PushScalarChunks(mp);
                        std::vector<TYPE> X = PushBaseChunks(x);
                        std::vector<TYPE> Y = PushBaseChunks(y);
                        base_basic_integral_type aBB =
                            base_basic_integral_type(a.to_integral());
                        base_integral_type aB = base_integral_type(aBB);
                        std::vector<TYPE> A = PushBaseChunks(aB);

                        TYPE zero = 0;
                        TYPE one = 1;
                        allocate(zero, 0, row, column_type::constant);
                        row++;
                        allocate(one, 0, row, column_type::constant);
                        row++;

                        std::vector<TYPE> CHUNKED_ZERO(num_chunks);
                        std::vector<TYPE> CHUNKED_ONE(num_chunks);
                        std::vector<TYPE> CHUNKED_BIT(num_chunks);

                        for (std::size_t i = 0; i < num_chunks; i++) {
                            CHUNKED_ONE[i] = (i != 0) ? zero : one;
                            CHUNKED_BIT[i] = (i != 0) ?  zero : 0;                            
                            CHUNKED_ZERO[i] = zero;
                        }
                        allocate(CHUNKED_BIT[0]);

                        // Helper functions for subcomponents
                        auto RangeCheck = [&context_object, num_chunks,
                                           bit_size_chunk](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                        };
                        auto CheckModP = [&context_object, num_chunks, bit_size_chunk,
                                          zero](std::vector<TYPE> x,
                                                std::vector<TYPE> pp) {
                            Check_Mod_P rc =
                                Check_Mod_P(context_object, {x, pp, zero}, num_chunks,
                                            bit_size_chunk, false);
                        };
                        auto CheckModPOut = [&context_object, num_chunks, bit_size_chunk,
                                             zero](std::vector<TYPE> x,
                                                   std::vector<TYPE> pp) {
                            Check_Mod_P rc =
                                Check_Mod_P(context_object, {x, pp, zero}, num_chunks,
                                            bit_size_chunk, true);
                            return rc.output;
                        };
                        auto CarryOnAddition = [&context_object, num_chunks,
                                                bit_size_chunk](std::vector<TYPE> x,
                                                                std::vector<TYPE> y,
                                                                bool make_link = true) {
                            Carry_On_addition ca =
                                Carry_On_addition(context_object, {x, y}, num_chunks,
                                                  bit_size_chunk, make_link);
                            return ca;
                        };
                        auto ChoiceFunction =
                            [&context_object, num_chunks, bit_size_chunk](
                                TYPE q, std::vector<TYPE> x, std::vector<TYPE> y) {
                                Choice_Function cf = Choice_Function(
                                    context_object, {q, x, y}, num_chunks, bit_size_chunk);
                                return cf.r;
                            };

                        auto CopyConstrain = [this, num_chunks](std::vector<TYPE> x,
                                                                std::vector<TYPE> y) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(x[i], y[i]);
                            }
                        };

                        auto SingleCopyConstrain = [this, num_chunks](TYPE x, TYPE y) {
                            copy_constrain(x, y);
                        };

                        auto SubModP = [&context_object, P, PP, zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x, std::vector<TYPE> y) {
                            Substitution_Mod_P t =
                                Substitution_Mod_P(context_object, {x,y, P, PP, zero},
                                               num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto AddModP = [&context_object, P, PP, zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,
                                                        std::vector<TYPE> y) {
                            Addition_Mod_P t =
                                Addition_Mod_P(context_object, {x, y, P, PP, zero},
                                               num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto MultModP = [&context_object, P, PP, zero, num_chunks,
                                         bit_size_chunk](std::vector<TYPE> x,
                                                         std::vector<TYPE> y) {
                            Multiplication_Mod_P t =
                                Multiplication_Mod_P(context_object, {x, y, P, PP, zero},
                                                     num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        
                        auto SubModN = [&context_object, N, NP, zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x, 
                                                        std::vector<TYPE> y) {
                            Substitution_Mod_N t =
                                Substitution_Mod_N(context_object, {x,y, N, NP, zero},
                                               num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto AddModN = [&context_object, N, NP, zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,
                                                        std::vector<TYPE> y) {
                            Addition_Mod_N t =
                                Addition_Mod_N(context_object, {x, y, N, NP, zero},
                                               num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto MultModN = [&context_object, N, NP, zero, num_chunks,
                                         bit_size_chunk](std::vector<TYPE> x,
                                                         std::vector<TYPE> y) {
                            Multiplication_Mod_N t =
                                Multiplication_Mod_N(context_object, {x, y, N, NP, zero},
                                                     num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto ECFullAdd = [&context_object, P, PP, zero,
                                          num_chunks, bit_size_chunk](
                                             std::vector<TYPE> xP, std::vector<TYPE> yP,
                                             std::vector<TYPE> xQ, std::vector<TYPE> yQ) {
                            Ec_Full_Add t =
                                Ec_Full_Add(context_object, {xP, yP, xQ, yQ, P, PP, zero},
                                            num_chunks, bit_size_chunk);
                            return t;
                        };

                        auto ECScalarMult = [&context_object, P, PP, N, MP, zero,
                                             num_chunks, bit_size_chunk](
                                                std::vector<TYPE> s, std::vector<TYPE> x,
                                                std::vector<TYPE> y) {
                            Ec_Scalar_Mult t =
                                Ec_Scalar_Mult(context_object, {s, x, y, P, PP, N, MP, zero},
                                               num_chunks, bit_size_chunk);
                            return t;
                        };

                        auto CopyChunks = [num_chunks](std::vector<TYPE>& from,
                                                       std::vector<TYPE>& to) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                to[i] = from[i];
                            }
                        };



                        // Declaring intermediate values 
                        std::vector<TYPE> Z(num_chunks);
                        std::vector<TYPE> R(num_chunks);
                        std::vector<TYPE> S(num_chunks);
                        TYPE V;
    
                        std::vector<TYPE> C(9);  // the c bits, c[0] = c[1]*...*c[8]
                        std::vector<TYPE> XQA(num_chunks);
                        std::vector<TYPE> YQA(num_chunks);
                        std::vector<TYPE> U1(num_chunks);
                        std::vector<TYPE> U2(num_chunks);
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);
                        std::vector<TYPE> I1(num_chunks);
                        std::vector<TYPE> I3(num_chunks);
                        std::vector<TYPE> I6(num_chunks);
                        std::vector<TYPE> I5(num_chunks);
                        std::vector<TYPE> D2(num_chunks);
                        std::vector<TYPE> I8(num_chunks);

                        ec_point_value_type QA;

                        // Assigning intermediate values
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                Z[i] = input.z[i];
                                R[i] = input.r[i];
                                S[i] = input.s[i];
                            }
                            V = input.v;

                            scalar_integral_type pow = 1;
                            SCALAR_TYPE z = 0, r = 0, s = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                z += scalar_integral_type(
                                         integral_type(input.z[i].to_integral())) *
                                     pow;
                                r += scalar_integral_type(
                                         integral_type(input.r[i].to_integral())) *
                                     pow;
                                s += scalar_integral_type(
                                         integral_type(input.s[i].to_integral())) *
                                     pow;
                                pow <<= bit_size_chunk;
                            }

                            SCALAR_TYPE i1, i3, i6;
                            BASE_TYPE i5, d2, i8;

                            // the computations
                            C[1] = 1 - r.is_zero();
                            i1 = r.is_zero() ? 0 : r.inversed();

                            C[2] =
                                (scalar_basic_integral_type(r.to_integral()) < n) ? 1 : 0;

                            C[3] = 1 - s.is_zero();
                            i3 = s.is_zero() ? 0 : s.inversed();

                            C[4] =
                                (scalar_basic_integral_type(s.to_integral()) < m) ? 1 : 0;

                            BASE_TYPE x1 = scalar_basic_integral_type(
                                r.to_integral());  // should we consider r + n also?
                            BASE_TYPE y1 =
                                (x1 * x1 * x1 + a).is_square()
                                    ? (x1 * x1 * x1 + a).sqrt()
                                    : 1;  // should be signaled as invalid signaure
                            if (base_basic_integral_type(y1.to_integral()) % 2 !=
                                scalar_basic_integral_type(
                                    integral_type(V.to_integral())) %
                                    2) {
                                y1 = -y1;
                            }
                            C[5] = (x1 * x1 * x1 + a - y1 * y1).is_zero();
                            i5 = (x1 * x1 * x1 + a - y1 * y1).is_zero()
                                     ? 0
                                     : (x1 * x1 * x1 + a - y1 * y1).inversed();

                            C[6] =
                                (SCALAR_TYPE(base_basic_integral_type(x1.to_integral())) -
                                 r)
                                    .is_zero();
                            i6 =
                                (SCALAR_TYPE(base_basic_integral_type(x1.to_integral())) -
                                 r)
                                        .is_zero()
                                    ? 0
                                    : (SCALAR_TYPE(
                                           base_basic_integral_type(x1.to_integral())) -
                                       r)
                                          .inversed();

                            C[7] = ((base_basic_integral_type(y1.to_integral()) % 2) ==
                                    (scalar_basic_integral_type(
                                         integral_type(V.to_integral())) %
                                     2));
                            d2 = (base_basic_integral_type(y1.to_integral()) +
                                  base_basic_integral_type(scalar_basic_integral_type(
                                      integral_type(V.to_integral())))) /
                                 2;

                            SCALAR_TYPE
                            u1 = r.is_zero()
                                     ? 2
                                     : -z * r.inversed(),  // if r = 0, the signature
                                                           // is invalid, but we
                                u2 = r.is_zero()
                                         ? 2
                                         : s * r.inversed();  // don't wanto to break the
                                                              // scalar multiplication
                            ec_point_value_type R = ec_point_value_type(
                                scalar_basic_integral_type(x1.to_integral()),
                                scalar_basic_integral_type(y1.to_integral()));
                            QA = G * u1 + R * u2;

                            C[8] = 1 - QA.is_zero();

                            i8 = QA.Y.is_zero() ? 0 : QA.Y.inversed();

                            C[0] = C[1] * C[2] * C[3] * C[4] * C[5] * C[6] * C[7] * C[8];

                            auto PushScalarValueChunks = [&context_object, &row, sB,
                                                          num_chunks](SCALAR_TYPE x) {
                                std::vector<TYPE> X(num_chunks);
                                scalar_integral_type x_value =
                                    scalar_basic_integral_type(x.to_integral());
                                for (std::size_t i = 0; i < num_chunks; i++) {
                                    X[i] = x_value % sB;
                                    x_value /= sB;
                                }

                                return X;
                            };

                            auto PushBaseValueChunks = [&context_object, &row, bB,
                                                        num_chunks](BASE_TYPE x) {
                                std::vector<TYPE> X(num_chunks);
                                base_integral_type x_value =
                                    base_basic_integral_type(x.to_integral());
                                for (std::size_t i = 0; i < num_chunks; i++) {
                                    X[i] = x_value % bB;
                                    x_value /= bB;
                                }
                                return X;
                            };

                            XQA = PushBaseValueChunks(QA.X);
                            YQA = PushBaseValueChunks(QA.Y);
                            U1 = PushScalarValueChunks(u1);
                            U2 = PushScalarValueChunks(u2);
                            XR = PushBaseValueChunks(R.X);
                            YR = PushBaseValueChunks(R.Y);

                            I1 = PushScalarValueChunks(i1);
                            I3 = PushScalarValueChunks(i3);
                            I6 = PushScalarValueChunks(i6);

                            I5 = PushBaseValueChunks(i5);
                            D2 = PushBaseValueChunks(d2);
                            I8 = PushBaseValueChunks(i8);
                        }

                        // Allocating intermediate values
                        for (std::size_t i = 0; i < 9; i++) {
                            allocate(C[i]);
                        }
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            allocate(I1[i]);
                            allocate(R[i]);
                            allocate(I3[i]);
                            allocate(S[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                            allocate(I5[i]);
                            allocate(I6[i]);
                            allocate(D2[i]);
                            allocate(U1[i]);
                            allocate(Z[i]);
                            allocate(U2[i]);
                            allocate(S[i]);
                            allocate(I8[i]);
                            allocate(XQA[i]);
                            allocate(YQA[i]);
                        }
                        allocate(V);

                        // Start of the circuit constraints

                        // c1 = [r != 0]
                        RangeCheck(I1);
                        CheckModP(I1, NP);  // CheckModN
                        auto t0 = AddModN(R, CHUNKED_ZERO);
                        auto t1 = MultModN(t0, I1);
                        auto t2 = MultModN(t0, t1);
                        CopyConstrain(t0, t2);
                        CHUNKED_BIT[0] = C[1];
                        CopyConstrain(t1,CHUNKED_BIT);  // t1 = (0,...,0,c1)

                        // c2 = [r < n]
                        auto t3 = CheckModPOut(R, NP);  // CheckModN
                        auto t3p = ChoiceFunction(C[2], CHUNKED_ONE, CHUNKED_ZERO);
                        CHUNKED_BIT[0] = t3;
                        CopyConstrain(CHUNKED_BIT, t3p);  // (0,...,0,t3) = t3p

                        // c3 = [s != 0]
                        RangeCheck(I3);
                        CheckModP(I3, NP);  // CheckModN
                        auto t4 = AddModN(S, CHUNKED_ZERO);
                        auto t5 = MultModN(t4, I3);
                        auto t6 = MultModN(t4, t5);
                        CopyConstrain(t4, t6); 
                        CHUNKED_BIT[0] = C[3];
                        CopyConstrain(t5,CHUNKED_BIT);  // t5 = (0,...,0,c3)

                        // c4 = [s < (n-1)/2+1]
                        auto t7 = CheckModPOut(S, MP);  // CheckModM
                        auto t7p = ChoiceFunction(C[4], CHUNKED_ONE, CHUNKED_ZERO);
                        CHUNKED_BIT[0] = t7;
                        CopyConstrain(CHUNKED_BIT, t7p);  // (0,...,0,t7) = t7p

                        // c5 = [yR^2 = xR^3 + a]
                        RangeCheck(XR);
                        CheckModP(XR, PP);
                        RangeCheck(YR);
                        CheckModP(YR, PP);
                        auto t8 = MultModP(XR, XR);
                        auto t9 = MultModP(t8, XR);
                        auto t10 = AddModP(t9, A);
                        auto t11 = MultModP(YR, YR);

                        auto t12 = SubModP(t10, t11);
                        RangeCheck(I5);
                        CheckModP(I5, PP);
                        auto t13 = MultModP(t12, I5);
                        auto t13p = ChoiceFunction(C[5], CHUNKED_ONE, CHUNKED_ZERO);
                        auto t14 = MultModP(t12, t13);
                        CopyConstrain(t12, t14); 
                        CopyConstrain(t13, t13p); 

                        // c6 = [xR = r (mod n)]
                        auto t15 = AddModN(XR, CHUNKED_ZERO);
                        auto t16 = SubModN(t15, t0);
                        RangeCheck(I6);
                        CheckModP(I6, NP);  // CheckModN
                        auto t17 = MultModN(t16, I6);
                        auto t18 = MultModN(t16, t17);
                        CopyConstrain(t16, t18);
                        auto t19 = ChoiceFunction(C[6], CHUNKED_ONE, CHUNKED_ZERO);
                        CopyConstrain(t17, t19);

                        // c7 = [yR = V (mod 2)]
                        CHUNKED_BIT[0] = V;
                        RangeCheck(CHUNKED_BIT);
                        auto d1 = CarryOnAddition(YR, CHUNKED_BIT);
                        SingleCopyConstrain(d1.c, zero); 
                        RangeCheck(D2);
                        auto d3 = CarryOnAddition(D2, CHUNKED_ONE);
                        SingleCopyConstrain(d3.c, zero); 
                        RangeCheck(d3.r);
                        auto d4 = ChoiceFunction(C[7], d3.r, D2);
                        auto t20 = CarryOnAddition(D2, d4);
                        SingleCopyConstrain(t20.c, zero);
                        CopyConstrain(t20.r, d1.r);

                        // u1 r = -z (mod n)
                        RangeCheck(U1);
                        CheckModP(U1, NP);  // CheckModN
                        auto t21 = MultModN(U1, t0);
                        auto t22 = AddModN(Z, CHUNKED_ZERO);
                        auto t23 = MultModN(t22, t1);
                        auto t24 = AddModN(t21, t23);
                        CopyConstrain(t24, CHUNKED_ZERO);  // t24 = 0

                        // u2 r = s (mod n)
                        RangeCheck(U2);
                        CheckModP(U2, NP);  // CheckModN
                        auto t25 = MultModN(U2, t0);
                        auto t26 = MultModN(S, t1);
                        CopyConstrain(t25, t26);

                        // u1 * G
                        auto t27 = ECScalarMult(U1, X, Y);

                        // u2 * R
                        auto t28 = ECScalarMult(U2, XR, YR);

                        // QA = u1*G + u2*R
                        auto t29 = ECFullAdd(t27.xR, t27.yR, t28.xR, t28.yR);

                        // to assure the circuit doesn't break for invalid signatures we
                        // have to place the results from t29 to (xQA, yQA)

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            BASE_TYPE new_yQA = 0;
                            for (std::size_t i = num_chunks; i > 0; i--) {
                                new_yQA *= sB;
                                new_yQA += integral_type(t29.yR[i - 1].to_integral());
                            }
                            if (QA.Y != new_yQA) {  // we also have to adjust I8, c8 and
                                                    // c0 to agree with the updated yQA
                                BASE_TYPE new_I8 =
                                    new_yQA.is_zero() ? 0 : new_yQA.inversed();
                                base_integral_type new_I8_int =
                                    base_basic_integral_type(new_I8.to_integral());
                                for (std::size_t i = 0; i < num_chunks; i++) {
                                    I8[i] = new_I8_int % bB;
                                    new_I8_int /= bB;
                                }
                                // update c8
                                C[8] = TYPE(1 - new_yQA.is_zero());
                                // update c0
                                C[0] = TYPE(C[0] * (1 - new_yQA.is_zero()));
                            }
                        }
                        // copy constrain QA = t29
                        CopyConstrain(XQA, t29.xR);  
                        CopyConstrain(YQA, t29.yR);

                        // c8 = [QA != O]
                        RangeCheck(I8);
                        CheckModP(I8, PP);
                        auto t30 = MultModP(YQA, I8);
                        auto t31 = MultModP(YQA, t30);
                        CopyConstrain(YQA, t31); 
                        CHUNKED_BIT[0] = C[8];
                        CopyConstrain(t30, CHUNKED_BIT);  // t30 = (0,...,0,c8)

                        // c = c[1]*....*c[8]
                        CHUNKED_BIT[0] = C[1];
                        auto t32 = ChoiceFunction(C[2], CHUNKED_ZERO, CHUNKED_BIT);
                        auto t33 = ChoiceFunction(C[3], CHUNKED_ZERO, t32);
                        auto t34 = ChoiceFunction(C[4], CHUNKED_ZERO, t33);
                        auto t35 = ChoiceFunction(C[5], CHUNKED_ZERO, t34);
                        auto t36 = ChoiceFunction(C[6], CHUNKED_ZERO, t35);
                        auto t37 = ChoiceFunction(C[7], CHUNKED_ZERO, t36);
                        auto t38 = ChoiceFunction(C[8], CHUNKED_ZERO, t37);
                        CHUNKED_BIT[0] = C[0];
                        CopyConstrain(t38, CHUNKED_BIT);  // t38 = (0,...,0,c)

                        for (int i = 0; i < num_chunks; ++i) {
                            xQA.push_back(XQA[i]);
                            yQA.push_back(YQA[i]);
                        }
                        c = C[0];
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ecdsa_recovery
                    : public ecdsa_recovery<FieldType, stage,
                                            crypto3::algebra::curves::pallas> {
                    using Base = ecdsa_recovery<FieldType, stage,
                                                crypto3::algebra::curves::pallas>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ecdsa_recovery
                    : public ecdsa_recovery<FieldType, stage,
                                            crypto3::algebra::curves::vesta> {
                    using Base =
                        ecdsa_recovery<FieldType, stage, crypto3::algebra::curves::vesta>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class secp_k1_256_ecdsa_recovery
                    : public ecdsa_recovery<FieldType, stage,
                                            crypto3::algebra::curves::secp_k1<256>> {
                    using Base =
                        ecdsa_recovery<FieldType, stage, crypto3::algebra::curves::secp_k1<256>>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ECDSA_RECOVERY_HPP
