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

#include <nil/blueprint/bbf/components/algebra/fields/non_native/addition_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/negation_mod_p.hpp>
#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/blueprint/bbf/components/detail/choice_function.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_full_add.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_scalar_mult.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
            // Parameters: curve (in Weierstrass form, y² = x³ + a), num_chunks = k, bit_size_chunk = b
            // Takes partial message hash z and extended ECDSA signature (r,s,V)
            // Outputs
            // bit c = signature is valid and
            // QA = (xQA, yQA) = the recovered public key
            // Expects input as k-chunked values with b bits per chunk
            // Input: z[0],...,z[k-1], r[0],...,r[k-1], s[0],...,s[k-1], V
            // Output: c, xQA[0],...,xQA[k-1], yQA[0],...,yQA[k-1]
            //
                template<typename FieldType>
                struct ecdsa_recovery_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> z;
                    std::vector<TYPE> r;
                    std::vector<TYPE> s;
                    TYPE v;
                };

                template<typename FieldType, GenerationStage stage,
                         typename CurveType>
                class ecdsa_recovery : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  ecdsa_recovery_raw_input<FieldType>,
                                                  std::tuple<>>::type;

                  public:
                    TYPE c;
                    std::vector<TYPE> xQA;
                    std::vector<TYPE> yQA;

                    static table_params get_minimal_requirements(
                        //TODO
                        // Get the right minimal_requirements for this component 
                        // and all non_native and ec subcomponents
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        const std::size_t L = bit_size_chunk*num_chunks + (bit_size_chunk*num_chunks % 2), // if odd, then +1. Thus L is always even
                                            Q = L/2;
                        std::size_t witness = num_chunks * Q;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 1;
                        constexpr std::size_t rows = 65536 - 1;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>, std::vector<TYPE>,
                                      std::vector<TYPE>, TYPE>
                    form_input(context_type& context_object, raw_input_type raw_input,
                               std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_z(num_chunks);
                        std::vector<TYPE> input_r(num_chunks);
                        std::vector<TYPE> input_s(num_chunks);
                        TYPE input_v;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_z[i] = raw_input.z[i];
                                input_r[i] = raw_input.r[i];
                                input_s[i] = raw_input.s[i];
                            }
                            input_v = raw_input.v;
                        }
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            context_object.allocate(input_z[i], 0, i,
                                                    column_type::public_input);
                            context_object.allocate(input_r[i], 0, i + num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_s[i], 0, i + 2 * num_chunks,
                                                    column_type::public_input);
                        }
                        context_object.allocate(input_v, 0, 3 * num_chunks,
                                                    column_type::public_input);
                        return std::make_tuple(input_z, input_r, input_s, input_v);
                    }

                    ecdsa_recovery(context_type& context_object,
                                      std::vector<TYPE> input_z,
                                      std::vector<TYPE> input_r,
                                      std::vector<TYPE> input_s,
                                      TYPE input_v,
                                      std::size_t num_chunks, std::size_t bit_size_chunk,
                                      bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;

                        using BaseField = typename CurveType::base_field_type;
                        using BASE_TYPE = typename BaseField::value_type;
                        using base_basic_integral_type = typename BaseField::integral_type;
                        typedef nil::crypto3::multiprecision::big_uint<2 *BaseField::modulus_bits> base_integral_type;

                        using ScalarField = typename CurveType::scalar_field_type;
                        using SCALAR_TYPE = typename ScalarField::value_type;
                        using scalar_basic_integral_type = typename ScalarField::integral_type;
                        typedef nil::crypto3::multiprecision::big_uint<2 *ScalarField::modulus_bits> scalar_integral_type;

                        using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;

                        base_integral_type bB = base_integral_type(1) << bit_size_chunk,
                                    p = BaseField::modulus,
                            b_ext_pow = base_integral_type(1) << num_chunks*bit_size_chunk,
                                   pp = b_ext_pow - p;

                        scalar_integral_type sB = scalar_integral_type(1) << bit_size_chunk,
                                            n = ScalarField::modulus,
                                    s_ext_pow = scalar_integral_type(1) << num_chunks*bit_size_chunk,
                                            np = s_ext_pow - n,
                                            m = (n-1)/2 + 1,
                                            mp = s_ext_pow - m;

                        ec_point_value_type G = ec_point_value_type::one();
                        base_integral_type x = base_integral_type(base_basic_integral_type(G.X.data)),
                                        y = base_integral_type(base_basic_integral_type(G.Y.data));
                        BASE_TYPE a = CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::params_type::b;
                        
                        size_t row = 0;
                        auto PushBaseChunks = [&context_object,&row,bB,num_chunks](base_integral_type &x) {
                            std::vector<TYPE> X(num_chunks);
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = TYPE(x % bB);
                                context_object.allocate(X[i], 0, row, column_type::constant);
                                x /= bB;
                                row++;
                            }
                            return X;
                        };

                        auto PushScalarChunks = [&context_object,&row, sB,num_chunks](scalar_integral_type &x) {
                            std::vector<TYPE> X(num_chunks);
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = TYPE(x % sB);
                                context_object.allocate(X[i], 0, row, column_type::constant);
                                x /= sB;
                                row++;
                            }
                            return X;
                        };

                        std::vector<TYPE> P = PushBaseChunks(p);
                        std::vector<TYPE> PP = PushBaseChunks(pp);
                        std::vector<TYPE> N = PushScalarChunks(n);
                        std::vector<TYPE> NP = PushScalarChunks(np);
                        std::vector<TYPE> M = PushScalarChunks(m);
                        std::vector<TYPE> MP = PushScalarChunks(mp);
                        std::vector<TYPE> X = PushBaseChunks(x);
                        std::vector<TYPE> Y = PushBaseChunks(y);
                        base_basic_integral_type aBB = base_basic_integral_type(a.data);
                        base_integral_type aB = base_integral_type(aBB);
                        std::vector<TYPE> A = PushBaseChunks(aB);

                        TYPE zero = 0;
                        TYPE one = 1;
                        allocate(zero,0,row,column_type::constant);
                        row++;
                        allocate(one,0,row,column_type::constant);
                    

                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Carry_On_addition =
                            typename bbf::components::carry_on_addition<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;

                        using Addition_Mod_P =
                            typename bbf::components::addition_mod_p<FieldType, stage,
                                                                     BaseField>;
                        using Negation_Mod_P =
                            typename bbf::components::negation_mod_p<FieldType, stage,
                                                                     BaseField>;
                        using Multiplication_Mod_P =
                            typename bbf::components::flexible_multiplication<FieldType, stage,
                                                                     BaseField>;

                        using Addition_Mod_N =
                            typename bbf::components::addition_mod_p<FieldType, stage,
                                                                     BaseField>;
                        using Negation_Mod_N =
                            typename bbf::components::negation_mod_p<FieldType, stage,
                                                                     BaseField>;
                        using Multiplication_Mod_N =
                            typename bbf::components::flexible_multiplication<FieldType, stage,
                                                                     BaseField>;

                        using Ec_Full_Add =
                            typename bbf::components::ec_full_add<FieldType, stage,
                                                                     BaseField>;
                        using Ec_Scalar_Mult =
                            typename bbf::components::ec_scalar_mult<FieldType, stage,
                                                                     BaseField>;
                        
                        
                        std::vector<TYPE> Z(num_chunks);
                        std::vector<TYPE> R(num_chunks);
                        std::vector<TYPE> S(num_chunks);
                        TYPE V;

                        std::vector<TYPE> C(9); // the c bits, c[0] = c[1]*...*c[8]
                        
                        std::vector<TYPE> I1(num_chunks);
                        std::vector<TYPE> I3(num_chunks);
                        std::vector<TYPE> I6(num_chunks);

                        std::vector<TYPE> I5(num_chunks);
                        std::vector<TYPE> D2(num_chunks);
                        std::vector<TYPE> I8(num_chunks);

                        std::vector<TYPE> CHUNKED_ZERO (num_chunks);
                        std::vector<TYPE> CHUNKED_ONE (num_chunks);
                        std::vector<TYPE> CHUNKED_BIT (num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                Z[i] = input_z[i];
                                R[i] = input_r[i];
                                S[i] = input_s[i];
                            }
                            V = input_v.data;

                            integral_type pow = 1;
                            SCALAR_TYPE z = 0, r = 0, s = 0;
                            
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                z += scalar_basic_integral_type(
                                          integral_type(input_z[i].data)) *
                                      pow;
                                r += scalar_basic_integral_type(
                                          integral_type(input_r[i].data)) *
                                      pow;
                                s += scalar_basic_integral_type(
                                          integral_type(input_s[i].data)) *
                                      pow;
                                pow <<= bit_size_chunk;
                            }
                            SCALAR_TYPE i1, i3, i6;
                            BASE_TYPE i5, d2, i8;

                            // the computations
                            C[1] = 1 - r.is_zero();
                            i1 = r.is_zero() ? 0 : r.inversed();

                            C[2] = (scalar_basic_integral_type(r.data) < n) ? 1 : 0;

                            C[3] = 1 - s.is_zero();
                            i3 = s.is_zero() ? 0 : s.inversed();

                            C[4] = (scalar_basic_integral_type(s.data) < m) ? 1 : 0;

                            BASE_TYPE x1 = scalar_basic_integral_type(r.data); // should we consider r + n also?
                            BASE_TYPE y1 = (x1*x1*x1 + a).is_square() ? (x1*x1*x1 + a).sqrt() : 1; // should be signaled as invalid signaure
                            if (base_basic_integral_type(y1.data) % 2 != scalar_basic_integral_type(V.data) % 2) {
                                y1 = -y1;
                            }
                            C[5] = (x1*x1*x1 + a - y1*y1).is_zero();
                            i5 = (x1*x1*x1 + a - y1*y1).is_zero() ? 0 : (x1*x1*x1 + a - y1*y1).inversed();

                            C[6] = (SCALAR_TYPE(base_basic_integral_type(x1.data)) - r).is_zero();
                            i6 = (SCALAR_TYPE(base_basic_integral_type(x1.data)) - r).is_zero() ?
                                0 : (SCALAR_TYPE(base_basic_integral_type(x1.data)) - r).inversed();

                            C[7] = ((base_basic_integral_type(y1.data) % 2) == (scalar_basic_integral_type(V.data) % 2));
                            d2 = (base_basic_integral_type(y1.data) + base_basic_integral_type(scalar_basic_integral_type(V.data)))/2;

                            SCALAR_TYPE u1 = r.is_zero() ? 2 : -z * r.inversed(), // if r = 0, the signature is invalid, but we
                                            u2 = r.is_zero() ? 2 : s * r.inversed();  // don't wanto to break the scalar multiplication
                            ec_point_value_type R = ec_point_value_type(scalar_basic_integral_type(x1.data), scalar_basic_integral_type(y1.data)),
                                                QA = G*u1 + R*u2;
                            C[8] = 1 - QA.is_zero();
                            i8 = QA.Y.is_zero() ? 0 :  QA.Y.inversed();

                            C[0] = C[1]*C[2]*C[3]*C[4]*C[5]*C[6]*C[7]*C[8];


                            auto PushScalarValueChunks = [&context_object,&row, sB,num_chunks](SCALAR_TYPE &x) {
                                std::vector<TYPE> X(num_chunks);
                                for(std::size_t i = 0; i < num_chunks; i++) {
                                    X[i] = TYPE(scalar_basic_integral_type(x.data) % sB);
                                    context_object.allocate(X[i], 0, row, column_type::constant);
                                    x /= sB;
                                    row++;
                                }
                                return X;
                            };

                            auto PushBaseValueChunks = [&context_object,&row,bB,num_chunks](BASE_TYPE &x) {
                                std::vector<TYPE> X(num_chunks);
                                for(std::size_t i = 0; i < num_chunks; i++) {
                                    X[i] = TYPE(base_basic_integral_type(x.data) % bB);
                                    context_object.allocate(X[i], 0, row, column_type::constant);
                                    x /= bB;
                                    row++;
                                }
                                return X;
                            };
                            I1 = PushScalarValueChunks(i1);
                            I3 = PushScalarValueChunks(i3);
                            I6 = PushScalarValueChunks(i6);

                            I5 = PushBaseValueChunks(i5);
                            D2 = PushBaseValueChunks(d2);
                            I8 = PushBaseValueChunks(i8);
                        }

                        std::cout << "here 1" << std::endl;
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            (i!= 0)?CHUNKED_ONE[i] = 0:CHUNKED_ONE[i] = 1;
                            CHUNKED_ZERO[i] = 0;
                            CHUNKED_BIT[i] = 0;
                            context_object.allocate(CHUNKED_ZERO[i],0,row,column_type::constant);
                            row++;
                            context_object.allocate(CHUNKED_ONE[i],0,row,column_type::constant);
                            row++;
                            context_object.allocate(CHUNKED_BIT[i],0,row,column_type::constant);
                            row++;
                        }
                   
                        auto RangeCheck = [&context_object, num_chunks, bit_size_chunk](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                        };
                        auto CheckModP = [&context_object, num_chunks, bit_size_chunk,zero](std::vector<TYPE> x,std::vector<TYPE> pp) {
                            Check_Mod_P rc = Check_Mod_P(context_object, x,pp,zero, num_chunks,
                                                         bit_size_chunk);
                        };
                        auto CarryOnAddition = [&context_object, num_chunks, bit_size_chunk](std::vector<TYPE> x ,std::vector<TYPE> y, bool make_link = true) {
                            Carry_On_addition ca = Carry_On_addition(context_object, x,y, num_chunks,
                                                         bit_size_chunk,make_link);
                            return ca;
                        };
                        auto ChoiceFunction = [&context_object, num_chunks, bit_size_chunk](TYPE q, std::vector<TYPE> x ,std::vector<TYPE> y) {
                            Choice_Function cf = Choice_Function(context_object, q,x,y, num_chunks,
                                                         bit_size_chunk);
                            return cf.r;
                        };

                        auto CopyConstrain = [this, num_chunks](std::vector<TYPE> x,
                                                                std::vector<TYPE> y) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(x[i], y[i]);
                            }
                        };

                        auto SingleCopyConstrain = [this, num_chunks](TYPE x,
                                                                TYPE y) {
                            copy_constrain(x, y);
                        };

                        auto NegModP = [&context_object,P,PP,CHUNKED_ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x) {
                            Negation_Mod_P t =
                                Negation_Mod_P(context_object, x, P,PP, CHUNKED_ZERO, num_chunks,
                                               bit_size_chunk);
                            return t.r;
                        };

                        auto AddModP = [&context_object,P,PP,CHUNKED_ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,std::vector<TYPE> y) {
                            Addition_Mod_P t =
                                Addition_Mod_P(context_object, x, y, P,PP, CHUNKED_ZERO, num_chunks,
                                               bit_size_chunk);
                            return t.r;
                        };

                        auto MultModP = [&context_object,P,PP,zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,std::vector<TYPE> y) {
                            Multiplication_Mod_P t =
                                Multiplication_Mod_P(context_object, x, y, P,PP, zero, num_chunks,
                                               bit_size_chunk);
                            return t.r;
                        };

                        auto NegModN = [&context_object,N,NP,zero, num_chunks,CHUNKED_ZERO,
                                        bit_size_chunk](std::vector<TYPE> x) {
                            Negation_Mod_N t =
                                Negation_Mod_N(context_object, x, N,NP, CHUNKED_ZERO, num_chunks,
                                               bit_size_chunk);
                            return t.r;
                        };

                        auto AddModN = [&context_object,N,NP,CHUNKED_ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,std::vector<TYPE> y) {
                            Addition_Mod_N t =
                                Addition_Mod_N(context_object, x, y,N,NP, CHUNKED_ZERO, num_chunks,
                                               bit_size_chunk);
                            return t.r;
                        };

                        auto MultModN = [&context_object,N,NP,zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,std::vector<TYPE> y) {
                            Multiplication_Mod_N t =
                                Multiplication_Mod_N(context_object, x, y, N,NP, zero, num_chunks,
                                               bit_size_chunk);
                            return t.r;
                        };

                        auto ECFullAdd = [&context_object, P,PP, CHUNKED_ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> xP,std::vector<TYPE> yP,std::vector<TYPE> xQ,std::vector<TYPE> yQ) {
                            Ec_Full_Add t =
                                Ec_Full_Add(context_object, xP,yP,xQ,yQ, P,PP, CHUNKED_ZERO, num_chunks,
                                               bit_size_chunk);
                            return t;
                        };

                        auto ECScalarMult = [&context_object, P,PP,N,MP, CHUNKED_ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> s,std::vector<TYPE> x,std::vector<TYPE> y) {
                            Ec_Scalar_Mult t =
                                Ec_Scalar_Mult(context_object, s,x,y,P,PP, N,MP, CHUNKED_ZERO, num_chunks,
                                               bit_size_chunk);
                            return t;
                        };

                        auto CopyChunks = [num_chunks](std::vector<TYPE> &from, std::vector<TYPE> &to) {
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                to[i] = from[i];
                            }
                        };
                        std::cout << "here 2" << std::endl;

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            allocate(I1[i]);

                            allocate(NP[i]);
                            allocate(R[i]);
                        }

                        // c1 = [r != 0]
                        std::cout << "here 3" << std::endl;
                        RangeCheck(I1);
                        std::cout << "here 4" << std::endl;
                        CheckModP(I1,NP); // CheckModN
                        std::cout << "here 5" << std::endl;
                        auto t0 = AddModN(R,CHUNKED_ZERO);
                        std::cout << "here 6" << std::endl;
                        auto t1 = MultModN(t0,I1);
                        std::cout << "here 7" << std::endl;
                        auto t2 = MultModN(t0,t1);
                        std::cout << "here 8" << std::endl;
                        CopyConstrain(t0,t2); // copy constrain t0 = t2
                        CHUNKED_BIT[0] = C[1];
                        CopyConstrain(t1,CHUNKED_BIT); // copy constrain t1 = (0,...,0,c1)
                        /*

                        // c2 = [r < n]
                        auto t3 = CheckModPOut(r_var,np_var); // CheckModN
                        auto t3p= ChoiceFunction(c_var[2],chunked_one,chunked_zero);
                        // copy constrain (0,...,0,t3) = t3p

                        // c3 = [s != 0]
                        RangeCheck(I3_var);
                        CheckModP(I3_var,np_var); // CheckModN
                        auto t4 = AddModN(s_var,chunked_zero);
                        auto t5 = MultModN(t4.z,I3_var);
                        auto t6 = MultModN(t4.z,t5.r);
                        // copy constrain t4 = t6
                        // copy constrain t5 = (0,...,0,c3)

                        // c4 = [s < (n-1)/2+1]
                        auto t7 = CheckModPOut(s_var,mp_var); // CheckModM
                        auto t7p= ChoiceFunction(c_var[4],chunked_one,chunked_zero);
                        // copy constrain (0,...,0,t7) = t7p

                        // c5 = [yR^2 = xR^3 + a]
                        RangeCheck(xR_var);
                        CheckModP(xR_var,pp_var);
                        RangeCheck(yR_var);
                        CheckModP(yR_var,pp_var);
                        auto t8 = MultModP(xR_var,xR_var);
                        auto t9 = MultModP(t8.r,xR_var);
                        auto t10= AddModP(t9.r,a_var);
                        auto t11= MultModP(yR_var,yR_var);
                        auto t12= NegModP(t11.r);
                        auto t13= AddModP(t10.z,t12.y);
                        RangeCheck(I5_var);
                        CheckModP(I5_var,pp_var);
                        auto t14= MultModP(t13.z,I5_var);
                        auto t14p=ChoiceFunction(c_var[5],chunked_one,chunked_zero);
                        auto t15= MultModP(t13.z,t14.r);
                        // copy constrain t13 = t15
                        // copy constrain t14 = t14p

                        // c6 = [xR = r (mod n)]
                        auto t16= AddModN(xR_var,chunked_zero);
                        auto t17= NegModN(t0.z);
                        auto t18= AddModN(t16.z,t17.y);
                        RangeCheck(I6_var);
                        CheckModP(I6_var,np_var); // CheckModN
                        auto t19= MultModN(t18.z,I6_var);
                        auto t20= MultModN(t18.z,t19.r);
                        // copy constrain t18 = t20
                        auto t21= ChoiceFunction(c_var[6],chunked_one,chunked_zero);
                        // copy constrain t19 = t21

                        // c7 = [yR = V (mod 2)]
                        chunked_bit[0] = v_var;
                        RangeCheck(chunked_bit);
                        auto d1 = CarryOnAddition(yR_var,chunked_bit);
                        // copy constrain d1.ck = 0
                        RangeCheck(d2_var);
                        auto d3 = CarryOnAddition(d2_var,chunked_one);
                        // copy constrain d3.ck = 0
                        RangeCheck(d3.z);
                        auto d4 = ChoiceFunction(c_var[7],d3.z,d2_var);
                        auto t22= CarryOnAddition(d2_var,d4.z);
                        // copy constrain t22.ck = 0
                        // copy constrain t22 = d1

                        // u1 r = -z (mod n)
                        RangeCheck(u1_var);
                        CheckModP(u1_var,np_var); // CheckModN
                        auto t23= MultModN(u1_var,t0.z);
                        auto t24= AddModN(z_var,chunked_zero);
                        auto t25= MultModN(t24t23.r,t25.r);
                        // copy constrain t26 = 0

                        // u2 r = s (mod n)
                        RangeCheck(u2_var);
                        CheckModP(u2_var,np_var); // CheckModN
                        auto t27= MultModN(u2_var,t0.z);
                        auto t28= Mu.z,t1.r);
                        auto t26= AddModN(ltModN(s_var,t1.r);
                        // copy constrain t27 = t28

                        // u1 * G
                        auto t29= ECScalarMult(u1_var,x_var,y_var);

                        // u2 * R
                        auto t30= ECScalarMult(u2_var,xR_var,yR_var);

                        // QA = u1*G + u2*R
                        auto t31= ECFullAdd(t29.xR,t29.yR,t30.xR,t30.yR);
                        // to assure the circuit doesn't break for invalid signatures we have to place the results
                        // from t31 to (xQA, yQA)
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            assignment.witness(component.W((i+1) % WA), start_row_index + (i+1)/WA) = var_value(assignment, t31.xR[i]);
                            assignment.witness(component.W((i+num_chunks+1) % WA), start_row_index + (i+num_chunks+1)/WA) =
                                var_value(assignment, t31.yR[i]);
                        }
                        base_value_type new_yQA = 0;
                        for(std::size_t i = num_chunks; i > 0; i--) {
                            new_yQA *= sB;
                            new_yQA += integral_type(var_value(assignment, t31.yR[i-1]).data);
                        }
                        if (QA.Y != new_yQA) { // we also have to adjust I8, c8 and c0 to agree with the updated yQA
                            base_value_type new_I8 = new_yQA.is_zero() ? 0 : new_yQA.inversed();
                            base_integral_type new_I8_int = base_integral_type(new_I8.data);

                            for(std::size_t i = 0; i < num_chunks; i++) {
                                assignment.witness(component.W((i+10*num_chunks+9) % WA), start_row_index + (i+10*num_chunks+9)/WA) =
                                    value_type(new_I8_int % bB);
                                new_I8_int /= bB;
                            }
                            // update c8
                            assignment.witness(component.W((2*num_chunks + 8) % WA), start_row_index + (2*num_chunks + 8)/WA) =
                                value_type(1 - new_yQA.is_zero());
                            // update c0
                            assignment.witness(component.W(0), start_row_index) = value_type(c[0] * (1 - new_yQA.is_zero()));
                        }
                        // copy constrain QA = t31

                        // c8 = [QA != O]
                        RangeCheck(I8_var);
                        CheckModP(I8_var,pp_var);
                        auto t32= MultModP(yQA_var,I8_var);
                        auto t33= MultModP(yQA_var,t32.r);
                        // copy constrain yQA = t33
                        // copy constrain t32 = (0,...,0,c8)

                        // c = c[1]*....*c[8]
                        chunked_bit[0] = c_var[1];
                        auto t34= ChoiceFunction(c_var[2],chunked_zero,chunked_bit);
                        auto t35= ChoiceFunction(c_var[3],chunked_zero,t34.z);
                        auto t36= ChoiceFunction(c_var[4],chunked_zero,t35.z);
                        auto t37= ChoiceFunction(c_var[5],chunked_zero,t36.z);
                        auto t38= ChoiceFunction(c_var[6],chunked_zero,t37.z);
                        auto t39= ChoiceFunction(c_var[7],chunked_zero,t38.z);
                        auto t40= ChoiceFunction(c_var[8],chunked_zero,t39.z);
                        // copy constrain t40 = (0,...,0,c) 
                        */   


                        for (int i = 0; i < num_chunks; ++i) {
                            //xR.push_back(XR[i]);
                            //yR.push_back(YR[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ecdsa_recovery
                    : public ecdsa_recovery<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas> {
                    using Base = ecdsa_recovery<
                        FieldType, stage,
                        crypto3::algebra::curves::pallas>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ecdsa_recovery
                    : public ecdsa_recovery<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta> {
                    using Base = ecdsa_recovery<
                        FieldType, stage,
                        crypto3::algebra::curves::vesta>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ECDSA_RECOVERY_HPP
