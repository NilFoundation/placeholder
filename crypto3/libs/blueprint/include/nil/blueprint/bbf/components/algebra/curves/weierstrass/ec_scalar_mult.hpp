//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoinecyr@nil.foundation>
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
// @file Declaration of interfaces for scalar multiplication of EC points over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_EC_SCALAR_MULT_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_SCALAR_MULT_ECDSA_HPP

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/blueprint/bbf/components/algebra/fields/non_native/negation_mod_p.hpp>
#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/blueprint/bbf/components/detail/choice_function.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_double.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_incomplete_add.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_two_t_plus_q.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
            // Parameters: num_chunks = k, bit_size_chunk = b
            // For scalar s and point input_p = (x,y), input_p != O, s != 0 (to be corrected?)
            // from an elliptic curve over F[p]
            // computes R = s × input_p (scalar product for EC point)
            // Expects input as k-chunked values with b bits per chunk
            // Other values: p' = 2^(kb) - p, n = size of EC group, m = (n-1)/2, m' = 2^(kb) - m
            // Input: s[0],...,s[k-1], x[0],...,x[k-1], y[0],...,y[k-1],
            //      p[0],...,p[k-1], pp[0], ..., pp[k-1], n[0],...,n[k-1], mp[0],...,mp[k-1], 0
            // (expects zero constant as input)
            // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]
            //
                template<typename FieldType>
                struct ec_scalar_mult_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> s;
                    std::vector<TYPE> x;
                    std::vector<TYPE> y;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                    std::vector<TYPE> n;
                    std::vector<TYPE> mp;
                    TYPE zero;
                };

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class ec_scalar_mult : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  ec_scalar_mult_raw_input<FieldType>,
                                                  std::tuple<>>::type;

                  public:
                    std::vector<TYPE> inp_s;
                    std::vector<TYPE> inp_x;
                    std::vector<TYPE> inp_y;
                    std::vector<TYPE> inp_p;
                    std::vector<TYPE> inp_pp;
                    std::vector<TYPE> inp_n;
                    std::vector<TYPE> inp_mp;
                    std::vector<TYPE> res_xR;
                    std::vector<TYPE> res_yR;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                            std::cout<<"table requirements" <<std::endl;
                        std::size_t witness = 100 * num_chunks + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        // rows = 4096-1 so that lookup table is not too hard to fit and
                        // padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>, std::vector<TYPE>,
                                      std::vector<TYPE>, std::vector<TYPE>,
                                      std::vector<TYPE>, std::vector<TYPE>, 
                                      std::vector<TYPE>, TYPE>
                    form_input(context_type& context_object, raw_input_type raw_input,
                               std::size_t num_chunks, std::size_t bit_size_chunk) {
                                std::cout<<"form input" <<std::endl;
                        std::vector<TYPE> input_s(num_chunks);
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_y(num_chunks);
                        std::vector<TYPE> input_n(num_chunks);
                        std::vector<TYPE> input_mp(num_chunks);
                        std::vector<TYPE> input_p(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);
                        TYPE input_zero;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_s[i] = raw_input.s[i];
                                input_x[i] = raw_input.x[i];
                                input_y[i] = raw_input.y[i];
                                input_p[i] = raw_input.p[i];
                                input_pp[i] = raw_input.pp[i];
                                input_n[i] = raw_input.n[i];
                                input_mp[i] = raw_input.mp[i];
                            }
                            input_zero = raw_input.zero;
                        }
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            context_object.allocate(input_s[i], 0, i,
                                                    column_type::public_input);
                            context_object.allocate(input_x[i], 0, i + num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_y[i], 0, i + 2 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_p[i], 0, i + 3 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i + 4 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_n[i], 0, i + 5 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_mp[i], 0, i + 6 * num_chunks,
                                                    column_type::public_input);
                        }
                        context_object.allocate(input_zero, 0, 7 * num_chunks,
                                                column_type::public_input);
                        return std::make_tuple(input_s, input_x, input_y, input_p, 
                                               input_pp, input_n, input_mp, input_zero);
                    }

                    ec_scalar_mult(context_type& context_object,
                                      std::vector<TYPE> input_s,
                                      std::vector<TYPE> input_x,
                                      std::vector<TYPE> input_y,
                                      std::vector<TYPE> input_p,
                                      std::vector<TYPE> input_pp, 
                                      std::vector<TYPE> input_n,
                                      std::vector<TYPE> input_mp,
                                      TYPE input_zero,
                                      std::size_t num_chunks, std::size_t bit_size_chunk,
                                      bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                            std::cout<<"ec_scalar_mult" <<std::endl;
                        using integral_type = typename FieldType::integral_type;
                        using NON_NATIVE_TYPE = typename NonNativeFieldType::value_type;
                        using non_native_integral_type =
                            typename NonNativeFieldType::integral_type;

                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Carry_On_addition =
                            typename bbf::components::carry_on_addition<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;
                        using Negation_Mod_P =
                            typename bbf::components::negation_mod_p<FieldType, stage,
                                                                     NonNativeFieldType>;
                        using Ec_Double =
                            typename bbf::components::ec_double<FieldType, stage,
                                                                     NonNativeFieldType>;
                        using Ec_Incomplete_Add =
                            typename bbf::components::ec_incomplete_add<FieldType, stage,
                                                                     NonNativeFieldType>;
                        using Ec_Two_T_Plus_Q =
                            typename bbf::components::ec_two_t_plus_q<FieldType, stage,
                                                                     NonNativeFieldType>;
                        
                        std::cout<<"ec_scalar_mult 1" <<std::endl;
                        
                        std::vector<TYPE> EXTEND_BIT_ARRAY(num_chunks,input_zero);
                        
                        const std::size_t L = bit_size_chunk*num_chunks + (bit_size_chunk*num_chunks % 2), // if odd, then +1. Thus L is always even
                                  Q = L/2;

                        std::vector<std::vector<TYPE>> C(Q, std::vector<TYPE>(num_chunks));
                        std::vector<TYPE> SP(num_chunks);
                        std::vector<TYPE> CP(Q);
                        std::vector<TYPE> CPP(Q);

                        std::vector<std::vector<TYPE>> Xi(Q, std::vector<TYPE>(num_chunks));
                        std::vector<std::vector<TYPE>> Yi(Q, std::vector<TYPE>(num_chunks));
                        std::vector<std::vector<TYPE>> XPi(Q, std::vector<TYPE>(num_chunks));
                        std::vector<std::vector<TYPE>> YPi(Q, std::vector<TYPE>(num_chunks));
                        std::cout<<"ec_scalar_mult 2" <<std::endl;
                        //make_links = false for EXTEND_BIT_ARRAY


                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type pow = 1;
                            non_native_integral_type s = 0, n = 0, mp = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                s += non_native_integral_type(
                                          integral_type(input_s[i].data)) *
                                      pow;
                                n += non_native_integral_type(
                                          integral_type(input_n[i].data)) *
                                      pow;
                                mp += non_native_integral_type(
                                          integral_type(input_mp[i].data)) *
                                      pow;
                                pow <<= bit_size_chunk;
                            }

                            non_native_integral_type sp = n - s,
                                            C = (s > (n-1)/2) ? sp : s;
                            
                            // binary expansion of C, LSB
                            for(std::size_t i = 0; i < L; i++) {
                                if (i % 2) { // if i is odd
                                    CP[i/2] = C % 2;
                                } else {
                                    CPP[i/2] = C % 2;
                                }
                                C /= 2;
                            }

                            auto base = [num_chunks, bit_size_chunk](NON_NATIVE_TYPE x) {
                                std::vector<TYPE> res(num_chunks);
                                non_native_integral_type mask =
                                    (non_native_integral_type(1) << bit_size_chunk) - 1;
                                non_native_integral_type x_value =
                                    non_native_integral_type(x.data);
                                for (std::size_t i = 0; i < num_chunks; i++) {
                                    res[i] = TYPE(x_value & mask);
                                    x_value >>= bit_size_chunk;
                                }
                                return res;
                            };

                            SP = base(sp);
                        }

                        std::cout<<"ec_scalar_mult 3" <<std::endl;
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(CP[i]);
                            allocate(CPP[i]);
                            allocate(SP[i]);
                            for (std::size_t j = 0; j < Q; ++j){
                                allocate(C[j][i]);
                                allocate(Xi[j][i]);
                                allocate(Yi[j][i]);
                                allocate(XPi[j][i]);
                                allocate(YPi[j][i]);
                            }
                        }
                        std::cout<<"ec_scalar_mult 4" <<std::endl;

                        auto RangeCheck = [&context_object, num_chunks, bit_size_chunk](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                        };
                        auto CarryOnAddition = [&context_object, num_chunks, bit_size_chunk](std::vector<TYPE> x ,std::vector<TYPE> y) {
                            Carry_On_addition ca = Carry_On_addition(context_object, x,y, num_chunks,
                                                         bit_size_chunk);
                            return ca;
                        };
                        auto ChoiceFunction = [&context_object, num_chunks, bit_size_chunk](TYPE q, std::vector<TYPE> x ,std::vector<TYPE> y) {
                            Choice_Function cf = Choice_Function(context_object, q,x,y, num_chunks,
                                                         bit_size_chunk);
                            return cf.res_r;
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

                        auto NegModP = [&context_object, input_p, input_pp, input_zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x) {
                            Negation_Mod_P t =
                                Negation_Mod_P(context_object, x, input_p, input_pp, input_zero, num_chunks,
                                               bit_size_chunk);
                            return t.res_r;
                        };

                        auto ECDouble = [&context_object, input_p, input_pp, input_zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> xQ,std::vector<TYPE> yQ) {
                            Ec_Double t =
                                Ec_Double(context_object, xQ,yQ, input_p, input_pp, input_zero, num_chunks,
                                               bit_size_chunk);
                            return t;
                        };

                        auto ECIncompleteAdd = [&context_object, input_p, input_pp, input_zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> xP,std::vector<TYPE> yP,std::vector<TYPE> xQ,std::vector<TYPE> yQ) {
                            Ec_Incomplete_Add t =
                                Ec_Incomplete_Add(context_object, xP,yP,xQ,yQ, input_p, input_pp, input_zero, num_chunks,
                                               bit_size_chunk);
                            return t;
                        };

                        auto ECTwoTPlusQ = [&context_object, input_p, input_pp, input_zero, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> xt,std::vector<TYPE> yt,std::vector<TYPE> xQ,std::vector<TYPE> yQ) {
                            Ec_Two_T_Plus_Q t =
                                Ec_Two_T_Plus_Q(context_object, xt,yt,xQ,yQ, input_p, input_pp, input_zero, num_chunks,
                                               bit_size_chunk);
                            return t;
                        };

                        auto CopyChunks = [num_chunks](std::vector<TYPE> from, std::vector<TYPE> to) {
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                to[i] = from[i];
                            }
                        };
                        std::cout<<"ec_scalar_mult 5" <<std::endl;

                        // Part I : adjusting the scalar and the point
                        auto t = CarryOnAddition(input_s,input_mp);
                        std::cout<<"ec_scalar_mult 5.01" <<std::endl;
                        RangeCheck(t.res_r);
                        std::cout<<"ec_scalar_mult 5.02" <<std::endl;
                        auto alt_n = CarryOnAddition(input_s,SP);
                        std::cout<<"ec_scalar_mult 5.1" <<std::endl;
                        CopyConstrain(alt_n.res_r,input_n);
                        std::cout<<"ec_scalar_mult 5.2" <<std::endl;
                        SingleCopyConstrain(alt_n.res_c,input_zero);
                        std::cout<<"ec_scalar_mult 5.3" <<std::endl;
                        RangeCheck(SP);
                        auto total_C = ChoiceFunction(t.res_c,input_s,SP); // labeled simply C without indices on the Notion page
                        auto y_minus = NegModP(input_y);
                        auto y1 = ChoiceFunction(t.res_c,input_y,y_minus);
                        // Assert s × (x,y) = C × (x,y1)
                        std::cout<<"ec_scalar_mult 6" <<std::endl;

                        // Part II : precompute
                        auto p2 = ECDouble(input_x,y1);
                        auto p3 = ECIncompleteAdd(input_x,y1,p2.res_xR,p2.res_yR);
                        auto y_minus1 = ChoiceFunction(t.res_c,y_minus,input_y);
                        auto y_minus3 = NegModP(p3.res_yR);
                        std::cout<<"ec_scalar_mult 7" <<std::endl;

                        // Part III : the main loop
                        for(std::size_t i = Q-1; i > 0; i--) {
                            if (i < Q-1) {
                                auto Pp_temp = ECDouble(Xi[i+1],Yi[i+1]);
                                CopyChunks(Pp_temp.res_xR, XPi[i+1]);
                                CopyChunks(Pp_temp.res_yR, YPi[i+1]);

                                auto C_p = CarryOnAddition(C[i+1],C[i+1]);
                                RangeCheck(C_p.res_r);
                                SingleCopyConstrain(C_p.res_c,input_zero);

                                EXTEND_BIT_ARRAY[0] = CP[i];
                                auto C_pp = CarryOnAddition(C_p.res_r,EXTEND_BIT_ARRAY);
                                RangeCheck(C_pp.res_r);
                                SingleCopyConstrain(C_pp.res_c,input_zero);
                                CopyChunks(C_pp.res_r,C[i]);
                            } else {
                                EXTEND_BIT_ARRAY[0] = CP[i];
                                CopyChunks(EXTEND_BIT_ARRAY,C[i]);
                            }
                            auto C_ppp = CarryOnAddition(C[i],C[i]);
                            RangeCheck(C_ppp.res_r);
                            SingleCopyConstrain(C_ppp.res_c,input_zero);

                            EXTEND_BIT_ARRAY[0] = CPP[i];
                            auto C_temp = CarryOnAddition(C_ppp.res_r,EXTEND_BIT_ARRAY);
                            SingleCopyConstrain(C_temp.res_c,input_zero);
                            CopyChunks(C_temp.res_r,C[i]);
                            RangeCheck(C[i]);

                            auto xi_p = ChoiceFunction(CP[i],p3.res_xR,input_x);
                            auto xi_pp = ChoiceFunction(CP[i],input_x,p3.res_xR);
                            auto xi = ChoiceFunction(CPP[i],xi_p,xi_pp);
                            auto eta_p = ChoiceFunction(CP[i],y_minus3,y1);
                            auto eta_pp = ChoiceFunction(CP[i],y_minus1,p3.res_yR);
                            auto eta = ChoiceFunction(CPP[i],eta_p,eta_pp);
                            auto P_temp = ECTwoTPlusQ((i < Q-1) ? XPi[i+1] : p2.res_xR,(i < Q-1)? YPi[i+1] : p2.res_yR, xi, eta);
                            CopyChunks(P_temp.res_xR,Xi[i]);
                            CopyChunks(P_temp.res_yR,Yi[i]);
                        }
                        std::cout<<"ec_scalar_mult 8" <<std::endl;
                        // post-loop computations
                        auto C_p = CarryOnAddition(C[1],C[1]);
                        RangeCheck(C_p.res_r);
                        SingleCopyConstrain(C_p.res_c,input_zero);

                        EXTEND_BIT_ARRAY[0] = CP[0];
                        auto C_pp = CarryOnAddition(C_p.res_r,EXTEND_BIT_ARRAY);
                        RangeCheck(C_pp.res_r);
                        SingleCopyConstrain(C_pp.res_c,input_zero);

                        auto C_ppp = CarryOnAddition(C_pp.res_r,C_pp.res_r);
                        RangeCheck(C_ppp.res_r);
                        SingleCopyConstrain(C_ppp.res_c,input_zero);

                        EXTEND_BIT_ARRAY[0] = CPP[0];
                        auto C_temp = CarryOnAddition(C_ppp.res_r,EXTEND_BIT_ARRAY);

                        CopyConstrain(total_C,C_temp.res_r);
                        SingleCopyConstrain(C_temp.res_c,input_zero);
                        auto eta = ChoiceFunction(CP[0],y_minus1,y1);
                        auto Pp_pre = ECDouble(Xi[1],Yi[1]);
                        auto Pp_temp = ECIncompleteAdd(Pp_pre.res_xR,Pp_pre.res_yR,input_x,eta);
                        auto Ppp_temp = ECIncompleteAdd(Pp_temp.res_xR,Pp_temp.res_yR,input_x,y_minus1);
                        // this ^^^ will fail for 0 scalar (needs almost full addition)
                        auto XR = ChoiceFunction(CPP[0],Ppp_temp.res_xR,Pp_temp.res_xR);
                        auto YR = ChoiceFunction(CPP[0],Ppp_temp.res_yR,Pp_temp.res_yR);
                        std::cout<<"ec_scalar_mult 9" <<std::endl;

                        for (int i = 0; i < num_chunks; ++i) {
                            inp_s.push_back(input_s[i]);
                            inp_x.push_back(input_x[i]);
                            inp_y.push_back(input_y[i]);
                            inp_p.push_back(input_p[i]);
                            inp_pp.push_back(input_pp[i]);
                            inp_n.push_back(input_n[i]);
                            inp_mp.push_back(input_mp[i]);

                            res_xR.push_back(XR[i]);
                            res_yR.push_back(YR[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ec_scalar_mult
                    : public ec_scalar_mult<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base = ec_scalar_mult<
                        FieldType, stage,
                        crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ec_scalar_mult
                    : public ec_scalar_mult<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta::base_field_type> {
                    using Base = ec_scalar_mult<
                        FieldType, stage,
                        crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_SCALAR_MULT_ECDSA_HPP
