//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_FLEXIBLE_MULTIPLICATION_HPP
#define CRYPTO3_BBF_COMPONENTS_FLEXIBLE_MULTIPLICATION_HPP

#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <stdexcept> 
#include <variant>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Multiplication in non-native field with k-chunks and p > n, x * y - p * q - r = 0
                // Parameters: num_chunks = k, bit_size_chunk = b, T = k*b
                // native field module = n, non-native field module = p, pp = 2^T - p
                // NB: 2^T * n > p^2 + p
                // Input: x[0],..., x[k-1], y[0],..., y[k-1], p[0],..., p[k-1], pp[0],...,p[k-1]
                // Output: r[0],..., r[k-1]
                
                template<typename FieldType>
                struct flexible_multiplication_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> x;
                    std::vector<TYPE> y;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                };

                template<typename FieldType, GenerationStage stage>
                class flexible_multiplication : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using generic_component<FieldType, stage>::lookup;
                    using component_type = generic_component<FieldType, stage>;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  flexible_multiplication_raw_input<FieldType>,
                                                  std::tuple<>>::type;

                    using NonNativeFieldVariant = std::variant<crypto3::algebra::curves::pallas::base_field_type,
                                                               crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    std::vector<TYPE> inp_x;
                    std::vector<TYPE> inp_y;
                    std::vector<TYPE> inp_p;
                    std::vector<TYPE> inp_pp;
                    std::vector<TYPE> res;

                    static table_params get_minimal_requirements(NonNativeFieldVariant non_native_field, std::size_t num_chunks,
                                                                 std::size_t bit_size_chunk) {
                        //The 6 variables chunks fit in 2 rows, and there is a 3rd additionnal row available for the constraint values
                        std::size_t witness =3*num_chunks;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        //rows = 4096-1 so that lookup table is not too hard to fit and padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>,std::vector<TYPE>,std::vector<TYPE>,std::vector<TYPE>> form_input(context_type &context_object,                    
                                                                    raw_input_type raw_input,
                                                                    NonNativeFieldVariant non_native_field,
                                                                    std::size_t num_chunks,
                                                                    std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_y(num_chunks);
                        std::vector<TYPE> input_p(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);         
                        
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_x[i] = raw_input.x[i];
                                input_y[i] = raw_input.y[i];
                                input_p[i] = raw_input.p[i];
                                input_pp[i] = raw_input.pp[i];
                            }
                        }
                        for (std::size_t i = 0; i < num_chunks; i++)
                        {
                            context_object.allocate(input_x[i], 0, i, column_type::public_input);
                            context_object.allocate(input_y[i], 0, i+num_chunks, column_type::public_input);
                            context_object.allocate(input_p[i], 0, i+2*num_chunks, column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i+3*num_chunks, column_type::public_input);
                        }
                        return std::make_tuple(input_x,input_y,input_p,input_pp);
                    }

                    
                    flexible_multiplication(context_type &context_object, std::vector<TYPE> input_x, std::vector<TYPE> input_y,std::vector<TYPE> input_p,std::vector<TYPE> input_pp,
                                            NonNativeFieldVariant non_native_field,
                                            std::size_t num_chunks, std::size_t bit_size_chunk,
                                            bool make_links = true)
                        : generic_component<FieldType, stage>(context_object),
                          non_native_field(std::move(non_native_field)) {
                            

                        auto visit_result = std::visit([](auto&& field) {
                            using NonNativeFieldType = std::decay_t<decltype(field)>;
                            return typename NonNativeFieldType::extended_integral_type{};
                        }, non_native_field);

                        using foreign_extended_integral_type = decltype(visit_result); 
                        using native_integral_type = typename FieldType::integral_type;

                        using Check_Mod_P = typename bbf::components::check_mod_p<FieldType,stage>;
                        using Range_Check = typename bbf::components::range_check_multi<FieldType,stage>;
                        
                        std::vector<TYPE> X(num_chunks);
                        std::vector<TYPE> Y(num_chunks);
                        std::vector<TYPE> P(num_chunks);
                        std::vector<TYPE> PP(num_chunks);

                        std::vector<TYPE> Q(num_chunks);  
                        std::vector<TYPE> R(num_chunks);  

                        std::vector<TYPE> Z(num_chunks);
                        std::vector<TYPE> A(num_chunks);
                        std::vector<TYPE> B(2*(num_chunks - 2));

                        TYPE x_n;
                        TYPE y_n;
                        TYPE q_n;
                        TYPE r_n;
                        TYPE p_n;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            X[i] = input_x[i];
                            Y[i] = input_y[i];
                            P[i] = input_p[i];
                            PP[i] = input_pp[i];
                        }
                        foreign_extended_integral_type foreign_p = 0,
                                               foreign_x = 0,
                                               foreign_y = 0,
                                               pow = 1;
                        
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            foreign_x += foreign_extended_integral_type(native_integral_type(X[i].data)) * pow;
                            foreign_y += foreign_extended_integral_type(native_integral_type(Y[i].data)) * pow;
                            foreign_p += foreign_extended_integral_type(native_integral_type(P[i].data)) * pow;
                            pow <<= bit_size_chunk;
                        }

                        foreign_extended_integral_type foreign_r = (foreign_x * foreign_y) % foreign_p, // r = x*y % p
                                                        foreign_q = (foreign_x * foreign_y - foreign_r) / foreign_p; // q = (x*y - r)/p
                        foreign_extended_integral_type mask = (foreign_extended_integral_type(1) << bit_size_chunk) - 1;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            Q[j] = TYPE(foreign_q & mask);
                            R[j] = TYPE(foreign_r & mask);
                            foreign_q >>= bit_size_chunk;
                            foreign_r >>= bit_size_chunk;
                        }

                        }

                        for (std::size_t i = 0; i < num_chunks; ++i)
                        {
                            allocate(X[i]);
                            allocate(Y[i]);
                            allocate(PP[i]);
                            allocate(Q[i]);
                            allocate(R[i]);
                            allocate(P[i]);
                            }

                        native_integral_type pow = 1;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            x_n += X[j] * pow;
                            y_n += Y[j] * pow;
                            q_n += Q[j] * pow;
                            r_n += R[j] * pow;
                            p_n += P[j] * pow;
                            pow <<= bit_size_chunk;
                        }
                        allocate(x_n);
                        allocate(y_n);
                        allocate(q_n);
                        allocate(p_n);
                        allocate(r_n);
                        constrain(x_n * y_n - q_n * p_n - r_n);

                        // computation mod 2^T
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            Z[i] = TYPE(0);
                            for (std::size_t j = 0; j <= i; ++j) {
                                Z[i] += X[j] * Y[i-j] + PP[j] * Q[i-j];
                            }
                            allocate(Z[i]);
                        }

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            A[0] = Z[0] - R[0];
                            native_integral_type a_integral = native_integral_type(A[0].data) >> bit_size_chunk;
                            A[0] = TYPE(a_integral);
                            for (std::size_t i = 1; i < num_chunks; ++i) {
                                A[i] = (Z[i] + A[i-1] - R[i]);
                                a_integral = native_integral_type(A[i].data) >> bit_size_chunk;
                                A[i] = TYPE(a_integral);
                            }
                            for (std::size_t i = 0; i < num_chunks - 2; ++i) {
                                B[2*i] = TYPE(native_integral_type(A[i].data) & ((native_integral_type(1) << bit_size_chunk) - 1));
                                B[2*i + 1] =TYPE(native_integral_type(A[i].data) >> bit_size_chunk);
                            }
                        }

                        native_integral_type b_shift = native_integral_type(1) << bit_size_chunk;
                        allocate(A[0]);
                        constrain(A[0]*b_shift - Z[0] + R[0]);
                        for (std::size_t i = 1; i < num_chunks; ++i) {
                            allocate(A[i]);
                            constrain(A[i]*b_shift - Z[i] - A[i-1]+ R[i]);
                        }

                        for (std::size_t i = 0; i < num_chunks - 2; ++i) {
                            allocate(B[2*i]);
                            allocate(B[2*i+1]);
                            constrain(B[2*i] + B[2*i+1]*b_shift - A[i]);
                        }
                                                
                        Check_Mod_P c1 = Check_Mod_P(context_object, R,PP,num_chunks,bit_size_chunk,false,make_links);
                        Check_Mod_P c2 = Check_Mod_P(context_object, Q,PP,num_chunks,bit_size_chunk,false,make_links);

                        //In original flexible_multiplication
                        //Range_Check rc = Range_Check(context_object, R,num_chunks,bit_size_chunk,make_links);

                        //In ECDSA implementation doc
                        Range_Check rc = Range_Check(context_object, B,num_chunks,bit_size_chunk,make_links);

                        //Starting b\n
                        if(num_chunks>2){
                            std::vector<TYPE> B_X[2 * (num_chunks > 2)]; 
                            for (int i = 0; i < 2 * (num_chunks > 2); ++i) {
                                B_X[i].resize(num_chunks);

                                for (std::size_t j = 0; j < num_chunks - 2; ++j) {
                                    B_X[i].push_back(B[j + i * (num_chunks - 2)]);
                                    allocate(B_X[i][j]);
                                    }

                                 B_X[i].push_back(X[num_chunks - 3]);    
                                 B_X[i].push_back(X[num_chunks - 3]);
                                allocate(B_X[i][num_chunks-2]);
                                allocate(B_X[i][num_chunks-1]);
                                Range_Check(context_object, B_X[i],num_chunks,bit_size_chunk,make_links);
                            }    
                        }                 

                        if (make_links) {
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            copy_constrain(X[i], input_x[i]);
                            copy_constrain(Y[i], input_y[i]);
                            copy_constrain(P[i], input_p[i]);
                            copy_constrain(PP[i], input_pp[i]);
                            }
                        }

                        for (int i = 0; i < num_chunks; ++i) {
                            inp_x.push_back(input_x[i]);
                            inp_y.push_back(input_y[i]);
                            inp_p.push_back(input_p[i]);
                            inp_pp.push_back(input_pp[i]);
                        }
                        for (int i = 0; i < num_chunks; ++i) {
                            res.push_back(R[i]);
                        }
                    }
                    
                  private:
                    NonNativeFieldVariant non_native_field;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_FLEXIBLE_MULTIPLICATION_HPP
