//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for PLONK BBF bbf_tester class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_TESTER_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_TESTER_COMPONENT_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/bbf/is_zero.hpp>
// #include <nil/blueprint/bbf/choice_function.hpp>
// #include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/blueprint/bbf/useless.hpp>


namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType>
            struct bbf_tester_raw_input {
                using TYPE = typename FieldType::value_type;

                TYPE X, Q;
                std::array<TYPE,3> CX;
                std::array<TYPE,3> CY;
            };

            template<typename FieldType, GenerationStage stage>
            class bbf_tester : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

                public:
                    using typename generic_component<FieldType,stage>::TYPE;
                    using typename generic_component<FieldType,stage>::table_params;
                    using raw_input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                               bbf_tester_raw_input<FieldType>,std::tuple<>>::type;

                    TYPE input;
                    TYPE res;

                    static table_params get_minimal_requirements() {
                        return {13,0,1,8191}; // W, PI, C, rows (so many rows, because carry_on_addition has a built-in range check
                    }

                    static std::tuple<TYPE, TYPE, std::array<TYPE,3>, std::array<TYPE,3>>
                    form_input(context_type &context_object, raw_input_type raw_input) {
                        TYPE X, Q;
                        std::array<TYPE,3> CX;
                        std::array<TYPE,3> CY;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            X = raw_input.X;
                            Q = raw_input.Q;
                            std::copy(std::begin(raw_input.CX), std::end(raw_input.CX), std::begin(CX));
                            std::copy(std::begin(raw_input.CY), std::end(raw_input.CY), std::begin(CY));
                        }
                        context_object.allocate(X,0,0,column_type::public_input);
                        context_object.allocate(Q,0,1,column_type::public_input);
                        for(std::size_t i = 0; i < 3; i++) {
                            context_object.allocate(CX[i],0,2+i,column_type::public_input);
                            context_object.allocate(CY[i],0,5+i,column_type::public_input);
                        }
                        return std::make_tuple(X,Q,CX,CY);
                    }

                    bbf_tester(context_type &context_object,
                            TYPE X, TYPE Q, std::array<TYPE,3> CX, std::array<TYPE,3> CY,
                            bool make_links = true) :
                        generic_component<FieldType,stage>(context_object) {

                        using Is_Zero = is_zero<FieldType, stage>;
                        // using Choice_Function = choice_function<FieldType, stage, 3>;
                        // using Carry_On_Addition = carry_on_addition<FieldType, stage, 3, 16>;
                        using Useless = useless<FieldType, stage>;

                        TYPE const_test = 5;
                        allocate(const_test,0,0,column_type::constant);

                        Is_Zero(context_object, X, make_links); // make_links delegated to subcomponent

                        // std::vector<std::size_t> ct2_area = {2,3,4,5};
                        // context_type ct2 = context_object.subcontext(ct2_area,0,4);
                        // auto c2 = Choice_Function(ct2,Q,CX,CY, make_links); // make_links delegated to subcomponent

                        // std::vector<std::size_t> ct3_area = {7,8,9,10,11};
                        // context_type ct3 = context_object.subcontext(ct3_area,0,4);
                        // auto c3 = Carry_On_Addition(ct3, CX, CY, make_links);

                        std::vector<std::size_t> ct4_area = {12};
                        context_type ct4 = context_object.subcontext(ct4_area,1,4);
                        auto c4 = Useless(ct4);
                    }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_TESTER_COMPONENT_HPP
