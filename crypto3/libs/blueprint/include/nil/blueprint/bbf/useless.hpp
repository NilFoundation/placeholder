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
// @file Declaration of interfaces for PLONK BBF useless component class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_USELESS_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_USELESS_COMPONENT_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
//#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, GenerationStage stage>
            class useless : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
                using generic_component<FieldType, stage>::multi_lookup_table;

                public:
                    using typename generic_component<FieldType,stage>::TYPE;

                public:
                    useless(context_type &context_object, bool make_links = true) :
                        generic_component<FieldType,stage>(context_object) {

                        TYPE X[3];
                        TYPE Y[3];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            X[0] = 3; X[1] = 14; X[2] = 15;
                            Y[0] = 14; Y[1] = 17;  Y[2] = 3;
                        }

                        allocate(X[0],0,0);
                        allocate(X[1],0,1);
                        allocate(X[2],0,2);

                        allocate(Y[0],1,0);
                        allocate(Y[1],1,1);
                        allocate(Y[2],1,2);

                        std::vector<std::size_t> lookup_cols = {0};
                        std::vector<std::vector<std::size_t>> multi_lookup_cols = {{0},{1}};
                        lookup_table("dummy_dynamic",lookup_cols,0,3);
                        lookup_table("dummy_dynamic2",lookup_cols,1,1);
                        multi_lookup_table("multi_dummy_dynamic",multi_lookup_cols, 1, 2);
                        lookup(X[0],"dummy_dynamic");
                        lookup(X[0],"multi_dummy_dynamic");
                        lookup(Y[0],"multi_dummy_dynamic");
                    };
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_USELESS_COMPONENT_HPP
