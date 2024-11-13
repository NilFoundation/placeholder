//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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
// @file Declaration of interfaces for PLONK BBF context & generic component classes
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_BBF_GATE_OPTIMIZER_HPP
#define CRYPTO3_BLUEPRINT_BBF_GATE_OPTIMIZER_HPP

#include <functional>
#include <sstream>
#include <vector>
#include <unordered_map>

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/blueprint/bbf/expresion_visitor_helpers.hpp>
#include <nil/blueprint/bbf/allocation_log.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/bbf/row_selector.hpp>
#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType>
            class optimized_gates {
            public:
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using lookup_input_constraints_type = crypto3::zk::snark::lookup_input_constraints<FieldType>;
                using lookup_constraint_type = std::pair<std::string, lookup_input_constraints_type>;

                // Here size_t is the index of the selector from 'selectors_'.
                std::vector<std::pair<std::vector<constraint_type, size_t>> constraint_list;
                std::vector<plonk_copy_constraint> copy_constraints;
                std::map<std::string, std::pair<std::vector<std::size_t>, size_t>> dynamic_lookup_tables;
                std::vector<std::pair<std::vector<lookup_constraint_type>, size_t> lookup_constraints;

                // We will map each selector to the corresponding number.
                std::vector<row_selector<>> selectors_;
            };

            template<typename FieldType>
            class gates_optimizer {
            public:
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using context_type = context<FieldType, GenerationStage::CONSTRAINTS>;

                // We expect you to move context into this object, and stop using it.
                gates_optimizer(context_type&& c)
                    : context_(std::make_unique<context_type>(std::move(c))) {
                }

                /** Tries to shift the constraints to left or right. 
                 *  \param[in] shift - Must be +-1, we cannot shift more than by 1.
                 */
                std::optional<std::pair<row_selector<>, std::vector<constraint_type>>> try_shift_constraints(
                    const std::vector<constraint_type> constraints, const row_selector<>& selector, size_t shift) {
                    if (shift != -1 && shift != 1)
                        return nullptr;
                    if (shift == -1 && selector[0])
                        return nullptr;
                    if (shift == 1 && selector[selector.size() - 1])
                        return nullptr;

                    row_selector<> shifted_selector = selector;
                    if (shift == 1)
                        shifted_selector >>= 1;
                    else
                        shifted_selector <<= 1;

                    // try to shift the constraints.
                    std::optional<std::vector<constraint_type>> shifted_constraints = shift_constraints(constraints, shift); 
                    if (!shifted_constraints)
                        return nullptr;
                    return {shifted_selector, *shifted_constraints};
                }

                /** Tries to shift the lookup constraints to left or right. 
                 *  \param[in] shift - Must be +-1, we cannot shift more than by 1.
                 */
                std::optional<std::pair<row_selector<>, std::vector<typename context_type::lookup_constraint_type>>>
                try_shift_lookup_constraints(
                        const std::vector<typename context_type::lookup_constraint_type>& lookup_list,
                        const row_selector<>& selector, size_t shift) {
                    if (shift != -1 && shift != 1)
                        return nullptr;
                    if (shift == -1 && selector[0])
                        return nullptr;
                    if (shift == 1 && selector[selector.size() - 1])
                        return nullptr;

                    row_selector<> shifted_selector = selector;
                    if (shift == 1)
                        shifted_selector >>= 1;
                    else
                        shifted_selector <<= 1;

                    // try to shift the constraints.
                    std::optional<std::vector<typename context_type::lookup_constraint_type>> shifted_constraints =
                        shift_lookup_constraints(lookup_list, shift); 
                    if (!shifted_constraints)
                        return nullptr;
                    return {shifted_selector, *shifted_constraints};
                }

                optimized_gates<FieldType> optimize_gates() {
                    optimized_gates<FieldType> result;

                    // Take everything out of context, and erase the context to free its memory.
                    std::unordered_map<row_selector<>, std::vector<constraint_type>> constraint_list = context_.get_constraints();
                    std::map<std::string, std::pair<std::vector<std::size_t>, row_selector<>>>
                        dynamic_lookup_tables = ct.get_dynamic_lookup_tables();
                    std::vector<plonk_copy_constraint> copy_constraints = ct.get_copy_constraints();
                    std::unordered_map<row_selector<>, std::vector<typename context_type::lookup_constraint_type>>
                        lookup_constraints = ct.get_lookup_constraints();
                    context_.reset(nullptr);

                    optimize_selectors_by_shifting(constraint_list, lookup_constraints);

                    for (const auto& [name, area] : dynamic_lookup_tables) {
                        const auto& selector = area.second; 
                        add_selector(selector);
                    }

                    for (const auto& [row_list, lookup_list] : lookup_constraints) {
                        add_selector(row_list);
                    }
 
                    return result;
                }

                size_t add_selector(const row_selector<>& selector) {
                    auto iter = selectors_.find(selector);
                    if (iter == selectors_.end()) {
                        selectors_.insert({selector, next_selector_id_});
                        return next_selector_id_++;
                    }
                    return iter->second;
                }

            private:

                /** This function tries to reduce the number of selectors required by rotating the constraints by +-1.
                 *  \param[in, out] constraint_list - Gate constraints.
                 *  \param[in, out] lookup_constraints - Lookup constraints.
                 */
                void optimize_selectors_by_shifting(
                        std::unordered_map<row_selector<>, std::vector<constraint_type>>& constraint_list,
                        std::unordered_map<row_selector<>, std::vector<typename context_type::lookup_constraint_type>>& lookup_constraints) {
                    auto shift_optimize = [&constraint_list](size_t shift) {
                        // Check if some gate constraint can be shifted to match the selector of another one.
                        for (auto& [selector, constraints]: constraint_list) {
                            if (constraints.empty())
                                continue;

                            // Consider shifting left, if that would help.
                            std::optional<std::pair<row_selector<>, std::vector<constraint_type>>> shifted = try_shift_constraints(
                                constraints, selector, shift);
                            if (shifted) {
                                auto iter = constraint_list.find(shifted->first);
                                if (iter != constraint_list.end()) {
                                    iter->second.insert(iter->second.end(), shifted->second.begin(), shifted->second.end());
                                    // We don't want to erase a key in 'constraint_list' while iterating over it, so just
                                    // drop the constraints for now.
                                    constraints.resize(0);
                                    continue;
                                }
                            }
                        }
                        // Check if constraints in the lookup constraints can be shifted to match another one, or some 
                        // selector in the gate constraints.
                        for (const auto& [row_list, lookup_list] : lookup_constraints) {
                            
                        }
                    };

                    shift_optimize(-1);
                    shift_optimize(+1);
                }

                std::unique_ptr<context<FieldType, GenerationStage::CONSTRAINTS>> context_;

                // We will map each selector to the corresponding number.
                std::unordered_map<row_selector<>, size_t> selectors_;
                size_t next_selector_id_ = 0;
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_BBF_GATE_OPTIMIZER_HPP
