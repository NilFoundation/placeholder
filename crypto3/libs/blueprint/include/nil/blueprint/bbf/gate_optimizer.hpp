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
                using context_type = context<FieldType, GenerationStage::CONSTRAINTS>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using lookup_input_constraints_type = crypto3::zk::snark::lookup_input_constraints<FieldType>;
                using lookup_constraint_type = std::pair<std::string, lookup_input_constraints_type>;

                // Here size_t is the index of the selector from 'selectors_'.
                std::unordered_map<size_t, std::vector<constraint_type>> constraint_list;
                std::vector<plonk_copy_constraint> copy_constraints;
                std::map<std::string, std::pair<std::vector<std::size_t>, size_t>> dynamic_lookup_tables;
                std::unordered_map<size_t, std::vector<typename context_type::lookup_constraint_type>> lookup_constraints;

                // We will map each selector to the corresponding id.
                std::unordered_map<row_selector<>, size_t> selectors_;

                size_t add_selector(const row_selector<>& selector) {
                    auto iter = selectors_.find(selector);
                    size_t next_selector_id = selectors_.size();
                    if (iter == selectors_.end()) {
                        selectors_.insert({selector, next_selector_id});
                        return next_selector_id;
                    }
                    return iter->second;
                }

                void add_constraints(size_t selector_id, const std::vector<constraint_type>& constraints) {
                    auto iter = constraint_list.find(selector_id);
                    if (iter != constraint_list.end()) {
                        iter->second.insert(
                            iter->second.end(),
                            constraints.begin(),
                            constraints.end());
                    } else {
                        constraint_list.insert({selector_id, constraints});
                    }
                }

                void add_lookup_constraints(
                        size_t selector_id,
                        const std::vector<typename context_type::lookup_constraint_type>& lookup_list) {
                    auto iter = lookup_constraints.find(selector_id);
                    if (iter != lookup_constraints.end()) {
                        iter->second.insert(
                            iter->second.end(),
                            lookup_list.begin(),
                            lookup_list.end());
                    } else {
                        lookup_constraints.insert({selector_id, lookup_list});
                    }
                }
            };

            // This is for debugging, don't use extensively.
            template<typename FieldType>
            std::ostream& operator<<(std::ostream& os, const optimized_gates<FieldType>& gates) {
                for (const auto& [selector, id]: gates.selectors_) {
                    auto iter = gates.constraint_list.find(id);
		    		if (iter != gates.constraint_list.end()) {
                    	os << "Selector #" << id << " " << selector << std::endl;
                    	for (const auto &constraint : iter->second) {
                    	    os << constraint << std::endl;
                    	}
                    	os << "--------------------------------------------------------------" << std::endl;
		    		}
                }
                return os;
            }

            template<typename FieldType>
            class gates_optimizer {
            public:
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using context_type = context<FieldType, GenerationStage::CONSTRAINTS>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using lookup_input_constraints_type = crypto3::zk::snark::lookup_input_constraints<FieldType>;
                using lookup_constraint_type = std::pair<std::string, lookup_input_constraints_type>;

                // We expect you to move context into this object, and stop using it.
                gates_optimizer(context_type&& c)
                    : context_(std::make_unique<context_type>(std::move(c))) {
                }

                std::optional<std::vector<constraint_type>> shift_constraints(
                        const std::vector<constraint_type>& constraints, int shift) {
                    std::vector<constraint_type> shifted_constraints;
                    for (const auto& c: constraints) {
                        std::optional<constraint_type> shifted = c.rotate(shift);
                        if (!shifted)
                            return std::nullopt;
                        shifted_constraints.push_back(*shifted);
                    }
                    return shifted_constraints;
                }

                /** Tries to shift the lookup constraints to left or right.
                 *  \param[in] shift - Must be +-1, we cannot shift more than by 1.
                 */
                std::optional<std::vector<typename context_type::lookup_constraint_type>> shift_lookup_constraints(
                        const std::vector<typename context_type::lookup_constraint_type>& lookup_list, int shift) {
                    std::vector<typename context_type::lookup_constraint_type> shifted_lookup_list;
                    for (const std::pair<std::string, lookup_input_constraints_type>& lookup: lookup_list) {
                        std::optional<std::vector<constraint_type>> shifted_constraints =
                            shift_constraints(lookup.second, shift);
                        if (!shifted_constraints)
                            return std::nullopt;
                        shifted_lookup_list.push_back({lookup.first, *shifted_constraints});
                    }
                    return shifted_lookup_list;
                }

                // This function just makes the conversion, does not actually optimize.
                optimized_gates<FieldType> context_to_gates() {
                    optimized_gates<FieldType> result;

                    // Take everything out of context, and erase the context to free its memory.
                    std::unordered_map<row_selector<>, std::vector<constraint_type>> constraint_list = context_->get_constraints();
                    std::map<std::string, std::pair<std::vector<std::size_t>, row_selector<>>>
                        dynamic_lookup_tables = context_->get_dynamic_lookup_tables();
                    std::vector<plonk_copy_constraint> copy_constraints = context_->get_copy_constraints();
                    std::unordered_map<row_selector<>, std::vector<typename context_type::lookup_constraint_type>>
                        lookup_constraints = context_->get_lookup_constraints();
                    context_.reset(nullptr);

                    // Push all the selectors into 'selectors_' and change the values to ids.
                    for (auto& [row_list, constraints] : constraint_list) {
                        size_t id = result.add_selector(row_list);
                        result.constraint_list[id] = std::move(constraints);
                    }
                    for (auto& [name, area] : dynamic_lookup_tables) {
                        const auto& selector = area.second;
                        size_t id = result.add_selector(selector);
                        result.dynamic_lookup_tables[name] = {std::move(area.first), id};
                    }
                    for (const auto& [row_list, lookup_list] : lookup_constraints) {
                        size_t id = result.add_selector(row_list);
//std::cout << "Processing lookup constraint with row list " << row_list << ", got id = " << id << std::endl;
                        result.lookup_constraints[id] = std::move(lookup_list);
                    }
                    return result;
                }

                optimized_gates<FieldType> optimize_gates() {
                    optimized_gates<FieldType> result = context_to_gates();
                    // optimized_gates<FieldType> result = gates_storage_;
                    // std::cout << "Before: \n\n" << result << std::endl;
                    // optimize_selectors_by_shifting(result);
                    optimize_selectors_by_shifting(result);
                    // std::cout << "After: \n\n" << result << std::endl;
                    return result;
                }


            private:

                /** This function tries to reduce the number of selectors required by rotating the constraints by +-1.
                 */
                void optimize_selectors_by_shifting(optimized_gates<FieldType>& gates) {
                    // First, if some selector can be shifted left or right, and the resulting selector is present,
                    // record the corresponsing ids.
                    std::vector<size_t> left_shifts(gates.selectors_.size(), -1);
                    std::vector<size_t> right_shifts(gates.selectors_.size(), -1);
                    create_selector_shift_maps(gates, left_shifts, right_shifts);
                    std::vector<std::pair<size_t, int>> chosen_selectors = choose_selectors(
                        left_shifts, right_shifts);

					//std::cout << "The following selector shifts were selected: \n";
					//for (size_t i = 0; i < chosen_selectors.size(); ++i) {
					//	std::cout << "#" << i << " -> " << "#" << chosen_selectors[i].first << " shifted " << chosen_selectors[i].second << std::endl;
					//}
					//std::cout << std::endl;

                    // Maps the old selector ID to the new one, only for the selectors to be used.
                    std::map<size_t, size_t> new_selector_mapping;
                    size_t next_selector_id = 0;

                    // We will move the gates to 'result', since we want to change the selector ids.
                    // Then they will be moved back to the initial object.
                    optimized_gates<FieldType> result;

                    // Run over the constraints and apply the chosen shifts.
                    for (size_t id = 0; id < chosen_selectors.size(); ++id) {
                        size_t replacement_id = chosen_selectors[id].first;
                        if (new_selector_mapping.find(replacement_id) == new_selector_mapping.end())
                            new_selector_mapping[replacement_id] = next_selector_id++;

                        int shift = chosen_selectors[id].second;

                        if (shift == 0) {
                            auto iter = gates.constraint_list.find(id);
                            if (iter != gates.constraint_list.end())
                                result.add_constraints(new_selector_mapping[id], std::move(iter->second));

                            auto iter2 = gates.lookup_constraints.find(id);
                            if (iter2 != gates.lookup_constraints.end())
                                result.add_lookup_constraints(new_selector_mapping[id], std::move(iter2->second));
                        } else {
                            // Selector #id is replaced by #replacement_id by shifting 'shift'.

                            // Move all from constraints_list.
                            auto iter = gates.constraint_list.find(id);
                            if (iter != gates.constraint_list.end()) {
                                std::vector<constraint_type> constraints = std::move(iter->second);
                                gates.constraint_list.erase(id);
                                // We need the minus on the next line, we need to shift the constraints in the
                                // opposite direction of the selector shift.
                                std::optional<std::vector<constraint_type>> shifted_constraints =
                                    shift_constraints(std::move(constraints), -shift);

                                //std::cout << "Shifting " << -shift << " :" << std::endl;
                                //for (const auto &constraint : constraints) {
                                //    std::cout << constraint << std::endl;
                                //}
                                //std::cout << "result is: " << std::endl;
                                //for (const auto &constraint : *shifted_constraints) {
                                //    std::cout << constraint << std::endl;
                                //}
                                //std::cout << "Corresponding selectors are :" << id << " shifting to " << replacement_id << std::endl;
                                if (!shifted_constraints)
                                    throw std::logic_error("Unable to shift constraints after the shift decisions are made.");
                                result.add_constraints(new_selector_mapping[replacement_id], *shifted_constraints);
                            }

                            // Move all lookup_constraints.
                            auto iter2 = gates.lookup_constraints.find(id);
                            if (iter2 != gates.lookup_constraints.end()) {
                                std::vector<typename context_type::lookup_constraint_type> lookup_list = std::move(iter2->second);
                                gates.lookup_constraints.erase(id);

                                // We need the minus on the next line, we need to shift the constraints in the
                                // opposite direction of the selector shift.
                                std::optional<std::vector<typename context_type::lookup_constraint_type>> shifted_lookup_list =
                                    shift_lookup_constraints(lookup_list, -shift);
                                if (!shifted_lookup_list)
                                    throw std::logic_error("Unable to shift lookup constraints after the shift decisions are made.");
                                result.add_lookup_constraints(new_selector_mapping[replacement_id], *shifted_lookup_list);
                            }
                        }
                    }
					// Update the selector ids.
                	for (auto& [selector, id]: gates.selectors_) {
						if (new_selector_mapping.find(id) != new_selector_mapping.end())
                            result.selectors_.insert({ std::move(selector), new_selector_mapping[id] });
					}

					// Update the selector ids in dynamic lookups.
					for(auto& [name, area] : gates.dynamic_lookup_tables) {
						area.second = new_selector_mapping[area.second];
					}

                    gates.constraint_list = std::move(result.constraint_list);
                    gates.lookup_constraints = std::move(result.lookup_constraints);
					gates.selectors_ = result.selectors_;
                }

                /**
                 * This function is responsible for choosing the selectors we will use. If some selector can be shifted and used instead of another,
                 * we should do it. We must be careful, such that if there are 3 selectors s1->s2->s3, and we can shift both s1 and s3 to s2,
                 * we should do that, rather than shifting s2 to s3, and kepping s1.
                 * \param[in] left_shifts - if not zero, then left_shifts[i] shows the ID of selector that results in shifting selector with ID 'i' to the left, if the corresponding constrants can be rotated.
                 * \param[in] right_shifts - if not zero, then right_shifts[i] shows the ID of selector that results in shifting selector with ID 'i' to the right, if the corresponding constrants can be rotated.
                 * \returns The vector of choices made. Element #i in the vector is the selector that will replace selector #i. The second value is either 0, meaning we don't shift, or +-1 showing the shift direction. Careful with the shift value, it shows the direction selector is shifted, the constraints must be rotated in the opposize direction.
                 */
                std::vector<std::pair<size_t, int>> choose_selectors(
                        const std::vector<size_t>& left_shifts, const std::vector<size_t>& right_shifts) {
                    size_t N = left_shifts.size();
                    // For each selector we will keep a pair, the id of selector that will substitute the current one, and the shift used.
                    // If shift is 0, then the selector is used.
                    std::vector<std::pair<size_t, int>> chosen_shifts(N, {-1, -1});

                    // Create the opposite mappings as well.
                    std::vector<size_t> reversed_left_shifts(N, -1);
                    std::vector<size_t> reversed_right_shifts(N, -1);
                    for (size_t i = 0; i < N; ++i) {
                        if (left_shifts[i] != -1)
                            reversed_left_shifts[left_shifts[i]] = i;
                    }
                    for (size_t i = 0; i < N; ++i) {
                        if (right_shifts[i] != -1)
                            reversed_right_shifts[right_shifts[i]] = i;
                    }

                    // For each node go to the left and right as far as possible.
					// Then run over the chain of selectors and make the decisions.
                    for (size_t i = 0; i < N; ++i) {
                        // We may already have a decision for the current node.
                        if (chosen_shifts[i].first != -1)
                            continue;

                        std::vector<size_t> chain;
                        chain.push_back(i);

                        size_t current_node = i;

                        // Go all the way to the right.
                        // reversed_left_shifts[i] if shifted to the left will become selector 'i'.
                        // selector i if shifted right will result in right_shifts[current_node].
                        while (reversed_left_shifts[current_node] != -1 || right_shifts[current_node] != -1) {
                            if (reversed_left_shifts[current_node] != -1) {
                                current_node = reversed_left_shifts[current_node];
                            } else {
                                current_node = right_shifts[current_node];
                            }
                            chain.push_back(current_node);
                        }

                        // Go all the way to the left.
                        current_node = i;
                        while (reversed_right_shifts[current_node] != -1 || left_shifts[current_node] != -1) {
                            if (reversed_right_shifts[current_node] != -1) {
                                current_node = reversed_right_shifts[current_node];
                            } else {
                                current_node = left_shifts[current_node];
                            }
                            // It's not optimal to insert into vector, but the vector is very short.
                            chain.insert(chain.begin(), current_node);
                        }

                        // Now we have a chain of selectors, where chain[i] can be shifted right to create chain[i+1],
                        // but the shift may or may not be permitted.
                        for (int j = chain.size() - 1; j >= 0; j--) {
                            if (chosen_shifts[chain[j]].first != -1)
                                continue;
                            // We must either take node chain[j], or (chain[j-1] if chain[j] left shift to chain[j-1] is permitted.
                            // Check if we have the ability to NOT include chain[j].
                            if (j != 0) {
                                // chain[j] if shifted left will result in chain[j - 1], so let's include chain[j - 1].
                                if (left_shifts[chain[j]] == chain[j - 1]) {
                                    chosen_shifts[chain[j - 1]] = {chain[j - 1], 0};
                                    chosen_shifts[chain[j]] = {chain[j - 1], -1};

									// Check if chain[j - 2] can be skipped by rotating it to the right.
                                    if (j >= 2 && right_shifts[chain[j - 2]] == chain[j - 1]) {
                                        chosen_shifts[chain[j - 2]] = {chain[j - 1], +1};
                                    }
                                } else {
                                    // Include chain[j].
                                    chosen_shifts[chain[j]] = {chain[j], 0};
                                    // Check if chain[j - 1] can be skipped by rotating it to the right.
                                    if (right_shifts[chain[j - 1]] == chain[j]) {
                                        chosen_shifts[chain[j - 1]] = {chain[j], +1};
                                    }
                                }
                            } else {
                                // We cannot skip chain[j] by using chain[j - 1].
                                chosen_shifts[chain[j]] = {chain[j], 0};
                            }
                        }
                    }
                    return chosen_shifts;
                }

                /**
                 * This function creates vectors with allowed shifts of selectors to the left and right.
                 * \param[out] left_shifts - if not zero, then left_shifts[i] shows the ID of selector that results in shifting selector with ID 'i' to the left, if the corresponding constrants can be rotated.
                 * \param[out] right_shifts - if not zero, then right_shifts[i] shows the ID of selector that results in shifting selector with ID 'i' to the right, if the corresponding constrants can be rotated.
                 */
                void create_selector_shift_maps(const optimized_gates<FieldType>& gates,
                                                std::vector<size_t>& left_shifts,
                                                std::vector<size_t>& right_shifts) {
                    for (const auto& [selector, id]: gates.selectors_) {
                        if (!selector[0]) {
                            row_selector<> left_selector = selector;
                            left_selector >>= 1;
                            auto iter = gates.selectors_.find(left_selector);
                            if (iter != gates.selectors_.end()) {
                                size_t left_id = iter->second;
                                // We need to check shift +1, if the selecor is shifted left,
                                // the constraint must be rotated right.
                                if (can_shift(gates, id, +1)) {
                                    left_shifts[id] = left_id;
                                }
                            }
                        }

                        if (!selector[selector.max_index() - 1]) {
                            row_selector<> right_selector = selector;
                            right_selector <<= 1;
                            auto iter = gates.selectors_.find(right_selector);
                            if (iter != gates.selectors_.end()) {
                                size_t right_id = iter->second;
                                // We need to check shift -1, if the selecor is shifted left,
                                // the constraint must be rotated right.
                                if (can_shift(gates, id, -1)) {
                                    right_shifts[id] = right_id;
                                }
                            }
                        }
                    }
                }

                bool can_shift(const optimized_gates<FieldType>& gates,
                               size_t selector_id,
                               size_t shift) {
                    // Check if there is a constraint that can't be shifted.
                    auto iter = gates.constraint_list.find(selector_id);
                    if (iter != gates.constraint_list.end()) {
                        const std::vector<constraint_type>& constraints = iter->second;
                        std::optional<std::vector<constraint_type>> shifted_constraints =
                            shift_constraints(constraints, shift);
                        if (!shifted_constraints) {
                            return false;
                        }
                    }

                    // Check if there is a lookup constraint that can't be shifted.
                    auto iter2 = gates.lookup_constraints.find(selector_id);
                    if (iter2 != gates.lookup_constraints.end()) {
                        const std::vector<typename context_type::lookup_constraint_type>& lookup_list = iter2->second;
                        for (const std::pair<std::string, lookup_input_constraints_type>& lookup: lookup_list) {
                            std::optional<std::vector<constraint_type>> shifted_constraints =
                                shift_constraints(lookup.second, shift);
                            if (!shifted_constraints) {
                                return false;
                            }
                        }
                    }
                    return true;
                }

                std::unique_ptr<context<FieldType, GenerationStage::CONSTRAINTS>> context_;
                //optimized_gates<FieldType> gates_storage_;
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_BBF_GATE_OPTIMIZER_HPP
