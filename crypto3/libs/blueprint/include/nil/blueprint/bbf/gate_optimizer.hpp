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
                std::unordered_map<size_t, std::vector<std::pair<constraint_type,std::string>>> constraint_list;
                std::vector<std::pair<constraint_type, std::string>> global_constraints;
                std::vector<plonk_copy_constraint> copy_constraints;
                std::map<std::string, std::pair<std::vector<std::vector<std::size_t>>, size_t>> dynamic_lookup_tables;

                // Global lookup constraints (to use without selector)
                std::vector<lookup_constraint_type> global_lookup_constraints;

                // Lookup constraints with single selector are stored here.
                std::unordered_map<size_t, std::vector<lookup_constraint_type>> lookup_constraints;

                // The following lookup constraints are grouped with non-intersecting selectors.
                // grouped_lookups[table_name][group_id][selector_id] maps to the lookup inputs for the given selector.
                std::unordered_map<std::string, std::unordered_map<size_t, std::unordered_map<size_t, lookup_input_constraints_type>>> grouped_lookups;

                // We will map each selector to the corresponding id.
                std::unordered_map<row_selector<>, size_t> selectors_;

                size_t add_selector(const row_selector<>& selector) {
                    auto iter = selectors_.find(selector);
                    size_t next_selector_id = selectors_.size();
                    if (iter == selectors_.end()) {
                        selectors_.insert({selector, next_selector_id});
                        // std::cout << "Added a selector " << selector << " which now has id " << next_selector_id << std::endl;
                        return next_selector_id;
                    }
                    return iter->second;
                }

                void add_constraints(size_t selector_id, const std::vector<std::pair<constraint_type, std::string>>& constraints) {
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
                    os << "Selector #" << id << " " << selector << std::endl;
                    os << "Constraints: " << std::endl;
                    if (iter != gates.constraint_list.end()) {
                        for (const auto &constraint : iter->second) {
                            os << constraint.second << constraint.first << std::endl;
                        }
                        os << "--------------------------------------------------------------" << std::endl;
                    }
                }

                for (const auto& [table_name, grouped_lookups] : gates.grouped_lookups) {
                    os << "================ Grouped lookups for table " << table_name << " ===================" << std::endl;
                    for (const auto& [group_id, lookups] : grouped_lookups) {
                        os << "    >>>>>>> Group #" << group_id << std::endl;
                        for (const auto& [selector_id, lookup_inputs] : lookups) {
                            os << "        selector #" << selector_id << " -> " << std::endl;
                            os << "        --------------------------------------------------------------" << std::endl;
                            for (const auto& li: lookup_inputs) {
                                os << "        " << li << std::endl;
                            }
                            os << "        --------------------------------------------------------------" << std::endl;
                        }
                        os << "    <<<<<<< End of Group #" << group_id << std::endl;
                    }
                    os << "===============================================================" << std::endl;
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

                std::optional<std::vector<std::pair<constraint_type, std::string>>> shift_constraints(
                        const std::vector<std::pair<constraint_type, std::string>> constraints, int shift) {
                    std::vector<std::pair<constraint_type, std::string>> shifted_constraints;
                    for (const auto& c: constraints) {
                        std::optional<constraint_type> shifted = c.first.rotate(shift);
                        if (!shifted)
                            return std::nullopt;
                        shifted_constraints.push_back({*shifted, c.second});
                    }
                    return shifted_constraints;
                }

                std::optional<std::vector<constraint_type>> shift_constraints(
                        const std::vector<constraint_type> constraints, int shift) {
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
                    std::unordered_map<row_selector<>, std::vector<std::pair<constraint_type, std::string>>> constraint_list = context_->get_constraints();

                    result.global_constraints = context_->get_global_constraints();
                    result.global_lookup_constraints = context_->get_global_lookup_constraints();
                    std::map<std::string, std::pair<std::vector<std::vector<std::size_t>>, row_selector<>>>
                        dynamic_lookup_tables = context_->get_dynamic_lookup_tables();
                    result.copy_constraints = context_->get_copy_constraints();
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
                        result.lookup_constraints[id] = std::move(lookup_list);
                    }
                    return result;
                }

                optimized_gates<FieldType> optimize_gates() {
                    optimized_gates<FieldType> result = context_to_gates();
                    // optimized_gates<FieldType> result = gates_storage_;
                    // std::cout << "Before: \n\n" << result << std::endl;
                    optimize_selectors_by_shifting(result);
                    // std::cout << "After optimizing selectors: \n\n" << result << std::endl;
                    optimize_lookups_by_grouping(result);
                    // std::cout << "After: \n\n" << result << std::endl;
                    return result;
                }


            private:

                /** RLF (Recursive Largest First) algorithm for graph coloring.
                 *  \param[in] adj - Adjacency list of the graph.
                 *  \returns A vector that contains color of each vertex.
                 */
                std::vector<size_t> colorGraph(const std::vector<std::vector<size_t>>& adj) {
                    size_t n = adj.size();
                    if (n == 0)
                        return {};

                    // All vertices initially uncolored
                    std::vector<size_t> color(n, std::numeric_limits<size_t>::max());
                    std::unordered_set<size_t> uncolored;
                    for (size_t i = 0; i < n; i++)
                        uncolored.insert(i);

                    size_t currentColor = 0;

                    while (!uncolored.empty()) {
                        // Compute vertex degrees for uncolored vertices only.
                        std::vector<size_t> degrees(n, 0);
                        for (size_t i: uncolored) {
                            for (size_t j : adj[i]) {
                                if (uncolored.find(j) != uncolored.end())
                                    degrees[i]++;
                            }
                        }

                        // Step 1: Pick the vertex with the largest degree from the uncolored set
                        size_t startVertex = *std::max_element(uncolored.begin(), uncolored.end(),
                                                          [&](size_t a, size_t b) {
                                                              return degrees[a] < degrees[b];
                                                          });

                        // Start a new color class
                        color[startVertex] = currentColor;
                        uncolored.erase(startVertex);

                        // H is the set of vertices to consider adding
                        // Initially, it's all remaining uncolored vertices
                        std::unordered_set<size_t> H = uncolored;

                        // Throw out the neighbors of 'startVertex', those can't be included in the color class.
                        for (auto w : adj[startVertex]) {
                            H.erase(w);
                        }

                        // Iteratively add vertices to the color class
                        while (!H.empty()) {
                            // Pick the vertex in H with the largest # of neighbours that are adjacent to
                            // some vertex in the color set S.
                            // Tie-break by highest degree
                            size_t candidate = 0;
                            bool found = false;
                            // best number of neighbors that are adjacent to vertices in class, I.E. are uncolored,
                            // but not in H.
                            size_t bestValue = 0;
                            // tie-break by number of neighbors not in the color class,
                            // I.E. the degree of the vertex in the uncolored graph.
                            size_t bestDegree = 0;

                            for (auto v : uncolored) {
                                size_t val = 0;
                                for (size_t v2: adj[v]) {
                                    // If v2 is an uncolored vertex, but it's not in H, that's because
                                    // it is adjacent to a vertex in the color set.
                                    if (uncolored.find(v2) != uncolored.end() && H.find(v2) == H.end())
                                        val++;
                                }
                                if (!found || val > bestValue || (val == bestValue && degrees[v] < bestDegree)) {
                                    bestValue = val;
                                    bestDegree = degrees[v];
                                    candidate = v;
                                    found = true;
                                }
                            }

                            // Add candidate to the color class
                            uncolored.erase(candidate);
                            color[candidate] = currentColor;
                            H.erase(candidate);

                            for (auto w : adj[candidate]) {
                                H.erase(w);
                            }
                        }

                        currentColor++;
                    }

                    return color;
                }

                /** Creates and returns a graph in the form of an adjucency list.
                 */
                std::vector<std::vector<size_t>> create_selector_intersection_graph(
                        const optimized_gates<FieldType>& gates,
                        const std::vector<size_t>& used_selectors,
                        const std::unordered_map<size_t, size_t>& selector_id_to_index) {
                    std::vector<std::vector<size_t>> adj;
                    // Create the graph.
                    adj.resize(used_selectors.size());
                    for (const auto& [row_list1, selector_id1]: gates.selectors_) {
                        if (selector_id_to_index.find(selector_id1) == selector_id_to_index.end())
                            continue;
                        for (const auto& [row_list2, selector_id2]: gates.selectors_) {
                            if (selector_id2 >= selector_id1 || selector_id_to_index.find(selector_id2) == selector_id_to_index.end())
                                continue;
                            if (row_list1.intersects(row_list2))    {
                                // Add an edge.
                                adj[selector_id_to_index.at(selector_id1)].push_back(selector_id_to_index.at(selector_id2));
                                adj[selector_id_to_index.at(selector_id2)].push_back(selector_id_to_index.at(selector_id1));
                            }
                        }
                    }
                    return adj;
                }

                std::vector<std::vector<size_t>> get_subgraph(
                        const std::vector<std::vector<size_t>>& graph,
                        const std::vector<size_t>& all_lookup_selectors,
                        const std::unordered_map<size_t, size_t>& selector_id_to_index,
                        const std::vector<size_t>& subset_selectors) {
                    std::unordered_map<size_t, size_t> selector_id_to_subset_index;
                    for (size_t i = 0; i < subset_selectors.size(); ++i) {
                        selector_id_to_subset_index[subset_selectors[i]] = i;
                    }

                    std::vector<std::vector<size_t>> result(subset_selectors.size());
                    for (size_t i = 0; i < subset_selectors.size(); ++i) {
                        // 'id' is actually an index of selector in the 'all_lookup_selectors'.
                        for (size_t id: graph[selector_id_to_index.at(subset_selectors[i])]) {
                            result[i].push_back(selector_id_to_subset_index[all_lookup_selectors[id]]);
                        }
                    }
                    return result;
                }

                std::unordered_map<size_t, size_t> group_selectors(
                        const std::vector<std::vector<size_t>>& graph,
                        const std::vector<size_t>& all_lookup_selectors,
                        const std::unordered_map<size_t, size_t>& selector_id_to_index,
                        const std::vector<size_t>& used_selectors) {
                    std::vector<std::vector<size_t>> graph_subset = get_subgraph(
                        graph, all_lookup_selectors, selector_id_to_index, used_selectors);

                    //std::cout << "Current graph subset" << std::endl;
                    //for (size_t i = 0; i < graph_subset.size(); ++i) {
                    //    std::cout << i << " -> [";
                    //    for (size_t v2 : graph_subset[i]) {
                    //         std::cout << v2 << " ";
                    //    }
                    //    std::cout << "]" << std::endl;
                    //}

                    // coloring[i] is the group_id of used_selectors[i].
                    std::vector<size_t> coloring = colorGraph(graph_subset);

                    //std::cout << "Coloring is [";
                    //for (size_t i = 0; i < coloring.size(); ++i) {
                    //    std::cout << used_selectors[i] << " -> " << coloring[i] << " , ";
                    //}
                    //std::cout << "]" << std::endl;

                    // Now run over the returned coloring and map it back.
                    std::unordered_map<size_t, size_t> result;
                    for (size_t i = 0; i < coloring.size(); ++i) {
                        result[used_selectors[i]] = coloring[i];
                    }
                    return result;
                }

                /** This function tries to reduce the number of lookups by grouping them. If 2 lookups use non-intersecting
                 *  selectors, they can be merged into 1 like.
                 *  Imagine lookup inputs {L0 ... Lm} with selector s1, and {l0 ... lm} with selector s2, then we can merge them into
                 *  lookup inputs { s1 * L0 + s2 * l0, ...  , s1 * Lm + s2 * lm } with selector that selects all the rows.
                 *  We cannot optimally group the selectors into the minimal number of groups, that's an NP-complete problem
                 *  called graph coloring problem. We will use Brooks' algorithm, it's some simple heuristic thing.
                 */
                void optimize_lookups_by_grouping(optimized_gates<FieldType>& gates) {
                    std::vector<size_t> all_lookup_selectors;
                    std::unordered_map<size_t, size_t> selector_id_to_index;

                    for (const auto& [row_list, selector_id]: gates.selectors_) {
                        if (gates.lookup_constraints.find(selector_id) != gates.lookup_constraints.end()) {
                            all_lookup_selectors.push_back(selector_id);
                            selector_id_to_index[selector_id] = all_lookup_selectors.size() - 1;
                        }
                    }

                    // Create an adjacency list of the whole large graph, since taking intersections of selectors is not super fast.
                    std::vector<std::vector<size_t>> adj = create_selector_intersection_graph(
                        gates, all_lookup_selectors, selector_id_to_index);

                    //for (size_t i = 0; i < adj.size(); ++i) {
                    //    std::cout << i << " -> [";
                    //    for (size_t v2 : adj[i]) {
                    //         std::cout << v2 << " ";
                    //    }
                    //    std::cout << "]" << std::endl;
                    //}

                    // For each table, create the list of used selectors.
                    std::unordered_map<std::string, std::set<size_t>> selectors_per_table;
                    for(const auto& [selector_id, lookup_list] : gates.lookup_constraints) {
                        for(const auto& single_lookup_constraint : lookup_list) {
                            const auto& table_name = single_lookup_constraint.first;
                            selectors_per_table[table_name].insert(selector_id);
                        }
                    }

                    // For each table, group the selectors.

                    // Maps table name to a [map of selector id -> # of the group it belongs to].
                    std::unordered_map<std::string, std::unordered_map<size_t, size_t>> selector_groups;
                    std::unordered_map<std::string, std::unordered_map<size_t, size_t>> group_sizes;
                    for (const auto& [table_name, selectors_set] : selectors_per_table) {
                        std::vector<size_t> selectors(selectors_set.begin(), selectors_set.end());

                        // Maps group_id -> # of selectors in it.
                        selector_groups[table_name] = group_selectors(adj, all_lookup_selectors, selector_id_to_index, selectors);

                        // Count the size of each group, we need to not touch groups of size 1.
                        for (const auto& [selector_id, group_index]: selector_groups[table_name]) {
                            group_sizes[table_name][group_index]++;
                        }
                    }

                    std::unordered_map<size_t, std::vector<typename context_type::lookup_constraint_type>> new_lookup_constraints;

                    // Now merge all the lookups on selectors in the same group.
                    for (const auto& [selector_id, lookup_list] : gates.lookup_constraints) {
                        std::vector<lookup_constraint_type> lookup_gate;
                        for (const auto& single_lookup_constraint : lookup_list) {
                            const std::string& table_name = single_lookup_constraint.first;
                            size_t group_id = selector_groups[table_name][selector_id];

                            // std::cout << "Group for selector #" << selector_id << " is " << group_id << std::endl;

                            // If the group size is 1, don't touch it.
                            if (group_sizes[table_name][group_id] == 1) {
                                new_lookup_constraints[selector_id].push_back(
                                    {table_name, std::move(single_lookup_constraint.second)});
                            } else {
                                gates.grouped_lookups[table_name][group_id][selector_id] =
                                    std::move(single_lookup_constraint.second);
                            }
                        }
                    }

                    gates.lookup_constraints = std::move(new_lookup_constraints);
                }

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
                    //  std::cout << "#" << i << " -> " << "#" << chosen_selectors[i].first << " shifted " << chosen_selectors[i].second << std::endl;
                    //}
                    //std::cout << std::endl;

                    // Maps the old selector ID to the new one
                    std::map<size_t, size_t> new_selector_ids;
                    size_t next_selector_id = 0;

                    // We will move the gates to 'result', since we want to change the selector ids.
                    // Then they will be moved back to the initial object.
                    optimized_gates<FieldType> result;

                    // Run over the constraints and apply the chosen shifts.
                    for (size_t id = 0; id < chosen_selectors.size(); ++id) {
                        size_t replacement_id = chosen_selectors[id].first;
                        auto [iter, is_new] = new_selector_ids.emplace(replacement_id, next_selector_id);
                        if (is_new) ++next_selector_id;
                        new_selector_ids[id] = iter->second;

                        int shift = chosen_selectors[id].second;

                        if (shift == 0) {
                            auto iter = gates.constraint_list.find(id);
                            if (iter != gates.constraint_list.end())
                                result.add_constraints(new_selector_ids[id], std::move(iter->second));

                            auto iter2 = gates.lookup_constraints.find(id);
                            if (iter2 != gates.lookup_constraints.end())
                                result.add_lookup_constraints(new_selector_ids[id], std::move(iter2->second));
                        } else {
                            // Selector #id is replaced by #replacement_id by shifting 'shift'.

                            // Move all from constraints_list.
                            auto iter = gates.constraint_list.find(id);
                            if (iter != gates.constraint_list.end()) {
                                std::vector<std::pair<constraint_type, std::string>> constraints = std::move(iter->second);
                                gates.constraint_list.erase(id);
                                // We need the minus on the next line, we need to shift the constraints in the
                                // opposite direction of the selector shift.
                                std::optional<std::vector<std::pair<constraint_type, std::string>>> shifted_constraints =
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
                                result.add_constraints(new_selector_ids[replacement_id], *shifted_constraints);
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
                                result.add_lookup_constraints(new_selector_ids[replacement_id], *shifted_lookup_list);
                            }
                        }
                    }

                    // Update the selector ids
                    for (auto& [selector, id]: gates.selectors_) {
                        if (chosen_selectors[id].first == id) {
                            result.selectors_.emplace(std::move(selector), new_selector_ids.at(id));
                        }
                    }

                    // Update the selector ids in dynamic lookups.
                    for(auto& [name, area] : gates.dynamic_lookup_tables) {
                        area.second = new_selector_ids[area.second];
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
                    // We can't just shift selectors that define dynamic lookup tables' data,
                    // because we'd need to move the table itself too in the assignment table.
                    std::unordered_set<size_t> lookup_table_selectors;
                    for (auto &[name, area] : gates.dynamic_lookup_tables)
                        lookup_table_selectors.insert(area.second);

                    for (const auto& [selector, id]: gates.selectors_) {
                        if (lookup_table_selectors.contains(id)) continue;

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
                        const std::vector<std::pair<constraint_type, std::string>>& constraints = iter->second;
                        std::optional<std::vector<std::pair<constraint_type, std::string>>> shifted_constraints =
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
