//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP
#define CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP

#include <stdexcept>
#include <vector>
#include <functional>
#include <variant>
#include <stack>

#include <boost/container/small_vector.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil::crypto3::zk::snark {
    using dag_operands_vector_type = std::vector<size_t>;

    template<typename VariableType>
    struct dag_constant {
        using assignment_type = typename VariableType::assignment_type;
        assignment_type value;

        dag_constant(const assignment_type& value)
            : value(value) {}

        bool operator==(const dag_constant& other) const = default;
    };

    template<typename VariableType>
    struct dag_variable {
        VariableType variable;

        dag_variable(const VariableType& variable)
            : variable(variable) {}

        bool operator==(const dag_variable& other) const = default;
    };

    struct dag_addition {
        dag_operands_vector_type operands;

        dag_addition(const dag_operands_vector_type& operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }
        dag_addition(std::initializer_list<size_t> operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }

        bool operator==(const dag_addition& other) const = default;
    };

    struct dag_multiplication {
        dag_operands_vector_type operands;

        dag_multiplication(const dag_operands_vector_type& _operands) : operands(_operands) {
            std::sort(operands.begin(), operands.end());
        }
        dag_multiplication(std::initializer_list<size_t> operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }

        bool operator==(const dag_multiplication& other) const = default;
    };

    struct dag_negation {
        size_t operand;

        dag_negation(size_t operand)
            : operand(operand) {}

        bool operator==(const dag_negation& other) const = default;
    };

    template<typename VariableType>
    using dag_node = std::variant<
        dag_constant<VariableType>,
        dag_variable<VariableType>,
        dag_addition,
        dag_multiplication,
        dag_negation
    >;

    template<typename VariableType>
    class dag_node_hashing_visitor : public boost::static_visitor<size_t> {
    public:
        using assignment_type = typename VariableType::assignment_type;

        static const size_t constant_seed = 0x1;
        static const size_t add_seed      = 0x2;
        static const size_t multiply_seed = 0x3;
        static const size_t negation_seed = 0x4;

        dag_node_hashing_visitor() = default;

        size_t operator()(const dag_constant<VariableType>& n) const {
            size_t seed = constant_seed;
            boost::hash_combine(seed, std::hash<assignment_type>()(n.value));
            return seed;
        }

        size_t operator()(const dag_variable<VariableType>& n) const {
            return std::hash<VariableType>()(n.variable);
        }

        size_t operator()(const dag_addition& n) const {
            return std::accumulate(n.operands.begin(), n.operands.end(), add_seed, [](size_t a, size_t b) {
                size_t seed = a;
                boost::hash_combine(seed, b);
                return seed;
            });
        }
        size_t operator()(const dag_multiplication& n) const {
            return std::accumulate(n.operands.begin(), n.operands.end(), multiply_seed, [](size_t a, size_t b) {
                size_t seed = a;
                boost::hash_combine(seed, b);
                return seed;
            });
        }
        size_t operator()(const dag_negation& n) const {
            size_t seed = negation_seed;
            boost::hash_combine(seed, n.operand);
            return seed;
        }
    };


} // namespace nil::crypto3::zk::snark

// Define the hash of a dag_node, so we can use it in dag_expression.
template<typename VariableType>
struct std::hash<nil::crypto3::zk::snark::dag_node<VariableType>> {

    nil::crypto3::zk::snark::dag_node_hashing_visitor<VariableType> visitor;

    size_t operator()(const nil::crypto3::zk::snark::dag_node<VariableType> &node) const {
        return std::visit(visitor, node);
    }
};

namespace nil::crypto3::zk::snark {

    template<typename VariableType>
    class dag_expression_builder;

    template<typename VariableType>
    class dag_expression {
    public:
        friend class dag_expression_builder<VariableType>;

        using node_type = dag_node<VariableType>;
        using assignment_type = typename VariableType::assignment_type;

        using math_expression_type = expression<VariableType>;
        using term_type = term<VariableType>;
        using pow_operation_type = pow_operation<VariableType>;
        using binary_arithmetic_operation_type = binary_arithmetic_operation<VariableType>;

        size_t get_root_nodes_count() const {
            return root_nodes.size();
        }

        size_t get_nodes_count() const {
            return nodes.size();
        }

        const std::vector<node_type>& get_nodes() const {
            return nodes;
        }
        const node_type& get_node(size_t i) const {
            return nodes[i];
        }
        size_t get_root_node(size_t i) const {
            return root_nodes[i];
        }
        size_t get_root_node_degree(size_t i) const {
            return root_node_degrees[i];
        }
    private:

        std::unordered_map<node_type, size_t> node_map;
        std::vector<size_t> root_nodes;
        // The degrees of expression that represent the given root node.
        std::vector<size_t> root_node_degrees;
        std::vector<node_type> nodes;

        size_t register_node(const node_type& node) {
            auto it = node_map.find(node);
            if (it != node_map.end()) {
                return it->second;
            }
            size_t index = nodes.size();
            nodes.push_back(node);
            node_map[node] = index;
            return index;
        }
    };

    // Very useful for debugging, not used in production.
    template<typename VariableType>
    class dag_node_statistics_visitor : public boost::static_visitor<void> {
    public:
        size_t additions;
        size_t multiplications;
        size_t copies;
        size_t negations;

        dag_node_statistics_visitor() = default;

        void print_stats(const dag_expression<VariableType>& dag,
                         std::string_view tag = "DAG operations") {
            additions = multiplications = copies = negations = 0;
            for (const auto& node: dag.get_nodes()) {
                std::visit(*this, node);
            }

            SCOPED_LOG("{}: add {}, mul: {}, neg: {}, copy: {}", tag, additions,
                       multiplications, negations, copies);
        }

        void operator()(const dag_constant<VariableType>& n) {
            copies++;
        }

        void operator()(const dag_variable<VariableType>& n) {
            copies++;
        }

        void operator()(const dag_addition& n) {
            copies++;
            additions += n.operands.size() - 1;
        }
        void operator()(const dag_multiplication& n) {
            copies++;
            multiplications += n.operands.size() - 1;
        }
        void operator()(const dag_negation& n) {
            copies++;
            negations++;
        }
    };

    // For each node of a DAG counts how many times is it used as a child of another node.
    template<typename VariableType>
    class dag_child_occurence_counting_visitor : public boost::static_visitor<void> {
    public:

        std::vector<size_t> _occurences;

        dag_child_occurence_counting_visitor() = default;

        std::vector<size_t> get_occurence_counts(const dag_expression<VariableType> &dag) {
            _occurences = std::vector<size_t>(dag.get_nodes_count(), 0);
            for (const auto& node: dag.get_nodes()) {
                std::visit(*this, node);
            }
            return std::move(_occurences);
        }

        void operator()(const dag_constant<VariableType>& n) {
        }
        void operator()(const dag_variable<VariableType>& n) {
        }
        void operator()(const dag_addition& n) {
            for (size_t i = 0; i < n.operands.size(); i++) {
                _occurences[n.operands[i]]++;
            }
        }
        void operator()(const dag_multiplication& n) {
            for (size_t i = 0; i < n.operands.size(); i++) {
                _occurences[n.operands[i]]++;
            }
        }
        void operator()(const dag_negation& n) {
            _occurences[n.operand]++;
        }
    };

    // TODO(martun): if we find time, get rid of all usages of std::holds_alternative.

    // This class stores all registered expressions, then runs over them as a visitor and
    // builds a DAG for them.
    template<typename VariableType>
    class dag_expression_builder : public boost::static_visitor<size_t> {
    public:
        using node_type = dag_node<VariableType>;
        using assignment_type = typename VariableType::assignment_type;

        using math_expression_type = expression<VariableType>;
        using term_type = term<VariableType>;
        using pow_operation_type = pow_operation<VariableType>;
        using binary_arithmetic_operation_type = binary_arithmetic_operation<VariableType>;
        using co_occurence_map_type = std::unordered_map<std::pair<size_t, size_t>, size_t, boost::hash<std::pair<size_t,size_t>>>;

        size_t get_expression_count() const {
            return expressions.size();
        }

        void add_expression(const math_expression_type& expression) {
            expressions.push_back(expression);
        }

        void add_expression(math_expression_type&& expr) {
            expressions.push_back(std::move(expr));
        }

        dag_expression<VariableType> build() {
            expression_max_degree_visitor<VariableType> max_degree_visitor;

            for (const auto& expr: expressions) {
                size_t root_node = boost::apply_visitor(*this, expr.get_expr());
                result.root_nodes.push_back(root_node);

                std::size_t degree = max_degree_visitor.compute_max_degree(expr);
                result.root_node_degrees.push_back(degree);
            }
            squash_dag();
            return std::move(result);
        }

        // This operation runs over the dag in 'result', if it sees a mult/add node. that has a child that
        // is also mult/add node, it takes the children of that child to itself, as a direct child.
        // This does not result into a more optimal dag yet, it just [potentially] reduces the number of nodes.
        void squash_dag() {
            dag_node_statistics_visitor<VariableType> visitor;

            PROFILE_SCOPE("Squashing DAG expression");

            // visitor.print_stats(result, "DAG before squashing");

            merge_children(/*only_those_that_occur_once=*/ false);

            // visitor.print_stats(result, "DAG After merge children");

            remove_unreachable_nodes();

            // visitor.print_stats(result, "DAG After remove unreachable nodes");

            remove_duplicates();

            // visitor.print_stats(result, "DAG After removing duplicates");

            // Now remove children that are the only child of their parent, and parent operation matches.
            merge_children(/*only_those_that_occur_once=*/ true);
            remove_unreachable_nodes();

            // visitor.print_stats(result, "DAG after squashing");
        }

        // Runs over the dag, looking at the addition and multiplication nodes. If it detects a pair of children than appear
        // more than once in a node, it creates a separate node for that pair, and reuses that node.
        // In order to do that [semi]optimally we constantly run over the dag and compute the co-occurence matrix.
        // Then we merge node pairs if they co-occure more than once. Then the matrix is built again and again, until
        // if does not contain any number >1.
        void remove_duplicates() {
            bool something_changed;
            do {
                something_changed = false;
                auto [add_occurences, mul_occurences] = generate_occurance_count();
                auto [add_co_occurence_map, mul_co_occurence_map] = generate_co_occurence_maps(
                    add_occurences, mul_occurences);
                prune_co_occurence_map(add_co_occurence_map);
                prune_co_occurence_map(mul_co_occurence_map);

                std::vector<size_t> new_index(result.nodes.size());
                dag_expression<VariableType> new_result;
                for (size_t k = 0; k < result.nodes.size(); ++k) {
                    auto& node = result.nodes[k];
                    if (std::holds_alternative<dag_addition>(node)) {
                        auto& add = std::get<dag_addition>(node);
                        const auto [selected_pairs, used] = pair_nodes(
                            add.operands, add_occurences, add_co_occurence_map);
                        if (selected_pairs.size() != 0)
                            something_changed = true;

                        dag_operands_vector_type new_operands;
                        for (size_t i = 0; i < add.operands.size(); i++) {
                            if (!used[i])
                                new_operands.push_back(new_index[add.operands[i]]);
                        }
                        for (const auto& [first, second]: selected_pairs) {
                            auto new_idx = new_result.register_node(dag_addition{
                                new_index[add.operands[first]], new_index[add.operands[second]]});
                            new_operands.push_back(new_idx);
                        }
                        add.operands = new_operands;
                    } else if (std::holds_alternative<dag_multiplication>(node)) {
                        auto& mul = std::get<dag_multiplication>(node);
                        const auto [selected_pairs, used] = pair_nodes(
                            mul.operands, mul_occurences, mul_co_occurence_map);
                        if (selected_pairs.size() != 0)
                            something_changed = true;

                        dag_operands_vector_type new_operands;
                        for (size_t i = 0; i < mul.operands.size(); i++) {
                            if (!used[i])
                                new_operands.push_back(new_index[mul.operands[i]]);
                        }
                        for (const auto& [first, second]: selected_pairs) {
                            auto new_idx = new_result.register_node(dag_multiplication{
                                new_index[mul.operands[first]], new_index[mul.operands[second]]});
                            new_operands.push_back(new_idx);
                        }
                        mul.operands = new_operands;
                    } else if (std::holds_alternative<dag_negation>(node)) {
                        auto& neg = std::get<dag_negation>(node);
                        neg.operand = new_index[neg.operand];
                    }
                    auto new_idx = new_result.register_node(std::move(node));
                    new_index[k] = new_idx;
                }
                // Move all the root nodes as well.
                new_result.root_nodes = result.root_nodes;
                new_result.root_node_degrees = result.root_node_degrees;
                for (auto& root_id: new_result.root_nodes) {
                    root_id = new_index[root_id];
                }
                result = new_result;
            } while(something_changed);
        }

        // Creates pairs of operands based on the co-occurance maps. It returns indices in the 'operands' vector, not the values.
        // Also returns a vector telling us which index was paired.
        std::pair<std::vector<std::pair<size_t, size_t>>, std::vector<bool>> pair_nodes(
            const dag_operands_vector_type& operands,
            const std::unordered_map<size_t, size_t>& occurences,
            const co_occurence_map_type& co_occurence_map
            ) {
            // Get all the pairs that appear >=2 times and sort by decreasing order of appearances.
            std::multimap<size_t, std::pair<size_t, size_t>, std::greater<>> pairs;
            for (size_t i = 0; i < operands.size(); i++) {
                if (occurences.at(operands[i]) == 1)
                    continue;
                for (size_t j = i + 1; j < operands.size(); j++) {
                    auto iter = co_occurence_map.find(std::make_pair(operands[i], operands[j]));
                    if (iter != co_occurence_map.end() && iter->second > 1) {
                        pairs.emplace(iter->second, std::pair<std::size_t, std::size_t>{i, j});
                    }
                }
            }
            std::vector<std::pair<size_t, size_t>> selected_pairs;
            std::vector<bool> used(result.nodes.size(), false);
            for (const auto& [key, pr] : pairs) {
                const auto& [first, second] = pr;
                if (used[first] || used[second])
                    continue;
                used[first] = true;
                used[second] = true;
                selected_pairs.push_back({first, second});
            }
            return {selected_pairs, used};
        }

        // Keeps only the top 5% of pairs, removes the rest. We tried 1%, 2%, 5%, 10%, 20%. For some
        // reason 5% is optimal.
        void prune_co_occurence_map(co_occurence_map_type& m) const {
            if (m.size() == 0)
                return;

            std::vector<size_t> values;

            for (auto it = m.begin(); it != m.end(); ++it) {
                values.push_back(it->second);
            }
            std::sort(values.begin(), values.end());

            size_t M = values[values.size() / 20];
            for (auto it = m.begin(); it != m.end();) {
                if (it->second < M)
                    it = m.erase(it);
                else
                    ++it;
            }
        }

        // Count how many times each node appears as a child in addition or multiplication.
        // If it appears only once, there is no chance it has duplicates. This is an optimization.
        std::pair<std::unordered_map<size_t, size_t>, std::unordered_map<size_t, size_t>> generate_occurance_count() const {
            std::unordered_map<size_t, size_t> add_appearances;
            std::unordered_map<size_t, size_t> mul_appearances;
            for (size_t k = 0; k < result.nodes.size(); ++k) {
                const auto& node = result.nodes[k];
                if (std::holds_alternative<dag_addition>(node)) {
                    const auto& add = std::get<dag_addition>(node);
                    for (size_t i = 0; i < add.operands.size(); i++) {
                        add_appearances[add.operands[i]]++;
                    }
                } else if (std::holds_alternative<dag_multiplication>(node)) {
                    const auto& mul = std::get<dag_multiplication>(node);
                    for (size_t i = 0; i < mul.operands.size(); i++) {
                        mul_appearances[mul.operands[i]]++;
                    }
                }
            }
            return {add_appearances, mul_appearances};
        }

        std::pair<co_occurence_map_type, co_occurence_map_type> generate_co_occurence_maps(
                const std::unordered_map<size_t, size_t>& add_occurences,
                const std::unordered_map<size_t, size_t>& mul_occurences) const {
            co_occurence_map_type add_co_occurence_map;
            co_occurence_map_type mul_co_occurence_map;
            for (size_t k = 0; k < result.nodes.size(); ++k) {
                const auto& node = result.nodes[k];
                if (std::holds_alternative<dag_addition>(node)) {
                    const auto& add = std::get<dag_addition>(node);
                    for (size_t i = 0; i < add.operands.size(); i++) {
                        // It's useless to compute co-occurance for something, that appears only once.
                        if (add_occurences.at(add.operands[i]) == 1)
                            continue;
                        for (size_t j = i + 1; j < add.operands.size(); j++) {
                            add_co_occurence_map[std::make_pair(add.operands[i], add.operands[j])]++;
                        }
                    }
                } else if (std::holds_alternative<dag_multiplication>(node)) {
                    const auto& mul = std::get<dag_multiplication>(node);
                    for (size_t i = 0; i < mul.operands.size(); i++) {
                        // It's useless to compute co-occurance for something, that appears only once.
                        if (mul_occurences.at(mul.operands[i]) == 1)
                            continue;
                        for (size_t j = i + 1; j < mul.operands.size(); j++) {
                            mul_co_occurence_map[std::make_pair(mul.operands[i], mul.operands[j])]++;
                        }
                    }
                }
            }

            return {add_co_occurence_map, mul_co_occurence_map};
        }

        // Once we merge children of some nodes, we may have nodes that are unreachable from the root nodes,
        // I.E. they are useless. This function cleans them.
        void remove_unreachable_nodes() {
            std::vector<bool> reachable = get_reachable_nodes();
            std::vector<size_t> new_index(result.nodes.size());
            dag_expression<VariableType> new_result;
            for (size_t k = 0; k < result.nodes.size(); ++k) {
                if (!reachable[k])
                    continue;
                auto& node = result.nodes[k];
                if (std::holds_alternative<dag_addition>(node)) {
                    auto& add = std::get<dag_addition>(node);
                    for (size_t i = 0; i < add.operands.size(); i++) {
                        add.operands[i] = new_index[add.operands[i]];
                    }
                } else if (std::holds_alternative<dag_multiplication>(node)) {
                    auto& mul = std::get<dag_multiplication>(node);
                    for (size_t i = 0; i < mul.operands.size(); i++) {
                        mul.operands[i] = new_index[mul.operands[i]];
                    }
                } else if (std::holds_alternative<dag_negation>(node)) {
                    auto& neg = std::get<dag_negation>(node);
                    neg.operand = new_index[neg.operand];
                }
                auto new_idx = new_result.register_node(std::move(node));
                new_index[k] = new_idx;
            }
            // Move all the root nodes as well.
            new_result.root_nodes = result.root_nodes;
            new_result.root_node_degrees = result.root_node_degrees;
            for (auto& root_id: new_result.root_nodes) {
                root_id = new_index[root_id];
            }
            result = new_result;
        }

        // Returns a vector, 'true' means the node is either a root node, or is reachable from some root node.
        // This is useful in removing all nodes that are no longer reachable from a root node, since they were
        // replaced.
        std::vector<bool> get_reachable_nodes() {
            std::vector<bool> reachable(result.nodes.size(), false);
            for (size_t root_id: result.root_nodes)
                reachable[root_id] = true;
            for (int k = result.nodes.size() - 1; k >= 0; --k) {
                if (!reachable[k])
                    continue;
                auto& node = result.nodes[k];
                if (std::holds_alternative<dag_addition>(node)) {
                    const auto& add = std::get<dag_addition>(node);
                    for (size_t i = 0; i < add.operands.size(); i++) {
                        reachable[add.operands[i]] = true;
                    }
                } else if (std::holds_alternative<dag_multiplication>(node)) {
                    const auto& mul = std::get<dag_multiplication>(node);
                    for (size_t i = 0; i < mul.operands.size(); i++) {
                        reachable[mul.operands[i]] = true;
                    }
                } else if (std::holds_alternative<dag_negation>(node)) {
                    reachable[std::get<dag_negation>(node).operand] = true;
                }
            }
            return reachable;
        }

        /** \breief - Merges children into the parent node if operation matches. For example if the parent node is a multiplication,
         *          and one of it's children is a multiplication as well, it moves the children of that child to the parent.
         *  \param[in] only_those_that_occur_once - if set to true, will only move up children that are not re-used, I.E. this
         *          node is the only parent, so the child can be destroyed later.
         */
        void merge_children(bool only_those_that_occur_once) {
            std::vector<size_t> occurences;
            if (only_those_that_occur_once) {
                dag_child_occurence_counting_visitor<VariableType> v;
                occurences = v.get_occurence_counts(result);
            }

            for (size_t k = 0; k < result.nodes.size(); ++k) {
                auto& node = result.nodes[k];
                if (std::holds_alternative<dag_addition>(node)) {
                    auto& add = std::get<dag_addition>(node);
                    dag_operands_vector_type new_operands;
                    for (size_t i = 0; i < add.operands.size(); i++) {
                        const auto& child_node = result.nodes[add.operands[i]];
                        // If a child node holds addition, 'steal' its children.
                        if (std::holds_alternative<dag_addition>(child_node) &&
                            (!only_those_that_occur_once || occurences[add.operands[i]] == 1)) {

                            const auto& child_add = std::get<dag_addition>(child_node);
                            for (size_t j = 0; j < child_add.operands.size(); j++) {
                                new_operands.push_back(child_add.operands[j]);
                            }
                        } else {
                            new_operands.push_back(add.operands[i]);
                        }
                    }
                    add.operands = new_operands;
                } else if (std::holds_alternative<dag_multiplication>(node)) {
                    auto& mul = std::get<dag_multiplication>(node);
                    dag_operands_vector_type new_operands;
                    for (size_t i = 0; i < mul.operands.size(); i++) {
                        const auto& child_node = result.nodes[mul.operands[i]];
                        // If a child node holds multiplication, 'steal' its children.
                        if (std::holds_alternative<dag_multiplication>(child_node) &&
                            (!only_those_that_occur_once || occurences[mul.operands[i]] == 1)) {

                            const auto& child_mul = std::get<dag_multiplication>(child_node);
                            for (size_t j = 0; j < child_mul.operands.size(); j++) {
                                new_operands.push_back(child_mul.operands[j]);
                            }
                        } else {
                            new_operands.push_back(mul.operands[i]);
                        }
                    }
                    mul.operands = new_operands;
                }
            }
        }

        size_t operator()(const term<VariableType>& t) {
            dag_operands_vector_type children;
            if (t.get_vars().size() == 0 || t.get_coeff() != assignment_type::one()) {
                auto const_idx = result.register_node(dag_constant<VariableType>{t.get_coeff()});
                children.push_back(const_idx);
            }
            // then insert variables
            for (const auto& variable : t.get_vars()) {
                auto var_idx = result.register_node(dag_variable<VariableType>{variable});
                children.push_back(var_idx);
            }
            if (children.size() > 1)
                return result.register_node(dag_multiplication{children});
            return children.front();
        }

        size_t operator()(
                const pow_operation<VariableType>& pow
        ) {
            size_t base = boost::apply_visitor(*this, pow.get_expr().get_expr());
            int power = pow.get_power();

            if (power == 0) {
                return result.register_node(dag_constant<VariableType>{assignment_type::one()});
            }
            if (power == 1) {
                return base;
            }
            if (power < 0) {
                throw std::invalid_argument("Negative powers are not supported in DAG expressions");
            }

            size_t result_node = result.register_node(dag_constant<VariableType>{assignment_type::one()});
            size_t current_base = base;

            while (power > 0) {
                if (power % 2 == 1) {
                    result_node = result.register_node(dag_multiplication{result_node, current_base});
                }
                power /= 2;
                if (power > 0) {
                    current_base = result.register_node(dag_multiplication{current_base, current_base});
                }
            }

            return result_node;
        }

        size_t operator()(const binary_arithmetic_operation<VariableType>& op) {
            size_t left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
            size_t right = boost::apply_visitor(*this, op.get_expr_right().get_expr());

            switch (op.get_op()) {
                case ArithmeticOperator::ADD:
                    return result.register_node(dag_addition{left, right});
                case ArithmeticOperator::SUB:
                    return result.register_node(dag_addition{
                        left, result.register_node(dag_negation{right})});
                case ArithmeticOperator::MULT:
                    return result.register_node(dag_multiplication{left, right});
            }
            throw std::invalid_argument("ArithmeticOperator not found");
        }

    private:
        // We will store all the expressions that are registered here.
        std::vector<math_expression_type> expressions;

        // Used for the visitors. Once build() is called, the dag is temporarily created here,
        // then moved out and returned.
        dag_expression<VariableType> result;
    };

} // namespace nil::crypto3::zk::snark



#endif // CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP
