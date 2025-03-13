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

#ifndef PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP
#define PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP

#include <memory>
#include <ostream>
#include <stdexcept>
#include <type_traits>
#include <vector>
#include <unordered_map>
#include <map>
#include <functional>
#include <set>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename DagNodeType>
            struct dag_node_ptr_comparator {
                bool operator()(
                    const std::shared_ptr<DagNodeType> &a,
                    const std::shared_ptr<DagNodeType> &b
                ) const {
                    if (a == nullptr) {
                        return b == nullptr ? false : true;
                    }
                    if (b == nullptr) {
                        return false;
                    }
                    return *a < *b;
                }
            };

            template<typename VariableType>
            struct dag_node {
                using assignment_type = typename VariableType::assignment_type;
                using cmp_type = dag_node_ptr_comparator<dag_node<VariableType>>;
                using map_type = std::map<
                    std::shared_ptr<dag_node<VariableType>>,
                    size_t,
                    dag_node_ptr_comparator<dag_node<VariableType>>
                >;
                virtual assignment_type evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) = 0;
                virtual bool operator==(const dag_node &other) const = 0;
                virtual map_type children() const = 0;
                bool operator!=(const dag_node &other) const {
                    return !(*this == other);
                }
                virtual bool operator<(const dag_node &other) const = 0;
                virtual void clear_cache() = 0;
                // variables < multiplications < additions < negations < constants
                // variables being first means that we can short-circuit more often if selector is 0
                enum class NodeType { Variable, Multiplication, Addition, Negation, Constant };

                virtual NodeType get_type() const = 0;
                virtual void export_expression(std::ostream &os) const = 0;
                bool type_less(const dag_node &other) const {
                    return this->get_type() < other.get_type();
                }

                bool type_match(const dag_node &other) const {
                    return typeid(other) == typeid(*this);
                }

                bool type_mismatch(const dag_node &other) const {
                    return typeid(other) != typeid(*this);
                }

                dag_node() = default;
                dag_node(const dag_node &) = default;
                dag_node(dag_node &&) = default;
                dag_node &operator=(const dag_node &) = default;
                dag_node &operator=(dag_node &&) = default;
                virtual ~dag_node() = default;
            };

            template<typename VariableType>
            std::ostream& operator<<(std::ostream& os, const typename dag_node<VariableType>::NodeType& type) {
                switch (type) {
                    case dag_node<VariableType>::NodeType::Variable:
                        return os << "Variable";
                    case dag_node<VariableType>::NodeType::Constant:
                        return os << "Constant";
                    case dag_node<VariableType>::NodeType::Multiplication:
                        return os << "Multiplication";
                    case dag_node<VariableType>::NodeType::Addition:
                        return os << "Addition";
                    case dag_node<VariableType>::NodeType::Negation:
                        return os << "Negation";
                }
                return os;
            }

            template<typename VariableType>
            struct dag_variable : public dag_node<VariableType> {
                using assignment_type = typename VariableType::assignment_type;
                using base_type = dag_node<VariableType>;
                using map_type = typename base_type::map_type;
                VariableType var;

                dag_variable(const VariableType &_var) : var(_var) {}
                dag_variable(const dag_variable &other) :
                    var(other.var) {}

                virtual base_type::NodeType get_type() const override {
                    return base_type::NodeType::Variable;
                }

                map_type children() const override {
                    return map_type();
                }

                virtual void clear_cache() override {}

                virtual void export_expression(std::ostream &os) const override {
                    os << var;
                }

                virtual assignment_type evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) override {
                    return evaluation_map(var);
                }

                bool operator==(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return false;
                    }
                    return var == static_cast<const dag_variable<VariableType>&>(other).var;
                }

                bool operator<(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return base_type::type_less(other);
                    }
                    return var < static_cast<const dag_variable<VariableType>&>(other).var;
                }

                VariableType variable() const {
                    return var;
                }

                ~dag_variable() = default;
            };

            template<typename VariableType>
            struct dag_constant : public dag_node<VariableType> {
                using assignment_type = typename VariableType::assignment_type;
                using base_type = dag_node<VariableType>;
                using map_type = typename base_type::map_type;
                assignment_type value;

                dag_constant(const assignment_type &_value) :
                    value(_value) {}

                dag_constant(const dag_constant &other) :
                    value(other.value) {}

                virtual base_type::NodeType get_type() const override {
                    return base_type::NodeType::Constant;
                }

                virtual void clear_cache() override {}

                virtual void export_expression(std::ostream &os) const override {
                    // os << value.data;
                }

                virtual assignment_type evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) override {
                    return value;
                }

                map_type children() const override {
                    return map_type();
                }

                bool operator==(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return false;
                    }
                    return value == static_cast<const dag_constant<VariableType>&>(other).value;
                }

                bool operator<(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return base_type::type_less(other);
                    }
                    return value < static_cast<const dag_constant<VariableType>&>(other).value;
                }

                ~dag_constant() = default;
            };

            template<typename VariableType>
            std::shared_ptr<dag_node<VariableType>> count_map_insert(
                typename dag_node<VariableType>::map_type &count_map,
                std::shared_ptr<dag_node<VariableType>> node,
                std::size_t count = 1
            ) {
                auto it = count_map.find(node);
                if (it != count_map.end()) {
                    it->second += count;
                } else {
                    count_map[node] = count;
                }
                return node;
            }

            template<typename VariableType>
            std::size_t count_map_size_with_reps(
                const typename dag_node<VariableType>::map_type &count_map
            ) {
                std::size_t size = 0;
                for (const auto& [key, value] : count_map) {
                    size += value;
                }
                return size;
            }

            template<typename VariableType>
            bool count_map_more_than_one_child_with_reps(
                const typename dag_node<VariableType>::map_type &count_map
            ) {
                if (count_map.size() > 1) {
                    return true;
                }
                for (const auto& [key, value] : count_map) {
                    if (value > 1) {
                        return true;
                    }
                    // note that we only have a single element in the map
                    // this break is a hint to the compiler
                    break;
                }
                return false;
            }

            template<typename VariableType>
            int count_map_cmp(
                const std::map<std::shared_ptr<dag_node<VariableType>>,
                        size_t, dag_node_ptr_comparator<dag_node<VariableType>>
                > &a,
                const std::map<std::shared_ptr<dag_node<VariableType>>,
                        size_t, dag_node_ptr_comparator<dag_node<VariableType>>
                > &b
            ) {
                if (a.size() != b.size()) {
                    return a.size() < b.size() ? -1 : 1;
                }
                for (const auto& [key, value] : a) {
                    if (b.find(key) == b.end()) {
                        return -1;
                    }
                    if (value != b.at(key)) {
                        return value < b.at(key) ? -1 : 1;
                    }
                }
                return 0;
            }

            template<typename VariableType>
            struct dag_op : public dag_node<VariableType> {
                using assignment_type = typename VariableType::assignment_type;
                using base_type = dag_node<VariableType>;
                using map_type = typename base_type::map_type;
                using NodeType = typename base_type::NodeType;
                map_type children_map;
                std::optional<assignment_type> result;

                dag_op() = default;

                map_type children() const override {
                    return children_map;
                }

                dag_op(const map_type &_children) :
                    children_map(_children) {}

                dag_op(const dag_op &other) :
                    children_map(other.children_map) {}

                void add_child(std::shared_ptr<dag_node<VariableType>> child) {
                    count_map_insert(children_map, child);
                    result = std::nullopt;
                }

                virtual void clear_cache() override {
                    result = std::nullopt;
                }

                virtual void export_expression(std::ostream &os) const override {
                    os << "(";
                    switch (this->get_type()) {
                        case NodeType::Addition:
                            os << "+";
                            break;
                        case NodeType::Multiplication:
                            os << "*";
                            break;
                        default:
                            __builtin_unreachable();
                            os << "Unknown";
                            break;
                    }
                    for (const auto& child : this->children()) {
                        os << " ";
                        child.first->export_expression(os);
                    }
                    os << ")";
                }
                ~dag_op() = default;
            };

            template<typename VariableType>
            void count_map_remove(
                std::map<std::shared_ptr<dag_node<VariableType>>,
                        size_t, dag_node_ptr_comparator<dag_node<VariableType>>
                > &count_map,
                std::shared_ptr<dag_node<VariableType>> node,
                std::size_t count = 1
            ) {
                auto it = count_map.find(node);
                if (it != count_map.end()) {
                    it->second -= count;
                    if (it->second == 0) {
                        // set the result to nullptr to remove cache if we have cache
                        auto mb_op = std::dynamic_pointer_cast<dag_op<VariableType>>(it->first);
                        if (mb_op != nullptr) {
                            mb_op->result = std::nullopt;
                        }
                        count_map.erase(it);
                    }
                }
            }

            template<typename VariableType>
            struct dag_add : public dag_op<VariableType> {
                using dag_op<VariableType>::children;
                using map_type = typename dag_op<VariableType>::map_type;
                using assignment_type = typename VariableType::assignment_type;
                using base_type = dag_op<VariableType>;
                dag_add(const map_type &_children) :
                    dag_op<VariableType>(_children) {}

                dag_add(const std::vector<std::shared_ptr<dag_node<VariableType>>> &children) {
                    for (const auto& child : children) {
                        base_type::add_child(child);
                    }
                }

                virtual base_type::NodeType get_type() const override {
                    return base_type::NodeType::Addition;
                }

                void power(
                    std::optional<assignment_type> &result,
                    const assignment_type &operand,
                    std::size_t power
                ) const {
                    for (std::size_t i = 0; i < power; ++i) {
                        result = result.value() + operand;
                    }
                }

                virtual assignment_type evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) override {
                    if (this->result != std::nullopt) {
                        return this->result.value();
                    }
                    auto it = base_type::children_map.begin();
                    auto first_child_res = it->first->evaluate(evaluation_map);
                    this->result = first_child_res;
                    power(this->result, first_child_res, it->second - 1);
                    for (++it; it != base_type::children_map.end(); ++it) {
                        auto child_res = it->first->evaluate(evaluation_map);
                        power(this->result, child_res, it->second);
                    }
                    return this->result.value();
                }

                bool operator==(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return false;
                    }
                    return base_type::children_map == static_cast<const dag_add<VariableType>&>(other).children_map;
                }

                bool operator<(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return base_type::type_less(other);
                    }
                    return this->children_map < static_cast<const dag_add<VariableType>&>(other).children_map;
                }

                ~dag_add() = default;
            };

            template<typename VariableType>
            struct dag_mul : public dag_op<VariableType> {
                using dag_op<VariableType>::children;
                using map_type = typename dag_op<VariableType>::map_type;
                using assignment_type = typename VariableType::assignment_type;
                using base_type = dag_op<VariableType>;
                dag_mul(const map_type &_children) :
                    dag_op<VariableType>(_children) {}

                dag_mul(const std::vector<std::shared_ptr<dag_node<VariableType>>> &children) {
                    for (const auto& child : children) {
                        base_type::add_child(child);
                    }
                }

                virtual base_type::NodeType get_type() const override {
                    return base_type::NodeType::Multiplication;
                }

                void power(
                    std::optional<assignment_type> &result,
                    const assignment_type &operand,
                    std::size_t power
                ) const {
                    for (std::size_t i = 0; i < power; ++i) {
                        result = result.value() * operand;
                    }
                }

                virtual assignment_type evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) override {
                    if (this->result != std::nullopt) {
                        return this->result.value();
                    }
                    auto it = base_type::children_map.begin();
                    auto first_child_res = it->first->evaluate(evaluation_map);
                    this->result = first_child_res;
                    if (first_child_res == assignment_type::zero()) { // short-circuiting here if zero
                        return first_child_res;
                    }
                    power(this->result, first_child_res, it->second - 1);
                    for (++it; it != base_type::children_map.end(); ++it) {
                        auto child_res = it->first->evaluate(evaluation_map);
                        power(this->result, child_res, it->second);
                    }
                    return this->result.value();
                }

                bool operator==(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return false;
                    }
                    return this->children_map == static_cast<const dag_mul<VariableType>&>(other).children_map;
                }

                bool operator<(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return base_type::type_less(other);
                    }
                    return this->children_map < static_cast<const dag_mul<VariableType>&>(other).children_map;
                }

                ~dag_mul() = default;
            };

            template<typename VariableType>
            struct dag_negate : public dag_node<VariableType>{
                using assignment_type = typename VariableType::assignment_type;
                using base_type = dag_node<VariableType>;
                using map_type = typename base_type::map_type;
                std::optional<assignment_type> result;
                std::shared_ptr<dag_node<VariableType>> child;
                dag_negate(const std::shared_ptr<dag_node<VariableType>> _child) :
                    child(_child) {}

                virtual base_type::NodeType get_type() const override {
                    return base_type::NodeType::Negation;
                }

                virtual void export_expression(std::ostream &os) const override {
                    os << "(- ";
                    child->export_expression(os);
                    os << ")";
                }

                virtual assignment_type evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) override {
                    if (this->result != std::nullopt) {
                        return this->result.value();
                    }
                    this->result = -(child->evaluate(evaluation_map));
                    return this->result.value();
                }

                map_type children() const override {
                    return map_type({{child, 1}});
                }

                virtual void clear_cache() override {
                    result = std::nullopt;
                }

                bool operator==(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return false;
                    }
                    return *child == *(static_cast<const dag_negate<VariableType>&>(other).child);
                }

                bool operator<(const dag_node<VariableType> &other) const override {
                    if (base_type::type_mismatch(other)) {
                        return base_type::type_less(other);
                    }
                    return *child < *(static_cast<const dag_negate<VariableType>&>(other).child);
                }

                ~dag_negate() = default;
            };

            template<typename VariableType>
            struct dag_expression {
                using assignment_type = typename VariableType::assignment_type;
                using node_type = dag_node<VariableType>;
                using map_type = typename node_type::map_type;
                // for translating math::expression to dag_expression
                using math_expression_type = math::expression<VariableType>;
                using term_type = math::term<VariableType>;
                using pow_operation_type = math::pow_operation<VariableType>;
                using binary_arithmetic_operation_type = math::binary_arithmetic_operation<VariableType>;

                map_type ops;
                std::vector<std::shared_ptr<node_type>> root_nodes;

                dag_expression() = default;
                dag_expression(math_expression_type expr) {
                    add_expression(expr);
                }
                ~dag_expression() = default;

                std::shared_ptr<dag_node<VariableType>> add_expression(const math_expression_type &expr) {
                    root_nodes.push_back(add_expression_rec(expr));
                    return root_nodes.back();
                }

                bool operator==(const dag_expression<VariableType> &other) const {
                    return root_nodes == other.root_nodes;
                }

                std::size_t calc_degree() const {
                    std::size_t degree = 0;
                    for (const auto& root_node : root_nodes) {
                        degree = std::max(degree, calc_degree_rec(root_node));
                    }
                    return degree;
                }

                // used for debugging, and seeing how much caching actually happens
                void print_repeat_info() const {
                    using node_type = typename dag_node<VariableType>::NodeType;
                    std::unordered_map<node_type, std::size_t> total_ops;
                    std::unordered_map<node_type, std::size_t> unique_ops;

                    for (const auto& [node, count] : ops) {
                        auto type = node->get_type();
                        total_ops[type] += count;
                        unique_ops[type]++;
                    }
                    for (const auto& [type, count] : total_ops) {
                        std::cout << "Total " << print_node_type<VariableType>(type)
                                  << " ops: " << count << std::endl;
                        std::cout << "Unique " << print_node_type<VariableType>(type)
                                  << " ops: " << unique_ops[type] << std::endl;
                    }
                }

                void export_expression(std::ostream &os) const {
                    for (const auto& root_node : root_nodes) {
                        root_node->export_expression(os);
                        os << std::endl;
                    }
                }

                void export_expression_to_file(const std::string &filename) const {
                    std::ofstream file(filename);
                    if (!file.is_open()) {
                        throw std::runtime_error("Failed to open file: " + filename);
                    }
                    export_expression(file);
                    file.close();
                }

                void visit_const(const std::function<void(std::shared_ptr<dag_node<VariableType>>)> &func) const {
                    for (const auto& root_node : root_nodes) {
                        visit_const_rec(root_node, func);
                    }
                }

                template<typename NewVariableType>
                dag_expression<NewVariableType> convert_to(
                    std::function<NewVariableType(const VariableType &)>& convert_var,
                    std::function<typename NewVariableType::assignment_type(const typename VariableType::assignment_type &)>&
                        convert_const
                ) const {
                    dag_expression<NewVariableType> result;
                    for (const auto& root_node : root_nodes) {
                        result.root_nodes.push_back(
                            convert_to_rec<NewVariableType>(root_node, convert_var, convert_const)
                        );
                    }
                    return result;
                }

                virtual std::vector<assignment_type> evaluate(
                    std::function<assignment_type(const VariableType&)> &evaluation_map
                ) {
                    std::vector<assignment_type> result;
                    // originally i thought about clearing the ops map after evaluation,
                    // but it's slower that way
                    //map_type mem_map_copy = ops;
                    for (const auto& root_node : root_nodes) {
                        //result.push_back(evaluate_rec(root_node->child, mem_map_copy, evaluation_map));
                        result.push_back(root_node->evaluate(evaluation_map));
                    }
                    return result;
                }

                dag_expression(const dag_expression& other) {
                    std::unordered_map<std::shared_ptr<node_type>, std::shared_ptr<node_type>> node_map;

                    for (const auto& root_node : other.root_nodes) {
                        auto copied_root = deep_copy_node(root_node, node_map);
                        root_nodes.push_back(copied_root);
                    }
                }

                dag_expression& operator=(const dag_expression& other) {
                    if (this != &other) {
                        // Create a temporary copy and swap
                        dag_expression temp(other);
                        ops = std::move(temp.ops);
                        root_nodes = std::move(temp.root_nodes);
                    }
                    return *this;
                }

                void clear_cache() {
                    for (const auto& [key, value] : ops) {
                        key->clear_cache();
                    }
                }
            private:
                void visit_const_rec(
                    std::shared_ptr<dag_node<VariableType>> node,
                    const std::function<void(std::shared_ptr<dag_node<VariableType>>)> &func
                ) const {
                    if (node == nullptr) {
                        return;
                    }
                    func(node);
                    for (const auto& [child, _] : node->children()) {
                        visit_const_rec(child, func);
                    }
                }

                template<typename NewVariableType>
                std::shared_ptr<dag_node<NewVariableType>> convert_to_rec(
                    std::shared_ptr<dag_node<VariableType>> node,
                    std::function<NewVariableType(const VariableType &)>& convert_var,
                    std::function<typename NewVariableType::assignment_type(const typename VariableType::assignment_type &)>&
                        convert_const
                ) const {
                    if (node == nullptr) {
                        return nullptr;
                    }
                    auto const_try = std::dynamic_pointer_cast<dag_constant<VariableType>>(node);
                    if (const_try != nullptr) {
                        return std::make_shared<dag_constant<NewVariableType>>(
                            convert_const(const_try->value));
                    }
                    using new_map_type = dag_node<NewVariableType>::map_type;
                    auto add_try = std::dynamic_pointer_cast<dag_add<VariableType>>(node);
                    if (add_try != nullptr) {
                        new_map_type children;
                        auto children_map = add_try->children();
                        for (const auto& [child, amount] : children_map) {
                            auto converted = convert_to_rec<NewVariableType>(child, convert_var, convert_const);
                            count_map_insert(children, converted, amount);
                        }
                        return std::make_shared<dag_add<NewVariableType>>(children);
                    }
                    auto mul_try = std::dynamic_pointer_cast<dag_mul<VariableType>>(node);
                    if (mul_try != nullptr) {
                        new_map_type children;
                        auto children_map = mul_try->children();
                        for (const auto& [child, amount] : children_map) {
                            auto converted = convert_to_rec<NewVariableType>(child, convert_var, convert_const);
                            count_map_insert(children, converted, amount);
                        }
                        return std::make_shared<dag_mul<NewVariableType>>(children);
                    }
                    auto neg_try = std::dynamic_pointer_cast<dag_negate<VariableType>>(node);
                    if (neg_try != nullptr) {
                        auto converted = convert_to_rec<NewVariableType>(neg_try->child, convert_var, convert_const);
                        return std::make_shared<dag_negate<NewVariableType>>(converted);
                    }
                    auto var_try = std::dynamic_pointer_cast<dag_variable<VariableType>>(node);
                    if (var_try != nullptr) {
                        return std::make_shared<dag_variable<NewVariableType>>(
                            convert_var(var_try->var));
                    }
                    return nullptr;
                }

                std::shared_ptr<node_type> deep_copy_node(
                    const std::shared_ptr<node_type>& node,
                    std::unordered_map<std::shared_ptr<node_type>, std::shared_ptr<node_type>>& node_map
                ) {
                    // Check if we've already copied this node
                    auto it = node_map.find(node);
                    if (it != node_map.end()) {
                        return insert_op(it->second);
                    }

                    // Copy the node based on its concrete type
                    std::shared_ptr<node_type> new_node;

                    // Handle constants
                    auto const_try = std::dynamic_pointer_cast<dag_constant<VariableType>>(node);
                    if (const_try != nullptr) {
                        new_node = std::make_shared<dag_constant<VariableType>>(const_try->value);
                    }
                    auto var_try = std::dynamic_pointer_cast<dag_variable<VariableType>>(node);
                    if (var_try != nullptr) {
                        new_node = std::make_shared<dag_variable<VariableType>>(var_try->var);
                    }
                    auto add_try = std::dynamic_pointer_cast<dag_add<VariableType>>(node);
                    if (add_try != nullptr) {
                        typename node_type::map_type new_children;
                        for (const auto& [child, count] : add_try->children()) {
                            auto copied_child = deep_copy_node(child, node_map);
                            count_map_insert(new_children, copied_child, count);
                        }
                        new_node = std::make_shared<dag_add<VariableType>>(new_children);
                    }
                    auto mul_try = std::dynamic_pointer_cast<dag_mul<VariableType>>(node);
                    if (mul_try != nullptr) {
                        typename node_type::map_type new_children;
                        for (const auto& [child, count] : mul_try->children()) {
                            auto copied_child = deep_copy_node(child, node_map);
                            count_map_insert(new_children, copied_child, count);
                        }
                        new_node = std::make_shared<dag_mul<VariableType>>(new_children);
                    }
                    auto neg_try = std::dynamic_pointer_cast<dag_negate<VariableType>>(node);
                    if (neg_try != nullptr) {
                        new_node = std::make_shared<dag_negate<VariableType>>(
                            deep_copy_node(neg_try->child, node_map)
                        );
                    }

                    node_map[node] = new_node;
                    insert_op(new_node);

                    return new_node;
                }

                std::shared_ptr<assignment_type> evaluate_rec(
                    std::shared_ptr<dag_node<VariableType>> node,
                    map_type &mem_map_copy,
                    std::function<std::shared_ptr<assignment_type>(const VariableType&)> &evaluation_map
                ) const {
                    for (const auto& [child, _] : node->children()) {
                        evaluate_rec(child, mem_map_copy, evaluation_map);
                    }
                    auto result = node->evaluate(evaluation_map);
                    //count_map_remove(mem_map_copy, node);
                    return result;
                }

                std::size_t calc_degree_rec(std::shared_ptr<dag_node<VariableType>> node) const {
                    std::size_t degree = 0;
                    auto const_try = std::dynamic_pointer_cast<dag_constant<VariableType>>(node);
                    if (const_try != nullptr) {
                        return 0;
                    }
                    auto var_try = std::dynamic_pointer_cast<dag_variable<VariableType>>(node);
                    if (var_try != nullptr) {
                        return 1;
                    }
                    auto mul_try = std::dynamic_pointer_cast<dag_mul<VariableType>>(node);
                    if (mul_try != nullptr) {
                        for (const auto& [child, amount] : mul_try->children()) {
                            const auto child_degree = calc_degree_rec(child);
                            degree += child_degree * amount;
                        }
                        return degree;
                    }
                    auto add_try = std::dynamic_pointer_cast<dag_add<VariableType>>(node);
                    if (add_try != nullptr) {
                        for (const auto& [child, _] : add_try->children()) {
                            degree = std::max(degree, calc_degree_rec(child));
                        }
                        return degree;
                    }
                    auto neg_try = std::dynamic_pointer_cast<dag_negate<VariableType>>(node);
                    if (neg_try != nullptr) {
                        return calc_degree_rec(neg_try->child);
                    }
                    return 0;
                }

                std::shared_ptr<dag_node<VariableType>> insert_op(std::shared_ptr<dag_node<VariableType>> node) {
                    auto it = ops.find(node);
                    if (it != ops.end()) {
                        it->second++;
                        return it->first;
                    } else {
                        return (ops.insert({node, 1}).first)->first;
                    }
                }

                std::shared_ptr<node_type> add_expression_rec(const math_expression_type &expr) {
                    auto type_num = expr.get_expr().which();
                    if (type_num == 0) { // term
                        const auto& term = boost::get<term_type>(expr.get_expr());
                        map_type children;
                        // first insert coefficient
                        // note that multiplying by one is superfluous, so we skip it when we can
                        if (term.get_vars().size() == 0 || term.get_coeff() != assignment_type::one()) {
                            auto const_it = insert_op(
                                std::make_shared<dag_constant<VariableType>>(term.get_coeff())
                            );
                            count_map_insert(children, const_it);
                        }
                        // then insert variables
                        for (const auto& variable : term.get_vars()) {
                            auto var_it = insert_op(
                                std::make_shared<dag_variable<VariableType>>(variable)

                            );
                            count_map_insert(children, var_it);
                        }
                        // note that we may have a single element in the map, but with a count greater than one
                        if (count_map_more_than_one_child_with_reps<VariableType>(children)) {
                            auto mul = std::make_shared<dag_mul<VariableType>>(children);
                            auto mul_it = insert_op(mul);
                            return mul_it;
                        } else {
                            return children.begin()->first;
                        }
                    } else if (type_num == 1) { // pow
                        throw std::runtime_error("pow operation currently not supported");
                    } else if (type_num == 2) { // binary arithmetic operation
                        const auto& binary_op = boost::get<binary_arithmetic_operation_type>(expr.get_expr());
                        const auto& left = binary_op.get_expr_left();
                        auto left_node = add_expression_rec(left);
                        const auto& right = binary_op.get_expr_right();
                        auto right_node = add_expression_rec(right);

                        using operation_type = binary_arithmetic_operation_type::ArithmeticOperatorType;
                        const auto& op = binary_op.get_op();
                        if (op == operation_type::ADD) {
                            auto add = std::make_shared<dag_add<VariableType>>(
                                std::vector<std::shared_ptr<dag_node<VariableType>>>(
                                    {left_node, right_node}));
                            auto add_it = insert_op(add);
                            return add_it;
                        } else if (op == operation_type::SUB) {
                            auto right_type = right.get_expr().which();
                            if (right_type == 0) {
                                auto right_term = boost::get<term_type>(right.get_expr());
                                // try to remove the negations of zero
                                // yes, those happen somehow?
                                if (right_term.get_coeff() == assignment_type::zero()) {
                                    return left_node;
                                }
                                if (right_term.get_vars().size() == 0) {
                                    // this means that we have to neagate the non-zero constant and add it to the left node
                                    auto coeff = right_term.get_coeff();
                                    auto neg_coeff = -coeff;
                                    auto negated_right_node =
                                        std::make_shared<dag_constant<VariableType>>(
                                            neg_coeff);
                                    auto negated_right_it = insert_op(negated_right_node);
                                    auto add = std::make_shared<dag_add<VariableType>>(
                                        std::vector<
                                            std::shared_ptr<dag_node<VariableType>>>(
                                            {left_node, negated_right_it}));
                                    auto add_it = insert_op(add);
                                    return add_it;
                                }
                            }
                            auto neg =
                                std::make_shared<dag_negate<VariableType>>(right_node);
                            auto neg_it = insert_op(neg);
                            auto add = std::make_shared<dag_add<VariableType>>(
                                std::vector<std::shared_ptr<dag_node<VariableType>>>(
                                    {left_node, neg_it}));
                            auto add_it = insert_op(add);
                            return add_it;
                        } else if (op == operation_type::MULT) {
                            auto mul = std::make_shared<dag_mul<VariableType>>(
                                std::vector<std::shared_ptr<dag_node<VariableType>>>(
                                    {left_node, right_node}));
                            auto mul_it = insert_op(mul);
                            return mul_it;
                        }
                        throw std::runtime_error("Unknown binary arithmetic operation");
                    }
                    throw std::runtime_error("Unknown math expression type");
                }
            };

            template<typename VariableType>
            std::string print_node_type(const typename dag_node<VariableType>::NodeType &node_type) {
                using type = typename dag_node<VariableType>::NodeType;
                std::stringstream ss;
                switch (node_type) {
                    case type::Variable:
                        ss << "Variable";
                        break;
                    case type::Constant:
                        ss << "Constant";
                        break;
                    case type::Multiplication:
                        ss << "Multiplication";
                        break;
                    case type::Addition:
                        ss << "Addition";
                        break;
                    case type::Negation:
                        ss << "Negation";
                        break;
                    default:
                        ss << "Unknown";
                        break;
                }
                return ss.str();
            }

            template<typename VariableType>
            std::ostream& operator<<(
                std::ostream& os, const std::shared_ptr<dag_node<VariableType>> &node
            ) {
                if (node == nullptr) {
                    os << "nullptr";
                    return os;
                }
                auto mb_var = std::dynamic_pointer_cast<dag_variable<VariableType>>(node);
                if (mb_var != nullptr) {
                    os << mb_var->variable();
                    return os;
                }
                auto mb_const = std::dynamic_pointer_cast<dag_constant<VariableType>>(node);
                if (mb_const != nullptr) {
                    os << *(mb_const->value);
                    return os;
                }
                auto mb_add = std::dynamic_pointer_cast<dag_add<VariableType>>(node);
                if (mb_add != nullptr) {
                    os << "(";
                    auto children = mb_add->children();
                    for (auto it = children.begin(); it != children.end(); ++it) {
                        const auto& [child, amount] = *it;
                        for (std::size_t i = 0; i < amount; ++i) {
                            os << child;
                            if (i != amount - 1) {
                                os << " + ";
                            }
                            if (std::next(it) != children.end()) {
                                os << " + ";
                            }
                        }
                    }
                    os << ")";
                    return os;
                }
                auto mb_mul = std::dynamic_pointer_cast<dag_mul<VariableType>>(node);
                if (mb_mul != nullptr) {
                    os << "(";
                    auto children = mb_mul->children();
                    for (auto it = children.begin(); it != children.end(); ++it) {
                        const auto& [child, amount] = *it;
                        for (std::size_t i = 0; i < amount; ++i) {
                            os << child;
                            if (i != amount - 1) {
                                os << " * ";
                            }
                        }
                        if (std::next(it) != children.end()) {
                            os << " * ";
                        }
                    }
                    os << ")";
                    return os;
                }
                auto mb_neg = std::dynamic_pointer_cast<dag_negate<VariableType>>(node);
                if (mb_neg != nullptr) {
                    os << "-(" << mb_neg->child << ")";
                    return os;
                }
                throw std::runtime_error("Unknown dag node type");
            }
        } // namespace math
    } // namespace crypto3
} // namespace nil

#endif // PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP