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

#include <stdexcept>
#include <vector>
#include <functional>
#include <variant>
#include <stack>

#include <boost/bimap/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/container/small_vector.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

namespace nil::crypto3::zk::snark {
    using dag_operands_vector_type = std::vector<std::size_t>;

    template<typename VariableType>
    struct dag_constant {
        using assignment_type = typename VariableType::assignment_type;
        assignment_type value;

        dag_constant(assignment_type value) : value(value) {}

        bool operator==(const dag_constant& other) const {
            return value == other.value;
        }
    };

    template<typename VariableType>
    struct dag_variable {
        VariableType variable;

        dag_variable(VariableType variable) : variable(variable) {}

        bool operator==(const dag_variable& other) const {
            return variable == other.variable;
        }
    };

    struct dag_addition {
        dag_operands_vector_type operands;

        dag_addition(dag_operands_vector_type operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }
        dag_addition(std::initializer_list<std::size_t> operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }

        bool operator==(const dag_addition& other) const {
            return operands == other.operands;
        }
    };

    struct dag_multiplication {
        dag_operands_vector_type operands;

        dag_multiplication(const dag_operands_vector_type& _operands) : operands(_operands) {
            std::sort(operands.begin(), operands.end());
        }
        dag_multiplication(std::initializer_list<std::size_t> operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }

        bool operator==(const dag_multiplication& other) const {
            return operands == other.operands;
        }
    };

    struct dag_negation {
        std::size_t operand;

        dag_negation(std::size_t operand) : operand(operand) {}

        bool operator==(const dag_negation& other) const {
            return operand == other.operand;
        }
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
    struct dag_node_hash {
        using assignment_type = typename VariableType::assignment_type;
        std::size_t operator()(const dag_node<VariableType> &node) const {
            const size_t constant_seed = 0x1;
            const size_t add_seed      = 0x2;
            const size_t multiply_seed = 0x3;
            const size_t negation_seed = 0x4;

            return std::visit([&](const dag_node<VariableType>& n) -> size_t {
                if (std::holds_alternative<dag_constant<VariableType>>(n)) {
                    std::size_t seed = constant_seed;
                    boost::hash_combine(seed, std::hash<assignment_type>()(std::get<dag_constant<VariableType>>(n).value));
                    return seed;
                } else if (std::holds_alternative<dag_variable<VariableType>>(n)) {
                    return std::hash<VariableType>()(std::get<dag_variable<VariableType>>(n).variable);
                } else if (std::holds_alternative<dag_addition>(n)) {
                    size_t hash = std::accumulate(std::get<dag_addition>(n).operands.begin(), std::get<dag_addition>(n).operands.end(), add_seed, [](size_t a, size_t b) {
                        std::size_t seed = a;
                        boost::hash_combine(seed, b);
                        return seed;
                    });
                } else if (std::holds_alternative<dag_multiplication>(n)) {
                    size_t hash = std::accumulate(std::get<dag_multiplication>(n).operands.begin(), std::get<dag_multiplication>(n).operands.end(), multiply_seed, [](size_t a, size_t b) {
                        std::size_t seed = a;
                        boost::hash_combine(seed, b);
                        return seed;
                    });
                } else if (std::holds_alternative<dag_negation>(n)) {
                    std::size_t seed = negation_seed;
                    boost::hash_combine(seed, std::hash<std::size_t>()(std::get<dag_negation>(n).operand));
                    return seed;
                }
                return 0;
            }, node);
        }
    };

    template<typename VariableType>
    struct dag_expression {

        using node_type = dag_node<VariableType>;
        using assignment_type = typename VariableType::assignment_type;

        using math_expression_type = expression<VariableType>;
        using term_type = term<VariableType>;
        using pow_operation_type = pow_operation<VariableType>;
        using binary_arithmetic_operation_type = binary_arithmetic_operation<VariableType>;

        using map_type = boost::bimaps::bimap<
            boost::bimaps::unordered_set_of<node_type, dag_node_hash<VariableType>>,
            boost::bimaps::set_of<size_t>
        >;

        dag_expression() = default;

        dag_expression(const math_expression_type& expression) {
            std::size_t root_node = convert_expression(expression);
            root_nodes.push_back(root_node);
        }

        void add_expression(const math_expression_type& expression) {
            std::size_t root_node = convert_expression(expression);
            root_nodes.push_back(root_node);
        }

        void visit_const(std::function<void(const node_type&)> visitor) const {
            for (const auto& node : nodes) {
                visitor(node);
            }
        }

        size_t get_root_nodes_count() const {
            return root_nodes.size();
        }
        size_t get_nodes_count() const {
            return nodes.size();
        }
        const map_type& get_node_map() const {
            return node_map;
        }
        std::size_t get_root_node(std::size_t i) const {
            return root_nodes[i];
        }

    private:

        map_type node_map;
        std::vector<std::size_t> root_nodes;
        std::vector<node_type> nodes;

        std::size_t convert_expression(const math_expression_type& expression) {
            struct stack_item {
                const math_expression_type* expr;
                std::size_t result_index;
                enum class State { Initial, ProcessingLeft, ProcessingRight } state;
                std::size_t left_node;
            };
            std::stack<stack_item> stack;
            stack.push({&expression, 0, stack_item::State::Initial, 0});

            std::size_t last_result_index = 0;

            while (!stack.empty()) {
                auto& current = stack.top();

                if (current.state == stack_item::State::Initial) {
                    auto type_num = current.expr->get_expr().which();
                    if (type_num == 0) { // term
                        const auto& term = boost::get<term_type>(current.expr->get_expr());
                        dag_operands_vector_type children;
                        // first insert coefficient
                        // note that multiplying by one is superfluous, so we skip it when we can
                        if (term.get_vars().size() == 0 || term.get_coeff() != assignment_type::one()) {
                            auto const_idx = register_node(dag_constant<VariableType>{term.get_coeff()});
                            children.push_back(const_idx);
                        }
                        // then insert variables
                        for (const auto& variable : term.get_vars()) {
                            auto var_idx = register_node(dag_variable<VariableType>{variable});
                            children.push_back(var_idx);
                        }
                        if (children.size() > 1) {
                            current.result_index = register_node(dag_multiplication{children});
                        } else {
                            current.result_index = children.front();
                        }
                        last_result_index = current.result_index;
                        stack.pop();
                    } else if (type_num == 1) { // pow
                        throw std::runtime_error("Power operation is not supported");
                    } else if (type_num == 2) { // binary arithmetic operation
                        const auto& binary_op = boost::get<binary_arithmetic_operation_type>(current.expr->get_expr());
                        const auto& left = binary_op.get_expr_left();
                        // Process left expression first
                        current.state = stack_item::State::ProcessingLeft;
                        stack.push({&left, 0, stack_item::State::Initial, 0});
                    } else {
                        throw std::runtime_error("Unknown expression type");
                    }
                } else if (current.state == stack_item::State::ProcessingLeft) {
                    // Left expression has been processed, get its result
                    current.left_node = last_result_index;

                    const auto& binary_op = boost::get<binary_arithmetic_operation_type>(current.expr->get_expr());
                    const auto& right = binary_op.get_expr_right();

                    using operation_type = binary_arithmetic_operation_type::ArithmeticOperatorType;
                    if (binary_op.get_op() == operation_type::SUB) {
                        auto right_type = right.get_expr().which();
                        if (right_type == 0) {
                            auto right_term = boost::get<term_type>(right.get_expr());
                            // try to remove the negations of zero
                            if (right_term.get_coeff() == assignment_type::zero()) {
                                current.result_index = current.left_node;
                                last_result_index = current.result_index;
                                stack.pop();
                                continue;
                            }
                            if (right_term.get_vars().size() == 0) {
                                // this means that we have to negate the non-zero constant and add it to the left node
                                auto coeff = right_term.get_coeff();
                                auto neg_coeff = -coeff;
                                auto negated_right_node = register_node(dag_constant<VariableType>{neg_coeff});
                                current.result_index = register_node(dag_addition{current.left_node, negated_right_node});
                                last_result_index = current.result_index;
                                stack.pop();
                                continue;
                            }
                        }
                    }
                    // Process right expression
                    current.state = stack_item::State::ProcessingRight;
                    stack.push({&right, 0, stack_item::State::Initial, 0});
                } else if (current.state == stack_item::State::ProcessingRight) {
                    // Both left and right expressions have been processed
                    std::size_t right_node = last_result_index;

                    const auto& binary_op = boost::get<binary_arithmetic_operation_type>(current.expr->get_expr());
                    using operation_type = binary_arithmetic_operation_type::ArithmeticOperatorType;

                    if (binary_op.get_op() == operation_type::ADD) {
                        current.result_index = register_node(dag_addition{current.left_node, right_node});
                    } else if (binary_op.get_op() == operation_type::MULT) {
                        current.result_index = register_node(dag_multiplication{current.left_node, right_node});
                    } else if (binary_op.get_op() == operation_type::SUB) {
                        auto neg = register_node(dag_negation{right_node});
                        current.result_index = register_node(dag_addition{current.left_node, neg});
                    } else {
                        throw std::runtime_error("Unknown binary arithmetic operation");
                    }

                    last_result_index = current.result_index;
                    stack.pop();
                }
            }

            return last_result_index;
        }

        size_t register_node(const node_type& node) {
            auto it = node_map.left.find(node);
            if (it != node_map.left.end()) {
                return it->second;
            }
            size_t index = nodes.size();
            nodes.push_back(node);
            node_map.left.insert(std::make_pair(node, index));
            return index;
        }
    };

} // namespace nil::crypto3::zk::snark

#endif // PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP
