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
#include <map>
#include <functional>
#include <set>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <variant>

#include <boost/bimap/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/container/small_vector.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            using operands_vector_type = boost::container::small_vector<std::size_t, 2>;

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
                operands_vector_type operands;

                dag_addition(operands_vector_type operands) : operands(operands) {}
                dag_addition(std::initializer_list<std::size_t> operands) : operands(operands) {}

                bool operator==(const dag_addition& other) const {
                    return operands == other.operands;
                }
            };

            struct dag_multiplication {
                operands_vector_type operands;

                dag_multiplication(operands_vector_type operands) : operands(operands) {}
                dag_multiplication(std::initializer_list<std::size_t> operands) : operands(operands) {}

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
                    const size_t constant_seed = 0xf49ed3e8af4e0ed5;
                    const size_t add_seed      = 0x0c40bf797557a37b;
                    const size_t multiply_seed = 0x409879e79890132a;
                    const size_t negation_seed = 0x9c2250db3076ccc2;
                    const size_t variable_seed = 0x4c8f509c18342c3e;

                    return std::visit([&](const dag_node<VariableType>& n) -> size_t {
                        if (std::holds_alternative<dag_constant<VariableType>>(n)) {
                            return constant_seed ^ std::hash<assignment_type>()(std::get<dag_constant<VariableType>>(n).value);
                        } else if (std::holds_alternative<dag_variable<VariableType>>(n)) {
                            return variable_seed ^ std::hash<VariableType>()(std::get<dag_variable<VariableType>>(n).variable);
                        } else if (std::holds_alternative<dag_addition>(n)) {
                            size_t hash = std::accumulate(std::get<dag_addition>(n).operands.begin(), std::get<dag_addition>(n).operands.end(), add_seed, [](size_t a, size_t b) {
                                return a ^ b;
                            });
                        } else if (std::holds_alternative<dag_multiplication>(n)) {
                            size_t hash = std::accumulate(std::get<dag_multiplication>(n).operands.begin(), std::get<dag_multiplication>(n).operands.end(), multiply_seed, [](size_t a, size_t b) {
                                return a ^ b;
                            });
                            return hash;
                        } else if (std::holds_alternative<dag_negation>(n)) {
                            return negation_seed ^ std::hash<std::size_t>()(std::get<dag_negation>(n).operand);
                        }
                        return 0;
                    }, node);
                }
            };

            template<typename VariableType>
            struct dag_expression {
                using node_type = dag_node<VariableType>;
                using node_hash = dag_node_hash<VariableType>;
                using assignment_type = typename VariableType::assignment_type;

                using math_expression_type = math::expression<VariableType>;
                using term_type = math::term<VariableType>;
                using pow_operation_type = math::pow_operation<VariableType>;
                using binary_arithmetic_operation_type = math::binary_arithmetic_operation<VariableType>;

                std::vector<std::size_t> root_nodes;

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

                std::size_t calc_degree() const {
                    std::vector<std::size_t> degrees;
                    std::size_t max_degree = 0;
                    for (const auto& [node, _] : node_map.right) {
                        if (std::holds_alternative<dag_constant<VariableType>>(node)) {
                            degrees.push_back(0);
                        } else if (std::holds_alternative<dag_variable<VariableType>>(node)) {
                            degrees.push_back(1);
                        } else if (std::holds_alternative<dag_addition>(node)) {
                            const auto& add = std::get<dag_addition>(node);
                            auto max_operand_degree = std::accumulate(add.operands.begin(), add.operands.end(), 0, [this, &degrees](std::size_t a, std::size_t b) {
                                return std::max(a, degrees[b]);
                            });
                            degrees.push_back(max_operand_degree);
                        } else if (std::holds_alternative<dag_multiplication>(node)) {
                            const auto& mul = std::get<dag_multiplication>(node);
                            auto sum_of_degrees = std::accumulate(mul.operands.begin(), mul.operands.end(), 0, [this, &degrees](std::size_t a, std::size_t b) {
                                return a + degrees[b];
                            });
                            degrees.push_back(sum_of_degrees);
                        } else if (std::holds_alternative<dag_negation>(node)) {
                            degrees.push_back(degrees[std::get<dag_negation>(node).operand]);
                        }
                        max_degree = std::max(max_degree, degrees.back());
                    }
                    return max_degree;
                }

                std::vector<assignment_type> evaluate(
                    std::function<assignment_type(const VariableType&)> variable_evaluator
                ) {
                    assignments.clear();
                    assignments.reserve(nodes.size());
                    for (const auto& [node, index] : node_map.right) {
                        if (std::holds_alternative<dag_constant<VariableType>>(node)) {
                            assignments.emplace_back(
                                std::get<dag_constant<VariableType>>(node).value);
                        } else if (std::holds_alternative<dag_variable<VariableType>>(node)) {
                            assignments.emplace_back(variable_evaluator(
                                std::get<dag_variable<VariableType>>(node).variable));
                        } else if (std::holds_alternative<dag_addition>(node)) {
                            const auto& add = std::get<dag_addition>(node);
                            assignments.emplace_back(assignments[add.operands[0]]);
                            auto& result = assignments.back();
                            for (std::size_t i = 1; i < add.operands.size(); i++) {
                                result += assignments[add.operands[i]];
                            }
                        } else if (std::holds_alternative<dag_multiplication>(node)) {
                            const auto& mul = std::get<dag_multiplication>(node);
                            assignments.emplace_back(assignments[mul.operands[0]]);
                            auto& result = assignments.back();
                            for (std::size_t i = 1; i < mul.operands.size(); i++) {
                                result *= assignments[mul.operands[i]];
                            }
                        } else if (std::holds_alternative<dag_negation>(node)) {
                            assignments.emplace_back(
                                -assignments[std::get<dag_negation>(node).operand]);
                        }
                    }
                    std::vector<assignment_type> result;
                    for (const auto& root_node : root_nodes) {
                        result.push_back(assignments[root_node]);
                    }
                    return result;
                }

            private:
                using map_type = boost::bimaps::bimap<
                    boost::bimaps::unordered_set_of<node_type, dag_node_hash<VariableType>>,
                    boost::bimaps::set_of<size_t>
                >;

                map_type node_map;
                std::vector<node_type> nodes;
                std::vector<assignment_type> assignments;

                std::size_t convert_expression(const math_expression_type& expression) {
                    auto type_num = expression.get_expr().which();
                    if (type_num == 0) { // term
                        const auto& term = boost::get<term_type>(expression.get_expr());
                        operands_vector_type children;
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
                            return register_node(dag_multiplication{children});
                        }
                        return children.front();
                    }
                    if (type_num == 1) { // pow
                        std::throw_with_nested(std::runtime_error("Power operation is not supported"));
                    }
                    if (type_num == 2) { // binary arithmetic operation
                        const auto& binary_op = boost::get<binary_arithmetic_operation_type>(expression.get_expr());
                        const auto& left = binary_op.get_expr_left();
                        auto left_node = convert_expression(left);
                        const auto& right = binary_op.get_expr_right();

                        using operation_type = binary_arithmetic_operation_type::ArithmeticOperatorType;
                        if (binary_op.get_op() == operation_type::ADD) {
                            auto right_node = convert_expression(right);
                            return register_node(dag_addition{left_node, right_node});
                        }
                        if (binary_op.get_op() == operation_type::MULT) {
                            auto right_node = convert_expression(right);
                            return register_node(dag_multiplication{left_node, right_node});
                        }
                        if (binary_op.get_op() == operation_type::SUB) {
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
                                    auto negated_right_node = register_node(dag_constant<VariableType>{neg_coeff});
                                    auto add = register_node(dag_addition{left_node, negated_right_node});
                                    return add;
                                }
                            }
                            auto right_node = convert_expression(right);
                            auto neg = register_node(dag_negation{right_node});
                            auto add = register_node(dag_addition{left_node, neg});
                            return add;
                        }
                        throw std::runtime_error("Unknown binary arithmetic operation");
                    }
                    throw std::runtime_error("Unknown expression type");
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

        } // namespace math
    } // namespace crypto3
} // namespace nil

#endif // PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP