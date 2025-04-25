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

#include <boost/container/small_vector.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

namespace nil::crypto3::zk::snark {
    using dag_operands_vector_type = std::vector<std::size_t>;

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
        dag_addition(std::initializer_list<std::size_t> operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }

        bool operator==(const dag_addition& other) const = default;
    };

    struct dag_multiplication {
        dag_operands_vector_type operands;

        dag_multiplication(const dag_operands_vector_type& _operands) : operands(_operands) {
            std::sort(operands.begin(), operands.end());
        }
        dag_multiplication(std::initializer_list<std::size_t> operands_) : operands(operands_) {
            std::sort(operands.begin(), operands.end());
        }

        bool operator==(const dag_multiplication& other) const = default;
    };

    struct dag_negation {
        std::size_t operand;

        dag_negation(std::size_t operand)
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

    // Used for counting max degree of an expression.
    template<typename VariableType>
    class dag_node_hashing_visitor : public boost::static_visitor<std::size_t> {
    public:
        using assignment_type = typename VariableType::assignment_type;

        static const size_t constant_seed = 0x1;
        static const size_t add_seed      = 0x2;
        static const size_t multiply_seed = 0x3;
        static const size_t negation_seed = 0x4;

        dag_node_hashing_visitor() = default;

        std::size_t operator()(const dag_constant<VariableType>& n) const {
            std::size_t seed = constant_seed;
            boost::hash_combine(seed, std::hash<assignment_type>()(n.value));
            return seed;
        }

        std::size_t operator()(const dag_variable<VariableType>& n) const {
            return std::hash<VariableType>()(n.variable);
        }

        std::size_t operator()(const dag_addition& n) const {
            return std::accumulate(n.operands.begin(), n.operands.end(), add_seed, [](size_t a, size_t b) {
                std::size_t seed = a;
                boost::hash_combine(seed, b);
                return seed;
            });
        }
        std::size_t operator()(const dag_multiplication& n) const {
            return std::accumulate(n.operands.begin(), n.operands.end(), multiply_seed, [](size_t a, size_t b) {
                std::size_t seed = a;
                boost::hash_combine(seed, b);
                return seed;
            });
        }
        std::size_t operator()(const dag_negation& n) const {
            std::size_t seed = negation_seed;
            boost::hash_combine(seed, n.operand);
            return seed;
        }
    };

} // namespace nil::crypto3::zk::snark

// Define the hash of a dag_node, so we can use it in dag_expression.
template<typename VariableType>
struct std::hash<nil::crypto3::zk::snark::dag_node<VariableType>> {

    nil::crypto3::zk::snark::dag_node_hashing_visitor<VariableType> visitor;

    std::size_t operator()(const nil::crypto3::zk::snark::dag_node<VariableType> &node) const {
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

        dag_expression() = default;

        size_t get_root_nodes_count() const {
            return root_nodes.size();
        }

        size_t get_nodes_count() const {
            return nodes.size();
        }

        const std::vector<node_type>& get_nodes() const {
            return nodes;
        }

        std::size_t get_root_node(std::size_t i) const {
            return root_nodes[i];
        }

    private:

        std::unordered_map<node_type, size_t> node_map;
        std::vector<std::size_t> root_nodes;
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

    // This class stores all registered expressions, then runs over them as a visitor and
    // builds a DAG for them.
    template<typename VariableType>
    class dag_expression_builder : public boost::static_visitor<std::size_t> {
    public:
        using node_type = dag_node<VariableType>;
        using assignment_type = typename VariableType::assignment_type;

        using math_expression_type = expression<VariableType>;
        using term_type = term<VariableType>;
        using pow_operation_type = pow_operation<VariableType>;
        using binary_arithmetic_operation_type = binary_arithmetic_operation<VariableType>;

        dag_expression_builder() = default;

        std::size_t get_expression_count() const {
            return expressions.size();
        }

        void add_expression(const math_expression_type& expression) {
            expressions.push_back(expression);
        }

        void add_expression(math_expression_type&& expr) {
            expressions.push_back(std::move(expr));
        }

        dag_expression<VariableType> build() {
            for (const auto& expr: expressions) {
                std::size_t root_node = boost::apply_visitor(*this, expr.get_expr());
                result.root_nodes.push_back(root_node);
            }
            return std::move(result);
        }

        std::size_t operator()(const term<VariableType>& t) {
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

        std::size_t operator()(
                const pow_operation<VariableType>& pow) {
            throw std::runtime_error("Power operation is not supported");
        }

        std::size_t operator()(const binary_arithmetic_operation<VariableType>& op) {
            std::size_t left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
            std::size_t right = boost::apply_visitor(*this, op.get_expr_right().get_expr());

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



#endif // PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_HPP
