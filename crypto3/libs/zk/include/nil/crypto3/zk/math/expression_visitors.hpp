//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP

#include <vector>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/non_linear_combination.hpp>

namespace nil::crypto3::zk::snark {

    // Used for counting max degree of an expression.
    template<typename VariableType>
    class expression_max_degree_visitor : public boost::static_visitor<std::uint32_t> {
    public:
        expression_max_degree_visitor() {}

        std::uint32_t compute_max_degree(const expression<VariableType>& expr) const {
            return boost::apply_visitor(*this, expr.get_expr());
        }

        std::uint32_t operator()(const term<VariableType>& t) const {
            return t.get_vars().size();
        }

        std::uint32_t operator()(
                const pow_operation<VariableType>& pow) const {
            std::uint32_t result = boost::apply_visitor(*this, pow.get_expr().get_expr());
            return result * pow.get_power();
        }

        std::uint32_t operator()(
                const binary_arithmetic_operation<VariableType>& op) const {
            std::uint32_t left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
            std::uint32_t right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
            switch (op.get_op()) {
                case ArithmeticOperator::ADD:
                case ArithmeticOperator::SUB:
                    return std::max(left, right);
                case ArithmeticOperator::MULT:
                    return left + right;
                default:
                    throw std::invalid_argument("ArithmeticOperator not found");
            }
        }
    };

    // Runs over the variables of an expression, calling the given callback function
    // for each variable. If a given variable is used multiple times,
    // the callback is called multiple times.
    template<typename VariableType>
    class expression_for_each_variable_visitor : public boost::static_visitor<void> {
    public:
        expression_for_each_variable_visitor(
                std::function<void(const VariableType&)> callback)
            : callback(callback) {}

        void visit(const expression<VariableType>& expr) {
            boost::apply_visitor(*this, expr.get_expr());
        }

        void operator()(const term<VariableType>& t) {
            for (const auto& var: t.get_vars()) {
                callback(var);
            }
        }

        void operator()(
                const pow_operation<VariableType>& pow) {
            boost::apply_visitor(*this, pow.get_expr().get_expr());
        }

        void operator()(const binary_arithmetic_operation<VariableType>& op) {
            boost::apply_visitor(*this, op.get_expr_left().get_expr());
            boost::apply_visitor(*this, op.get_expr_right().get_expr());
        }

        private:
            std::function<void(const VariableType&)> callback;
    };

    // Converts tree-structured expression to flat one, a vector of terms.
    // Used for generating solidity code for constraints, because we want
    // to use minimal number of variables in the stack.
    template<typename VariableType>
    class expression_to_non_linear_combination_visitor
        : public boost::static_visitor<non_linear_combination<VariableType>> {
    public:
        expression_to_non_linear_combination_visitor() {}

        non_linear_combination<VariableType> convert(
                const expression<VariableType>& expr) {
            non_linear_combination<VariableType> result =
                boost::apply_visitor(*this, expr.get_expr());
            result.merge_equal_terms();
            return result;
        }

        non_linear_combination<VariableType> operator()(
                const term<VariableType>& t) {
            return non_linear_combination<VariableType>(t);
        }

        non_linear_combination<VariableType> operator()(
                const pow_operation<VariableType>& pow) {
            non_linear_combination<VariableType> base = boost::apply_visitor(
                *this, pow.get_expr().get_expr());
            non_linear_combination<VariableType> result = base;

            // It does not matter how we compute power here.
            for (int i = 1; i < pow.get_power(); ++i)
            {
                result = result * base;
            }
            return result;
        }

        non_linear_combination<VariableType> operator()(
                const binary_arithmetic_operation<VariableType>& op) {
            non_linear_combination<VariableType> left =
                boost::apply_visitor(*this, op.get_expr_left().get_expr());
            non_linear_combination<VariableType> right =
                boost::apply_visitor(*this, op.get_expr_right().get_expr());
            switch (op.get_op()) {
                case ArithmeticOperator::ADD:
                    return left + right;
                case ArithmeticOperator::SUB:
                    return left - right;
                case ArithmeticOperator::MULT:
                    return left * right;
                default:
                    throw std::invalid_argument("ArithmeticOperator not found");
            }
        }
    };


    // Changes the underlying variable type of an expression. This is useful, when
    // we have a constraint with variable type plonk_variable<AssignmentType>
    // but we need a constraint of variable type
    // plonk_variable<polynomial_dfs<typename FieldType::value_type>>.
    // You can convert between types if the coefficient types are convertable.
    template<typename SourceVariableType, typename DestinationVariableType>
    class expression_variable_type_converter
        : public boost::static_visitor<expression<DestinationVariableType>> {
    public:
        /*
         * @param convert_coefficient - A function that can convert a coefficient of Source Type, into a coefficient
                                        of the destination type.
         */
        expression_variable_type_converter(
            std::function<typename DestinationVariableType::assignment_type(
                const typename SourceVariableType::assignment_type&)> convert_coefficient =
                    [](const typename SourceVariableType::assignment_type& coeff) {return coeff;})
            : _convert_coefficient(convert_coefficient) {
        }

        expression<DestinationVariableType> convert(
                const expression<SourceVariableType>& expr) {
            return boost::apply_visitor(*this, expr.get_expr());
        }

        expression<DestinationVariableType> operator()(
                const term<SourceVariableType>& t) {
            std::vector<DestinationVariableType> vars;
            for (const auto& var: t.get_vars()) {
                vars.emplace_back(
                    var.index, var.rotation, var.relative,
                    static_cast<typename DestinationVariableType::column_type>(static_cast<std::uint8_t>(var.type)));
            }
            return term<DestinationVariableType>(std::move(vars), _convert_coefficient(t.get_coeff()));
        }

        expression<DestinationVariableType> operator()(
                const pow_operation<SourceVariableType>& pow) {
            expression<DestinationVariableType> base = boost::apply_visitor(
                *this, pow.get_expr().get_expr());
            return pow_operation<DestinationVariableType>(base, pow.get_power());
        }

        expression<DestinationVariableType> operator()(
                const binary_arithmetic_operation<SourceVariableType>& op) {
            expression<DestinationVariableType> left =
                boost::apply_visitor(*this, op.get_expr_left().get_expr());
            expression<DestinationVariableType> right =
                boost::apply_visitor(*this, op.get_expr_right().get_expr());
            return binary_arithmetic_operation(std::move(left), std::move(right),
                                               op.get_op());
        }
    private:
        std::function<typename DestinationVariableType::assignment_type(
            const typename SourceVariableType::assignment_type&)> _convert_coefficient;

    };

    // Checks if an expression is just a single variable.
    template<typename VariableType>
    class expression_is_variable_visitor : public boost::static_visitor<bool> {
    public:
        expression_is_variable_visitor() {}

        static bool is_var(const expression<VariableType>& expr) {
            expression_is_variable_visitor v = expression_is_variable_visitor();
            return boost::apply_visitor(v, expr.get_expr());
        }

        bool operator()(const term<VariableType>& t) {
            return ((t.get_vars().size() == 1) && t.get_coeff().is_one());
        }

        bool operator()(const pow_operation<VariableType>& pow) {
            return false;
        }

        bool operator()(const binary_arithmetic_operation<VariableType>& op) {
            return false;
        }
    };

    // Returns the range of rows used by the given expression. The first bool value returns if the expression
    // has any variables or not, I.E. if it's false, the other 2 values have no meaning.
    template<typename VariableType>
    class expression_row_range_visitor : public boost::static_visitor<std::tuple<bool,int32_t,int32_t>> {
    public:
        expression_row_range_visitor() {}

        static std::tuple<bool,int32_t,int32_t> row_range(const expression<VariableType>& expr) {
            expression_row_range_visitor v = expression_row_range_visitor();
            return boost::apply_visitor(v, expr.get_expr());
        }

        std::tuple<bool,int32_t,int32_t> operator()(const term<VariableType>& t) {
            bool has_vars = false;
            int32_t min_row, max_row;

            if (t.get_vars().size() > 0) {
                has_vars = true;
                min_row = t.get_vars()[0].rotation;
                max_row = t.get_vars()[0].rotation;
                for(std::size_t i = 1; i < t.get_vars().size(); i++) {
                    min_row = std::min(min_row, t.get_vars()[i].rotation);
                    max_row = std::max(max_row, t.get_vars()[i].rotation);
                }
            }
            return {has_vars, min_row, max_row};
        }

        std::tuple<bool,int32_t,int32_t> operator()(const pow_operation<VariableType>& pow) {
            return boost::apply_visitor(*this, pow.get_expr().get_expr());
        }

        std::tuple<bool,int32_t,int32_t> operator()(const binary_arithmetic_operation<VariableType>& op) {
            auto [A_has_vars, A_min, A_max] = boost::apply_visitor(*this, op.get_expr_left().get_expr());
            auto [B_has_vars, B_min, B_max] = boost::apply_visitor(*this, op.get_expr_right().get_expr());

            if (!A_has_vars) {
                return {B_has_vars, B_min, B_max};
            }
            if (!B_has_vars) {
                return {A_has_vars, A_min, A_max};
            }
            return {true, std::min(A_min,B_min), std::max(A_max,B_max)};
        }
    };

    // Converts the given expression to become relative to the given row shift using rotations.
    template<typename VariableType>
    class expression_relativize_visitor : public boost::static_visitor<std::optional<expression<VariableType>>> {
    private:
        int32_t shift;
    public:
        expression_relativize_visitor(int32_t shift_) : shift(shift_) {}

        static std::optional<expression<VariableType>>
        relativize(const expression<VariableType>& expr, int32_t shift) {
            expression_relativize_visitor v = expression_relativize_visitor(shift);
            return boost::apply_visitor(v, expr.get_expr());
        }

        std::optional<expression<VariableType>>
        operator()(const term<VariableType>& t) {
            std::vector<VariableType> vars = t.get_vars();

            for(std::size_t i = 0; i < vars.size(); i++) {
                vars[i].relative = true;
                vars[i].rotation += shift;
                // if (std::abs(vars[i].rotation) > 1) {
                //     return std::nullopt;
                // }
            }

            return term<VariableType>(vars, t.get_coeff());
        }

        std::optional<expression<VariableType>>
        operator()(const pow_operation<VariableType>& pow) {
            auto term = boost::apply_visitor(*this, pow.get_expr().get_expr());
            if (!term)
                return std::nullopt;
            return pow_operation<VariableType>(
                *term,
                pow.get_power());
        }

        std::optional<expression<VariableType>>
        operator()(const binary_arithmetic_operation<VariableType>& op) {
            auto left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
            if (!left)
                return std::nullopt;
            auto right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
            if (!right)
                return std::nullopt;
            return binary_arithmetic_operation<VariableType>(
                *left, *right, op.get_op());
        }
    };

    // A visitor for checking that in an expression all variables are absolute or all variables are relative
    template<typename VariableType>
    class expression_relativity_check_visitor : public boost::static_visitor<bool> {
    public:
        expression_relativity_check_visitor(bool relativity_) : relativity(relativity_) {}

        static bool is_absolute(const expression<VariableType>& expr) {
            expression_relativity_check_visitor v = expression_relativity_check_visitor(false);
            return boost::apply_visitor(v, expr.get_expr());
        }
        static bool is_relative(const expression<VariableType>& expr) {
            expression_relativity_check_visitor v = expression_relativity_check_visitor(true);
            return boost::apply_visitor(v, expr.get_expr());
        }

        bool operator()(const term<VariableType>& t) {
            bool res = true;

            for(std::size_t i = 0; i < t.get_vars().size(); i++) {
                res = res && (t.get_vars()[i].relative == relativity);
            }
            return res;
        }

        bool operator()(const pow_operation<VariableType>& pow) {
            return boost::apply_visitor(*this, pow.get_expr().get_expr());
        }

        bool operator()(const binary_arithmetic_operation<VariableType>& op) {
            bool A_res = boost::apply_visitor(*this, op.get_expr_left().get_expr());
            bool B_res = boost::apply_visitor(*this, op.get_expr_right().get_expr());

            return A_res && B_res;
        }
    private:
        bool relativity;
    };

} // namespace nil::crypto3::zk::snark

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
