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
// @file Declaration of expression visitors that are used by the PLONK BBF context & generic component classes
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_EXPRESSION_VISITOR_HELPERS_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_EXPRESSION_VISITOR_HELPERS_HPP

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            // Checks if an expression is just a single variable.
            template<typename VariableType>
            class expression_is_variable_visitor : public boost::static_visitor<bool> {
            public:
                expression_is_variable_visitor() {}

                static bool is_var(const crypto3::math::expression<VariableType>& expr) {
                    expression_is_variable_visitor v = expression_is_variable_visitor();
                    return boost::apply_visitor(v, expr.get_expr());
                }

                bool operator()(const crypto3::math::term<VariableType>& term) {
                    return ((term.get_vars().size() == 1) && term.get_coeff().is_one());
                }

                bool operator()(const crypto3::math::pow_operation<VariableType>& pow) {
                    return false;
                }

                bool operator()(const crypto3::math::binary_arithmetic_operation<VariableType>& op) {
                    return false;
                }
            };

            // Returns the range of rows used by the given expression. The first bool value returns if the expression
            // has any variables or not, I.E. if it's false, the other 2 values have no meaning.
            template<typename VariableType>
            class expression_row_range_visitor : public boost::static_visitor<std::tuple<bool,int32_t,int32_t>> {
            public:
                expression_row_range_visitor() {}

                static std::tuple<bool,int32_t,int32_t> row_range(const crypto3::math::expression<VariableType>& expr) {
                    expression_row_range_visitor v = expression_row_range_visitor();
                    return boost::apply_visitor(v, expr.get_expr());
                }

                std::tuple<bool,int32_t,int32_t> operator()(const crypto3::math::term<VariableType>& term) {
                    bool has_vars = false;
                    int32_t min_row, max_row;

                    if (term.get_vars().size() > 0) {
                        has_vars = true;
                        min_row = term.get_vars()[0].rotation;
                        max_row = term.get_vars()[0].rotation;
                        for(std::size_t i = 1; i < term.get_vars().size(); i++) {
                            min_row = std::min(min_row, term.get_vars()[i].rotation);
                            max_row = std::max(max_row, term.get_vars()[i].rotation);
                        }
                    }
                    return {has_vars, min_row, max_row};
                }

                std::tuple<bool,int32_t,int32_t> operator()(const crypto3::math::pow_operation<VariableType>& pow) {
                    return boost::apply_visitor(*this, pow.get_expr().get_expr());
                }

                std::tuple<bool,int32_t,int32_t> operator()(const crypto3::math::binary_arithmetic_operation<VariableType>& op) {
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
            class expression_relativize_visitor : public boost::static_visitor<crypto3::math::expression<VariableType>> {
            private:
                int32_t shift;
            public:
                expression_relativize_visitor(int32_t shift_) : shift(shift_) {}

                static crypto3::math::expression<VariableType>
                relativize(const crypto3::math::expression<VariableType>& expr, int32_t shift) {
                    expression_relativize_visitor v = expression_relativize_visitor(shift);
                    return boost::apply_visitor(v, expr.get_expr());
                }

                crypto3::math::expression<VariableType>
                operator()(const crypto3::math::term<VariableType>& term) {
                    std::vector<VariableType> vars = term.get_vars();

                    for(std::size_t i = 0; i < vars.size(); i++) {
                        vars[i].relative = true;
                        vars[i].rotation += shift;
                        if (std::abs(vars[i].rotation) > 1) {
                            BOOST_LOG_TRIVIAL(warning) << "Rotation exceeds 1 after relativization in term " << term << ".\n";
                        }
                    }

                    return crypto3::math::term<VariableType>(vars, term.get_coeff());
                }

                crypto3::math::expression<VariableType>
                operator()(const crypto3::math::pow_operation<VariableType>& pow) {
                    return crypto3::math::pow_operation<VariableType>(
                        boost::apply_visitor(*this, pow.get_expr().get_expr()),
                        pow.get_power());
                }

                crypto3::math::expression<VariableType>
                operator()(const crypto3::math::binary_arithmetic_operation<VariableType>& op) {
                    return crypto3::math::binary_arithmetic_operation<VariableType>(
                        boost::apply_visitor(*this, op.get_expr_left().get_expr()),
                        boost::apply_visitor(*this, op.get_expr_right().get_expr()),
                        op.get_op());
                }
            };

            // A visitor for checking that in an expression all variables are absolute or all variables are relative
            template<typename VariableType>
            class expression_relativity_check_visitor : public boost::static_visitor<bool> {
            public:
                expression_relativity_check_visitor(bool relativity_) : relativity(relativity_) {}

                static bool is_absolute(const crypto3::math::expression<VariableType>& expr) {
                    expression_relativity_check_visitor v = expression_relativity_check_visitor(false);
                    return boost::apply_visitor(v, expr.get_expr());
                }
                static bool is_relative(const crypto3::math::expression<VariableType>& expr) {
                    expression_relativity_check_visitor v = expression_relativity_check_visitor(true);
                    return boost::apply_visitor(v, expr.get_expr());
                }

                bool operator()(const crypto3::math::term<VariableType>& term) {
                    bool res = true;

                    for(std::size_t i = 0; i < term.get_vars().size(); i++) {
                        res = res && (term.get_vars()[i].relative == relativity);
                    }
                    return res;
                }

                bool operator()(const crypto3::math::pow_operation<VariableType>& pow) {
                    return boost::apply_visitor(*this, pow.get_expr().get_expr());
                }

                bool operator()(const crypto3::math::binary_arithmetic_operation<VariableType>& op) {
                    bool A_res = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    bool B_res = boost::apply_visitor(*this, op.get_expr_right().get_expr());

                    return A_res && B_res;
                }
            private:
                bool relativity;
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_EXPRESSION_VISITOR_HELPERS_HPP
