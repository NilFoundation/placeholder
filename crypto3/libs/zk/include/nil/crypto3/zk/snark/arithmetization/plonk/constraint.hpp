//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_CONSTRAINT_HPP
#define CRYPTO3_ZK_PLONK_CONSTRAINT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

#include <map>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename VariableType>
                    using plonk_evaluation_map =
                        std::map<std::tuple<std::size_t, int, typename VariableType::column_type>,
                                 typename VariableType::assignment_type>;

                }    // namespace detail

                /************************* PLONK constraint ***********************************/

                template<typename FieldType, typename VariableType = plonk_variable<typename FieldType::value_type>>
                class plonk_constraint : public expression<VariableType> {
                public:
                    typedef FieldType field_type;
                    typedef VariableType variable_type;
                    typedef expression<VariableType> base_type;

                    plonk_constraint()
                        : expression<VariableType>(VariableType::assignment_type::zero()) {
                    };

                    plonk_constraint(const VariableType &var) : expression<VariableType>(var) {
                    }

                    plonk_constraint(const expression<VariableType> &nlc) :
                        expression<VariableType>(nlc) {
                    }

                    plonk_constraint(const term<VariableType> &nlt) :
                        expression<VariableType>(nlt) {
                    }

                    plonk_constraint(const std::vector<term<VariableType>> &terms) :
                        expression<VariableType>(VariableType::assignment_type::zero()) {
                        for (const auto& term : terms) {
                            (*this) += term;
                        }
                    }

                    // Constructor for integral types.
                    template<class NumericType>
                    plonk_constraint(const NumericType& coeff,
                            typename std::enable_if<std::is_integral<NumericType>::value, NumericType>::type* = nullptr)
                        : expression<VariableType>(coeff) {
                    }

                    // Constructor for big_uint.
                    template<std::size_t Bits>
                    plonk_constraint(const nil::crypto3::multiprecision::big_uint<Bits> &coeff)
                        : expression<VariableType>(coeff) {
                    }

                    plonk_constraint(const typename VariableType::assignment_type &coeff)
                        : expression<VariableType>(coeff) {
                    }

                    typename VariableType::assignment_type
                        evaluate(std::size_t row_index,
                                 const plonk_assignment_table<FieldType> &assignments) const {
                        expression_evaluator<VariableType> evaluator(
                            *this,
                            [&assignments, row_index](const VariableType &var) -> const typename VariableType::assignment_type& {
                                std::size_t rows_amount = assignments.rows_amount();
                                switch (var.type) {
                                    case VariableType::column_type::witness:
                                        return assignments.witness(var.index)[(rows_amount + row_index + var.rotation) % rows_amount];
                                    case VariableType::column_type::public_input:
                                        return assignments.public_input(var.index)[(rows_amount + row_index + var.rotation) % rows_amount];
                                    case VariableType::column_type::constant:
                                        return assignments.constant(var.index)[(rows_amount + row_index + var.rotation) % rows_amount];
                                    case VariableType::column_type::selector:
                                        return assignments.selector(var.index)[(rows_amount + row_index + var.rotation) % rows_amount];
                                    default:
                                        std::cerr << "Invalid column type" << std::endl;
                                        abort();
                                }
                            });

                        return evaluator.evaluate();
                    }

                    math::polynomial<typename VariableType::assignment_type>
                       evaluate(const plonk_polynomial_table<FieldType> &assignments,
                                std::shared_ptr<math::evaluation_domain<FieldType>> domain) const {
                        using polynomial_type = math::polynomial<typename VariableType::assignment_type>;
                        using polynomial_variable_type = plonk_variable<polynomial_type>;

                        // Convert scalar values to polynomials inside the expression.
                        expression_variable_type_converter<VariableType, polynomial_variable_type> converter;
                        auto converted_expression = converter.convert(*this);

                        // For each variable with a rotation pre-compute its value.
                        std::unordered_map<polynomial_variable_type, polynomial_type> rotated_variable_values;

                        expression_for_each_variable_visitor<polynomial_variable_type> visitor(
                            [&rotated_variable_values, &assignments, &domain](const polynomial_variable_type& var) {
                                if (var.rotation == 0)
                                    return;
                                rotated_variable_values[var] = assignments.get_variable_value(var, domain);
                        });
                        visitor.visit(converted_expression);

                        expression_evaluator<polynomial_variable_type> evaluator(
                            converted_expression,
                            [&domain, &assignments, &rotated_variable_values]
                            (const VariableType &var) -> const polynomial_type& {
                                if (var.rotation == 0) {
                                    return assignments.get_variable_value_without_rotation(var, domain);
                                }
                                return rotated_variable_values[var];
                            });
                        return evaluator.evaluate();
                    }

                    math::polynomial_dfs<typename VariableType::assignment_type>
                        evaluate(const plonk_polynomial_dfs_table<FieldType> &assignments,
                                 std::shared_ptr<math::evaluation_domain<FieldType>> domain) const {
                        using polynomial_dfs_type = math::polynomial_dfs<typename VariableType::assignment_type>;
                        using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;

                        // Convert scalar values to polynomials inside the expression.
                        expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            [&assignments](const typename VariableType::assignment_type& coeff) {
                                polynomial_dfs_type(0, assignments.rows_amount(), coeff);
                            });

                        auto converted_expression = converter.convert(*this);

                        // For each variable with a rotation pre-compute its value.
                        std::unordered_map<polynomial_dfs_variable_type, polynomial_dfs_type> rotated_variable_values;

                        expression_for_each_variable_visitor<polynomial_dfs_variable_type> visitor(
                            [&rotated_variable_values, &assignments, &domain](const polynomial_dfs_variable_type& var) {
                                if (var.rotation == 0)
                                    return ;
                                rotated_variable_values[var] = assignments.get_variable_value(var, domain);
                        });
                        visitor.visit(converted_expression);

                        expression_evaluator<polynomial_dfs_variable_type> evaluator(
                            converted_expression,
                            [&domain, &assignments, &rotated_variable_values]
                            (const polynomial_dfs_variable_type &var) -> const polynomial_dfs_type& {
                                if (var.rotation == 0) {
                                    return assignments.get_variable_value_without_rotation(var, domain);
                                }
                                return rotated_variable_values[var];
                            }
                        );

                        return evaluator.evaluate();
                    }

                    typename VariableType::assignment_type
                        evaluate(detail::plonk_evaluation_map<VariableType> &assignments) const {

                        expression_evaluator<VariableType> evaluator(
                            *this,
                            [&assignments](const VariableType &var) -> const typename VariableType::assignment_type& {
                                std::tuple<std::size_t, int, typename VariableType::column_type> key =
                                    std::make_tuple(var.index, var.rotation, var.type);

                                BOOST_ASSERT(assignments.count(key) > 0);
                                return assignments[key];
                            });

                        return evaluator.evaluate();
                    }

                    template<typename T>
                        requires(
                            !std::is_same_v<typename VariableType::assignment_type, T>)
                    T evaluate(std::map<std::tuple<std::size_t, int,
                                                   typename VariableType::column_type>,
                                        T> &assignments) const {
                        expression_variable_type_converter<variable_type,
                                                           plonk_variable<T>>
                            converter(
                                [&assignments](
                                    const typename VariableType::assignment_type &coeff) {
                                    return T(coeff);
                                });

                        auto converted_expression = converter.convert(*this);

                        expression_evaluator<plonk_variable<T>> evaluator(
                            converted_expression,
                            [&assignments](const plonk_variable<T> &var) -> const T & {
                                std::tuple<std::size_t, int,
                                           typename VariableType::column_type>
                                    key = std::make_tuple(var.index, var.rotation,
                                                          var.type);

                                BOOST_ASSERT(assignments.count(key) > 0);
                                return assignments[key];
                            });

                        return evaluator.evaluate();
                    }

                    bool is_absolute() const {
                        return expression_relativity_check_visitor<VariableType>::is_absolute(*this);
                    }
                    bool is_relative() const {
                        return expression_relativity_check_visitor<VariableType>::is_relative(*this);
                    }

                    // Returns the rotated version, or nullptr if it can't be rotated.
                    std::optional<plonk_constraint> rotate(int32_t shift) const {
                        auto result = expression_relativize_visitor<VariableType>::relativize(
                            *this, shift);
                        if (!result)
                            return std::nullopt;
                        return *result;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_CONSTRAINT_HPP
