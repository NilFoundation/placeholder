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

#ifndef PARALLEL_CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
#define PARALLEL_CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP

#ifdef CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <vector>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/non_linear_combination.hpp>

#ifdef GPU_PROVER
#include <sycl/sycl.hpp>
#include <nil/actor/core/sycl_garbage_collector.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace math {
            // Used for counting max degree of an expression.
            template<typename VariableType>
            class expression_max_degree_visitor : public boost::static_visitor<std::uint32_t> {
            public:
                expression_max_degree_visitor() {}

                std::uint32_t compute_max_degree(const math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::uint32_t operator()(const math::term<VariableType>& term) {
                    return term.get_vars().size();
                }

                std::uint32_t operator()(
                        const math::pow_operation<VariableType>& pow) {
                    std::uint32_t result = boost::apply_visitor(*this, pow.get_expr().get_expr());
                    return result * pow.get_power();
                }

                std::uint32_t operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
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

                void visit(const math::expression<VariableType>& expr) {
                    boost::apply_visitor(*this, expr.get_expr());
                }

                void operator()(const math::term<VariableType>& term) {
                    for (const auto& var: term.get_vars()) {
                        callback(var);
                    }
                }

                void operator()(
                        const math::pow_operation<VariableType>& pow) {
                    boost::apply_visitor(*this, pow.get_expr().get_expr());
                }

                void operator()(const math::binary_arithmetic_operation<VariableType>& op) {
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
                : public boost::static_visitor<math::non_linear_combination<VariableType>> {
            public:
                expression_to_non_linear_combination_visitor() {}

                math::non_linear_combination<VariableType> convert(
                        const math::expression<VariableType>& expr) {
                    math::non_linear_combination<VariableType> result =
                        boost::apply_visitor(*this, expr.get_expr());
                    result.merge_equal_terms();
                    return result;
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::term<VariableType>& term) {
                    return math::non_linear_combination<VariableType>(term);
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::pow_operation<VariableType>& pow) {
                    math::non_linear_combination<VariableType> base = boost::apply_visitor(
                        *this, pow.get_expr().get_expr());
                    math::non_linear_combination<VariableType> result = base;

                    // It does not matter how we compute power here.
                    for (int i = 1; i < pow.get_power(); ++i)
                    {
                        result = result * base;
                    }
                    return result;
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    math::non_linear_combination<VariableType> left =
                        boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    math::non_linear_combination<VariableType> right =
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
            // plonk_variable<math::polynomial_dfs<typename FieldType::value_type>>.
            // You can convert between types if the coefficient types are convertable.
            template<typename SourceVariableType, typename DestinationVariableType>
            class expression_variable_type_converter
                : public boost::static_visitor<math::expression<DestinationVariableType>> {
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

                math::expression<DestinationVariableType> convert(
                        const math::expression<SourceVariableType>& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                math::expression<DestinationVariableType> operator()(
                        const math::term<SourceVariableType>& term) {
                    std::vector<DestinationVariableType> vars;
                    for (const auto& var: term.get_vars()) {
                        vars.emplace_back(
                            var.index, var.rotation, var.relative,
                            static_cast<typename DestinationVariableType::column_type>(static_cast<std::uint8_t>(var.type)));
                    }
                    return math::term<DestinationVariableType>(std::move(vars), _convert_coefficient(term.get_coeff()));
                }

                math::expression<DestinationVariableType> operator()(
                        const math::pow_operation<SourceVariableType>& pow) {
                    math::expression<DestinationVariableType> base = boost::apply_visitor(
                        *this, pow.get_expr().get_expr());
                    return math::pow_operation<DestinationVariableType>(base, pow.get_power());
                }

                math::expression<DestinationVariableType> operator()(
                        const math::binary_arithmetic_operation<SourceVariableType>& op) {
                    math::expression<DestinationVariableType> left =
                        boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    math::expression<DestinationVariableType> right =
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
            private:
                std::function<typename DestinationVariableType::assignment_type(
                    const typename SourceVariableType::assignment_type&)> _convert_coefficient;

            };

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
            class expression_relativize_visitor : public boost::static_visitor<std::optional<crypto3::math::expression<VariableType>>> {
            private:
                int32_t shift;
            public:
                expression_relativize_visitor(int32_t shift_) : shift(shift_) {}

                static std::optional<crypto3::math::expression<VariableType>>
                relativize(const crypto3::math::expression<VariableType>& expr, int32_t shift) {
                    expression_relativize_visitor v = expression_relativize_visitor(shift);
                    return boost::apply_visitor(v, expr.get_expr());
                }

                std::optional<crypto3::math::expression<VariableType>>
                operator()(const crypto3::math::term<VariableType>& term) {
                    std::vector<VariableType> vars = term.get_vars();

                    for(std::size_t i = 0; i < vars.size(); i++) {
                        vars[i].relative = true;
                        vars[i].rotation += shift;
                        if (std::abs(vars[i].rotation) > 1) {
                            return std::nullopt;
                        }
                    }

                    return crypto3::math::term<VariableType>(vars, term.get_coeff());
                }

                std::optional<crypto3::math::expression<VariableType>>
                operator()(const crypto3::math::pow_operation<VariableType>& pow) {
                    auto term = boost::apply_visitor(*this, pow.get_expr().get_expr());
                    if (!term)
                        return std::nullopt;
                    return crypto3::math::pow_operation<VariableType>(
                        *term,
                        pow.get_power());
                }

                std::optional<crypto3::math::expression<VariableType>>
                operator()(const crypto3::math::binary_arithmetic_operation<VariableType>& op) {
                    auto left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    if (!left)
                        return std::nullopt;
                    auto right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    if (!right)
                        return std::nullopt;
                    return crypto3::math::binary_arithmetic_operation<VariableType>(
                        *left, *right, op.get_op());
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

#ifdef GPU_PROVER
            template <typename VariableType>
            class ssethi_ullman_visitor : public boost::static_visitor<std::size_t> {
            public:
                using expression_type = crypto3::math::expression<VariableType>;
                using term_type = crypto3::math::term<VariableType>;
                using pow_operation_type = crypto3::math::pow_operation<VariableType>;
                using binary_arithmetic_operation_type = crypto3::math::binary_arithmetic_operation<VariableType>;

                std::size_t operator()(const expression_type& expr) const {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::size_t operator()(const term_type& term) const {
                    return 1;
                }

                std::size_t operator()(const pow_operation_type& pow) const {
                    return 1;
                }

                std::size_t operator()(const binary_arithmetic_operation_type& op) const {
                    const std::size_t left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    const std::size_t right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    if (left != right) {
                        return std::max(left, right);
                    }
                    return left + 1;
                }
            };

            template<typename VariableType>
            class gpu_expression_evaluator : public boost::static_visitor<std::pair<sycl::event, std::shared_ptr<typename VariableType::assignment_type>>> {
                // assume that all the variables are already resized
            public:
                using value_type = typename VariableType::assignment_type;
                using shared_ptr_type = std::shared_ptr<value_type>;
                using event_value_pair_type = std::pair<sycl::event, shared_ptr_type>;
                std::size_t domain_size;
                sycl::queue& queue;
                std::unordered_map<VariableType, std::shared_ptr<value_type>>& variable_map;
                std::unordered_map<VariableType, sycl::event>& variable_events;
                actor::core::sycl_garbage_collector<value_type>& garbage_collector;

                gpu_expression_evaluator(
                    sycl::queue& queue, std::size_t domain_size,
                    std::unordered_map<VariableType, std::shared_ptr<value_type>>& variable_map,
                    std::unordered_map<VariableType, sycl::event>& variable_events,
                    actor::core::sycl_garbage_collector<value_type>& garbage_collector
                ) : queue(queue), domain_size(domain_size), variable_map(variable_map),
                    variable_events(variable_events), garbage_collector(garbage_collector)
                {}

                event_value_pair_type operator()(const crypto3::math::term<VariableType>& term) {
                    // note that we need to convert the value to polynomial_dfs here
                    sycl::queue& queue = this->queue;

                    value_type coeff = term.get_coeff();
                    std::shared_ptr<value_type> result_buf =
                        nil::actor::core::make_shared_device_memory<value_type>(domain_size, queue);
                    value_type* result_buf_ptr = result_buf.get();
                    sycl::event coeff_fill_event = queue.fill(result_buf_ptr, coeff, domain_size);
                    const std::size_t term_size = term.get_vars().size();
                    if (term_size == 0) {
                        garbage_collector.track_memory(result_buf, coeff_fill_event);
                        return {coeff_fill_event, result_buf};
                    }

                    const std::vector<VariableType>& term_vars = term.get_vars();
                    std::vector<sycl::event> buffer_events(term_size + 1);
                    buffer_events[0] = coeff_fill_event;
                    // note that we multiply sequentially here because all variable buffers are effectively immutable here
                    for (std::size_t i = 0; i < term_size; i++) {
                        const VariableType& var = term_vars[i];
                        sycl::event last_buffer_event = buffer_events[i];
                        sycl::event variable_event = variable_events[var];
                        const std::size_t domain_size = this->domain_size;
                        value_type* var_buf = variable_map[var].get();
                        buffer_events[i + 1] =
                            queue.submit([last_buffer_event, variable_event, result_buf_ptr,
                                          domain_size, var_buf](sycl::handler& cgh) {
                                cgh.depends_on({last_buffer_event, variable_event});
                                cgh.parallel_for(sycl::range<1>(domain_size), [=](sycl::id<1> idx) {
                                    result_buf_ptr[idx] = result_buf_ptr[idx] * var_buf[idx];
                                });
                            });
                    }
                    garbage_collector.track_memory(result_buf, buffer_events.back());
                    return {buffer_events.back(), result_buf};
                }

                event_value_pair_type operator()(const crypto3::math::pow_operation<VariableType>& pow) {
                    throw std::runtime_error("pow operation currently not supported on gpu");
                    return {};
                }

                event_value_pair_type operator()(const crypto3::math::binary_arithmetic_operation<VariableType>& op) {
                    // todo: cache
                    event_value_pair_type left, right;
                    ssethi_ullman_visitor<VariableType> ullman_visitor;
                    const std::size_t ullman_num_left = boost::apply_visitor(ullman_visitor, op.get_expr_left().get_expr());
                    const std::size_t ullman_num_right = boost::apply_visitor(ullman_visitor, op.get_expr_right().get_expr());
                    auto left_expr = op.get_expr_left().get_expr();
                    auto right_expr = op.get_expr_right().get_expr();
                    bool swap = false;
                    if (ullman_num_left < ullman_num_right) {
                        std::swap(left_expr, right_expr);
                        swap = true;
                    }
                    left = boost::apply_visitor(*this, left_expr);
                    left.first.wait();
                    right = boost::apply_visitor(*this, right_expr);
                    sycl::queue& queue = this->queue;

                    // left buf is the result buf
                    value_type* left_raw_buf = left.second.get();
                    value_type* right_raw_buf = right.second.get();
                    sycl::event result_event,
                                left_event = left.first,
                                right_event = right.first;
                    const std::size_t domain_size = this->domain_size;
                    switch (op.get_op()) {
                        case ArithmeticOperator::ADD:
                            result_event = queue.submit([left_raw_buf, right_raw_buf, domain_size, left_event, right_event](sycl::handler& cgh) {
                                cgh.depends_on({left_event, right_event});
                                cgh.parallel_for(sycl::range<1>(domain_size), [=](sycl::id<1> idx) {
                                    left_raw_buf[idx] += right_raw_buf[idx];
                                });
                            });
                            break;
                        case ArithmeticOperator::SUB:
                            if (!swap) {
                                result_event = queue.submit([left_raw_buf, right_raw_buf, domain_size, left_event, right_event](sycl::handler& cgh) {
                                    cgh.depends_on({left_event, right_event});
                                    cgh.parallel_for(sycl::range<1>(domain_size), [=](sycl::id<1> idx) {
                                        left_raw_buf[idx] -= right_raw_buf[idx];
                                    });
                                });
                            } else {
                                result_event = queue.submit([left_raw_buf, right_raw_buf, domain_size, left_event, right_event](sycl::handler& cgh) {
                                    cgh.depends_on({left_event, right_event});
                                    cgh.parallel_for(sycl::range<1>(domain_size), [=](sycl::id<1> idx) {
                                        left_raw_buf[idx] = right_raw_buf[idx] - left_raw_buf[idx];
                                    });
                                });
                            }
                            break;
                        case ArithmeticOperator::MULT:
                            result_event = queue.submit([left_raw_buf, right_raw_buf, domain_size, left_event, right_event](sycl::handler& cgh) {
                                cgh.depends_on({left_event, right_event});
                                cgh.parallel_for(sycl::range<1>(domain_size), [=](sycl::id<1> idx) {
                                    left_raw_buf[idx] *= right_raw_buf[idx];
                                });
                            });
                            break;
                    }
                    garbage_collector.track_memory(left.second, result_event);
                    garbage_collector.track_memory(right.second, result_event);
                    garbage_collector.finalize(right.second);
                    return {result_event, left.second};
                }

                event_value_pair_type operator()(const crypto3::math::expression<VariableType>& expr) {
                    auto res = boost::apply_visitor(*this, expr.get_expr());
                    garbage_collector.finalize(res.second);
                    return res;
                }
            };
#endif
        }    // namespace math
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
