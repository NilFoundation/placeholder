//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>=
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

#pragma once

#include <functional>

#include <boost/random.hpp>

#include <nil/crypto3/zk/math/expression.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil::crypto3::zk::snark;

template<typename VariableType>
VariableType generate_random_local_var(
    boost::random::mt19937 &random_engine
) {
    using var = VariableType;
    const std::size_t witness_amount = 140;
    const std::size_t constant_amount = 4;
    const std::size_t total_col_amount = witness_amount + constant_amount;
    const std::int32_t random_offset =
        boost::random::uniform_int_distribution<std::int32_t>(-1, 1)(random_engine);
    std::size_t random_col =
        boost::random::uniform_int_distribution<std::size_t>(0, total_col_amount - 1)(random_engine);
    typename var::column_type column_type;
    if (random_col < witness_amount) {
        column_type = var::column_type::witness;
    } else {
        column_type = var::column_type::constant;
        random_col -= witness_amount;
    }
    return var(random_col, random_offset, true, column_type);
}

template<typename VariableType>
expression<VariableType> generate_random_constraint(
    const std::size_t max_degree,
    const std::size_t max_linear_comb_size,
    boost::random::mt19937& random_engine
) {
    // Strategy: generate two random polynomials of max_degree / 2, and then multiply them
    // If max_degree % 2 != 0, we multiply the result by a random linear combination
    // Which is incidentally the ouput of this function with max_degree = 1
    // This generates very "wide" gates on average.
    // I need a different algorithm probably? Unsure.
    using field_type = typename VariableType::assignment_type::field_type;
    if (max_degree > 1) {
        auto a = generate_random_constraint<VariableType>(
            max_degree / 2, max_linear_comb_size, random_engine);
        auto b = generate_random_constraint<VariableType>(
            max_degree / 2, max_linear_comb_size, random_engine);
        if (max_degree % 2 != 0) {
            auto c = generate_random_constraint<VariableType>(
                1, max_linear_comb_size, random_engine);
            return a * b * c;
        } else {
            return a * b;
        }
    } else if (max_degree == 1) {
        nil::crypto3::random::algebraic_engine<field_type> engine(random_engine);
        expression<VariableType> linear_comb;
        const std::size_t linear_comb_size =
            boost::random::uniform_int_distribution<std::size_t>(1, max_linear_comb_size)(random_engine);
        for (std::size_t i = 0; i < linear_comb_size; i++) {
            linear_comb += engine() * generate_random_local_var<VariableType>(random_engine);
        }
        linear_comb += engine();
        return linear_comb;
    } else {
        BOOST_ASSERT_MSG(false, "max_degree must be > 0");
    }
    __builtin_unreachable();
}
