// MIT License
//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

// Do #define BOOST_SPIRIT_DEBUG in table.hpp, as it also includes qi.

#include <boost/spirit/include/qi.hpp>
#include <boost/phoenix/phoenix.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

struct table_sizes {
    uint32_t witnesses_size,
             public_inputs_size,
             constants_size,
             selectors_size,
             max_size;
};

BOOST_FUSION_ADAPT_STRUCT(
    table_sizes,
    (uint32_t, witnesses_size)
    (uint32_t, public_inputs_size)
    (uint32_t, constants_size)
    (uint32_t, selectors_size)
    (uint32_t, max_size)
)

struct circuit_sizes {
    uint32_t gates_size,
             copy_constraints_size,
             lookup_gates_size;
};

BOOST_FUSION_ADAPT_STRUCT(
    circuit_sizes,
    (uint32_t, gates_size)
    (uint32_t, copy_constraints_size)
    (uint32_t, lookup_gates_size)
)

struct gate_header {
    uint32_t selector_index,
             constraints_size;
};

BOOST_FUSION_ADAPT_STRUCT(
    gate_header,
    (uint32_t, selector_index)
    (uint32_t, constraints_size)
)

template<typename BlueprintFieldType>
struct var_constructor_impl {
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    typedef var result_type;

    template<typename Arg1, typename Arg2, typename Arg3>
    var operator()(Arg1 index, Arg2 rotation, Arg3 typed_var) const {
        typed_var.index = index;
        typed_var.rotation = rotation;
        return typed_var;
    }

};

template<typename BlueprintFieldType>
struct pow_constructor_impl {
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using expression = nil::crypto3::math::expression<var>;
    using pow_operation = nil::crypto3::math::pow_operation<expression>;

    typedef expression result_type;

    template<typename Arg1, typename Arg2>
    expression operator()(Arg1 base, Arg2 exponent) const {
        return base.pow(exponent);
    }
};

template<typename BlueprintFieldType>
struct copy_constraint_constructor {
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using plonk_copy_constraint_type = nil::crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;

    typedef plonk_copy_constraint_type result_type;

    template<typename Arg1, typename Arg2>
    plonk_copy_constraint_type operator()(Arg1 var1, Arg2 var2) const {
        return plonk_copy_constraint_type(var1, var2);
    }
};

template<typename Iterator>
struct table_sizes_parser : boost::spirit::qi::grammar<Iterator, table_sizes(), boost::spirit::qi::ascii::space_type> {
    table_sizes_parser() : table_sizes_parser::base_type(start) {
        using boost::spirit::qi::uint_;
        using boost::spirit::qi::lit;
        using boost::phoenix::val;
        using boost::phoenix::construct;

        start = lit("witnesses_size:") > uint_ >
                lit("public_inputs_size:") > uint_ >
                lit("constants_size:") > uint_ >
                lit("selectors_size:") > uint_ >
                lit("max_size:") > uint_;

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, table_sizes(), boost::spirit::qi::ascii::space_type> start;
};

template<typename Iterator, typename BlueprintFieldType>
struct table_row_parser : boost::spirit::qi::grammar<Iterator, std::vector<typename BlueprintFieldType::integral_type>,
                                                    boost::spirit::qi::ascii::space_type> {
    table_row_parser(table_sizes sizes) : table_row_parser::base_type(start) {
        using boost::spirit::qi::lit;
        using boost::spirit::qi::repeat;
        using boost::spirit::qi::uint_parser;
        using boost::spirit::qi::uint_;
        using boost::phoenix::val;
        using boost::phoenix::construct;

        auto hex_rule = uint_parser<typename BlueprintFieldType::integral_type, 16, 1,
                                    (BlueprintFieldType::modulus_bits + 4 - 1) / 4>();
        start = repeat(sizes.witnesses_size)[hex_rule] > lit('|') >
                repeat(sizes.public_inputs_size)[hex_rule] > lit('|') >
                repeat(sizes.constants_size)[hex_rule] > lit('|') >
                repeat(sizes.selectors_size)[hex_rule];

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                        << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, std::vector<typename BlueprintFieldType::integral_type>,
                            boost::spirit::qi::ascii::space_type> start;
};

template<typename Iterator>
struct circuit_sizes_parser : boost::spirit::qi::grammar<Iterator, circuit_sizes(),
                                                        boost::spirit::qi::ascii::space_type> {
    circuit_sizes_parser() : circuit_sizes_parser::base_type(start) {
        using boost::spirit::qi::uint_;
        using boost::spirit::qi::lit;
        using boost::phoenix::val;
        using boost::phoenix::construct;

        start = lit("gates_size:") > uint_ >
                lit("copy_constraints_size:") > uint_ >
                lit("lookup_gates_size:") > uint_;

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                        << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, circuit_sizes(), boost::spirit::qi::ascii::space_type> start;
};

template<typename Iterator>
struct gate_header_parser : boost::spirit::qi::grammar<Iterator, gate_header(), boost::spirit::qi::ascii::space_type> {
    gate_header_parser() : gate_header_parser::base_type(start) {
        using boost::spirit::qi::uint_;
        using boost::spirit::qi::lit;
        using boost::phoenix::val;
        using boost::phoenix::construct;

        start = lit("selector:") > uint_ > lit("constraints_size:") > uint_;

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                        << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, gate_header(), boost::spirit::qi::ascii::space_type> start;
};

template<typename Iterator, typename BlueprintFieldType>
struct gate_constraint_parser : boost::spirit::qi::grammar<Iterator,
        nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>(),
        boost::spirit::qi::ascii::space_type> {
    using plonk_constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
    using plonk_gate_type = nil::crypto3::zk::snark::plonk_gate<BlueprintFieldType, plonk_constraint_type>;
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using term = nil::crypto3::math::term<var>;

    gate_constraint_parser() : gate_constraint_parser::base_type(start) {
        using boost::spirit::qi::uint_;
        using boost::spirit::qi::int_;
        using boost::spirit::qi::lit;
        using boost::spirit::qi::char_;
        using boost::spirit::qi::_1;
        using boost::spirit::qi::_2;
        using boost::spirit::qi::_3;
        using boost::spirit::qi::_val;
        using boost::phoenix::val;
        using boost::phoenix::construct;
        using boost::phoenix::function;
        using boost::spirit::qi::int_parser;

        function<var_constructor_impl<BlueprintFieldType>> var_constructor;
        function<pow_constructor_impl<BlueprintFieldType>> pow_constructor;
        auto constant = int_parser<typename BlueprintFieldType::integral_type, 10, 1,
                                   (BlueprintFieldType::modulus_bits + 3 - 1) / 3>();
        variable = ((lit("w")[_val = construct<var>(0, 0, true, var::column_type::witness)] |
                     lit("pub")[_val = construct<var>(0, 0, true, var::column_type::public_input)] |
                     lit("c")[_val = construct<var>(0, 0, true, var::column_type::constant)] |
                     lit("sel")[_val = construct<var>(0, 0, true, var::column_type::selector)]) >
                     lit("_") > uint_ > -(lit("_rot(") > int_ > lit(")")))
                    [_val = if_else(_2,
                        var_constructor(_1, *_2, _val),
                        var_constructor(_1, 0, _val))];
        // This is a bit confusing, as atom has the type of term<var>.
        atom = variable | constant;
        expression = term_[_val = construct<plonk_constraint_type>(_1)]
                        >> *(('+' > term_)[_val = _val + _1] | ('-' > term_)[_val = _val - _1]);
        term_ = exponent[_val = construct<plonk_constraint_type>(_1)] >> *(('*' > exponent)[_val = _val * _1]);
        // uint_ is used here, because the expression does not support arbitrary exponents
        // The pow function only takes size_t.
        exponent = factor[_val = construct<plonk_constraint_type>(_1)]
                    >> -(('^' > uint_)[_val = pow_constructor(_val, _1)]);
        factor = atom | (lit("(") > expression > lit(")")) | (lit("-") >> factor);
        start = expression;

        //BOOST_SPIRIT_DEBUG_NODES((start)(expression)(term_)(factor)(atom)(variable));

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator,
                            plonk_constraint_type(),
                            boost::spirit::qi::ascii::space_type> start;
    boost::spirit::qi::rule<Iterator, term(), boost::spirit::qi::ascii::space_type> atom;
    boost::spirit::qi::rule<Iterator, var(), boost::spirit::qi::ascii::space_type> variable;
    boost::spirit::qi::rule<Iterator, boost::spirit::qi::ascii::space_type> constant;
    boost::spirit::qi::rule<Iterator, plonk_constraint_type(), boost::spirit::qi::ascii::space_type> expression;
    boost::spirit::qi::rule<Iterator, plonk_constraint_type(), boost::spirit::qi::ascii::space_type> factor;
    boost::spirit::qi::rule<Iterator, plonk_constraint_type(), boost::spirit::qi::ascii::space_type> exponent;
    boost::spirit::qi::rule<Iterator, plonk_constraint_type(), boost::spirit::qi::ascii::space_type> term_;
};

template<typename Iterator, typename BlueprintFieldType>
struct copy_constraint_parser : boost::spirit::qi::grammar<Iterator,
        nil::crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>(),
        boost::spirit::qi::ascii::space_type> {
    using plonk_copy_constraint_type = nil::crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    copy_constraint_parser() : copy_constraint_parser::base_type(start) {
        using boost::spirit::qi::uint_;
        using boost::spirit::qi::int_;
        using boost::spirit::qi::lit;
        using boost::spirit::qi::char_;
        using boost::spirit::qi::_1;
        using boost::spirit::qi::_2;
        using boost::spirit::qi::_3;
        using boost::spirit::qi::_val;
        using boost::phoenix::val;
        using boost::phoenix::construct;
        using boost::phoenix::function;
        using boost::spirit::qi::int_parser;

        function<var_constructor_impl<BlueprintFieldType>> var_constructor;
        function<copy_constraint_constructor<BlueprintFieldType>> copy_constraint_constructor;
        auto constant = int_parser<typename BlueprintFieldType::integral_type, 10, 1,
                                   (BlueprintFieldType::modulus_bits + 3 - 1) / 3>();
        variable = ((lit("w")[_val = construct<var>(0, 0, false, var::column_type::witness)] |
                     lit("pub")[_val = construct<var>(0, 0, false, var::column_type::public_input)] |
                     lit("c")[_val = construct<var>(0, 0, false, var::column_type::constant)] |
                     lit("sel")[_val = construct<var>(0, 0, true, var::column_type::selector)]) >
                     lit("_") > uint_ > lit("_abs") > -(lit("_rot(") > int_ > lit(")")))
                    [_val = if_else(_2,
                        var_constructor(_1, *_2, _val),
                        var_constructor(_1, 0, _val))];
        start = (variable > variable)[_val = copy_constraint_constructor(_1, _2)];

        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
            start,
            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
        );
    }

    boost::spirit::qi::rule<Iterator, plonk_copy_constraint_type(),
                            boost::spirit::qi::ascii::space_type> start;
    boost::spirit::qi::rule<Iterator, var(), boost::spirit::qi::ascii::space_type> variable;
};