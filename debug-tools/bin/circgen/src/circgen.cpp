//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <iostream>
#include <fstream>
#include <ios>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>

namespace po = boost::program_options;

void usage(po::options_description const& desc)
{
    std::cout << "circgen - Generate circuit and assignemnt table of a given length" << std::endl;
    std::cout << R"#(The circuit has three columns: one witness column, one public input column
and one selector column (one gate).
The number of rows is specified on command line.

The circuit represents computation of Fibonacci numbers

| row | GATE |   w_0   | public | selector |
|  0  |  --  |  f(0)   |   a    |   0      |
|  1  | FIB  |  f(1)   |   b    |   1      |
| ... | FIB  |         |   0    |   1      |
| N-2 | FIB  |  f(N-2) |   0    |   1      |
| N-1 |  --  |  f(N-1) |   0    |   0      |

public input has two values, a and b and they are copy-constrainted
to f(0) and f(1) respectively

FIB gate : w_0(i-1) + w_0(i) - w_0(i+1) == 0

Explanation:
   value from previous row (w_0(i-1))
   plus
   value on current row (w_0(i))
   minus
   value on the next row (w_0(i+1))
   equals
   0

The gate is enabled (with selector column) on rows from 1 to N-2.
)#" << std::endl;

    std::cout << desc << std::endl;
}


using namespace nil::crypto3::zk::snark;

template<typename FieldType>
std::pair<plonk_constraint_system<FieldType>, plonk_assignment_table<FieldType>>
generate_circuit(
        std::size_t rows,
        typename FieldType::value_type const& a,
        typename FieldType::value_type const& b)
{
    using assignment_type  = typename FieldType::value_type;
    using gate_type = plonk_gate<FieldType, plonk_constraint<FieldType>>;

    auto alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>();

    constexpr std::size_t witness_columns = 1;
    constexpr std::size_t selector_columns = 1;
    constexpr std::size_t lookup_columns = 0;
    constexpr std::size_t public_input_columns = 1;
    constexpr std::size_t constant_columns = 0;

    constexpr std::size_t table_columns =
        witness_columns + selector_columns + lookup_columns + public_input_columns +
        constant_columns;

    std::vector<std::vector<typename FieldType::value_type>> table(table_columns);

    std::vector<typename FieldType::value_type> selector(rows);

    for (std::size_t j = 0; j < table_columns; j++) {
        table[j].resize(rows);
    }

    // init values
    typename FieldType::value_type zero = FieldType::value_type::zero();
    typename FieldType::value_type one = FieldType::value_type::one();

    // public input
    table[1][0] = a;
    table[1][1] = b;

    // witness
    table[0][0] = table[1][0];
    table[0][1] = table[1][1];

    // selector
    table[2][0] = zero;
    table[2][1] = one;

    for (std::size_t i = 2; i < rows - 1; ++i) {
        // witness
        table[0][i] = table[0][i-2] + table[0][i-1];
        // public input
        table[1][i] = zero;
        // selector
        table[2][i-1] = one;
    }

    // Last row
    table[0][rows-1] = table[0][rows-2] + table[0][rows-3];
    table[1][rows-1] = 0;
    table[2][rows-1] = 0;

    std::vector<plonk_column<FieldType>> private_assignment(witness_columns);
    std::vector<plonk_column<FieldType>> selectors_assignment(selector_columns);
    std::vector<plonk_column<FieldType>> public_input_assignment(public_input_columns);
    std::vector<plonk_column<FieldType>> constant_assignment(constant_columns);

    private_assignment[0] = table[0];
    public_input_assignment[0] = table[1];
    selectors_assignment[0] = table[2];

    auto circuit_table = plonk_assignment_table<FieldType>(
            plonk_private_assignment_table<FieldType>(private_assignment),
    plonk_public_assignment_table<FieldType>(
                public_input_assignment, constant_assignment, selectors_assignment));
    auto padded_rows = zk_padding<FieldType, plonk_column<FieldType>>(circuit_table, alg_rnd);
    BOOST_LOG_TRIVIAL(info) << "Rows after padding: " << padded_rows;

    /* Gates (one pcs) */
    plonk_variable<assignment_type> w0(0, -1, true, plonk_variable<assignment_type>::column_type::witness);
    plonk_variable<assignment_type> w1(0, 0, true, plonk_variable<assignment_type>::column_type::witness);
    plonk_variable<assignment_type> w2(0, 1, true, plonk_variable<assignment_type>::column_type::witness);

    typename plonk_constraint<FieldType>::term_type w0_term(w0);
    typename plonk_constraint<FieldType>::term_type w1_term(w1);
    typename plonk_constraint<FieldType>::term_type w2_term(w2);

    plonk_constraint<FieldType> fib_constraint;
    fib_constraint += w0_term;
    fib_constraint += w1_term;
    fib_constraint -= w2_term;

    std::vector<plonk_constraint<FieldType>> fib_costraints {fib_constraint};
    gate_type fib_gate(0, fib_costraints);

    std::vector<gate_type> gates( {fib_gate} );

    /* Copy constraints (two pcs) */

    plonk_variable<assignment_type>
        f0(0, 0, false, plonk_variable<assignment_type>::column_type::witness),
        f1(0, 1, false, plonk_variable<assignment_type>::column_type::witness);

    plonk_variable<assignment_type>
        public_a(0, 0, false, plonk_variable<assignment_type>::column_type::public_input),
        public_b(0, 1, false, plonk_variable<assignment_type>::column_type::public_input);

    plonk_copy_constraint<FieldType> cc_a(f0, public_a), cc_b(f1, public_b);

    plonk_constraint_system<FieldType> cs({fib_gate}, {cc_a, cc_b});

    return {cs, circuit_table};
}

template<typename MarshallingType>
bool encode_marshalling_to_file(
        const boost::filesystem::path& path,
        const MarshallingType& data_for_marshalling)
{
    std::vector<std::uint8_t> v;
    v.resize(data_for_marshalling.length(), 0x00);
    auto write_iter = v.begin();
    nil::marshalling::status_type status = data_for_marshalling.write(write_iter, v.size());

    if (status != nil::marshalling::status_type::success) {
        BOOST_LOG_TRIVIAL(error) << "Marshalled structure encoding failed";
        return false;
    }

    std::ofstream stream(path, std::ios::out);
    stream.write(reinterpret_cast<const char*>(v.data()), v.size());
    stream.close();

    BOOST_LOG_TRIVIAL(info) << v.size() << " bytes saved to " << path;

    return true;
}

struct circgen_options {
    std::string field;
    std::size_t rows;
    std::string a, b;
    boost::filesystem::path output_dir, circuit, assignment_table;
};


template<typename circuit_field>
int run_main(circgen_options const& opts)
{
    using endianness = nil::marshalling::option::big_endian;

    using constraint_system = plonk_constraint_system<circuit_field>;
    using assignment_table = plonk_assignment_table<circuit_field>;
    using column = nil::crypto3::zk::snark::plonk_column<circuit_field>;
    using plonk_table = nil::crypto3::zk::snark::plonk_table<circuit_field, column>;

    using marshalling_field_type = nil::marshalling::field_type<endianness>;
    using mcs = nil::crypto3::marshalling::types::plonk_constraint_system<marshalling_field_type, constraint_system>;
    using mat = nil::crypto3::marshalling::types::plonk_assignment_table<marshalling_field_type, assignment_table>;

    using value_type = typename circuit_field::value_type;
    using integral_type = typename value_type::integral_type;

    if (!boost::filesystem::exists(opts.output_dir)) {
        if (boost::filesystem::create_directories(opts.output_dir)) {
            BOOST_LOG_TRIVIAL(info) << "Created directory for data: " << opts.output_dir;
        } else {
            BOOST_LOG_TRIVIAL(error) << "Can not create directory for data: " << opts.output_dir;
            return 1;
        }
    }

    value_type a (integral_type(opts.a)), b (integral_type(opts.b));

    BOOST_LOG_TRIVIAL(info) << "Generating circuit and assignment table for " << opts.rows << " rows.";
    BOOST_LOG_TRIVIAL(info) << "Public inputs: a = " << a << ", b = " << b;

    auto circuit = generate_circuit<circuit_field>(opts.rows, a, b);

    mcs marshalled_cs = nil::crypto3::marshalling::types::fill_plonk_constraint_system<endianness>(circuit.first);
    mat marshalled_at = nil::crypto3::marshalling::types::fill_assignment_table<endianness, plonk_table>(opts.rows, circuit.second);

    if (!encode_marshalling_to_file<mcs>(opts.output_dir / opts.circuit, marshalled_cs)) {
        return 1;
    }
    if (!encode_marshalling_to_file<mat>(opts.output_dir / opts.assignment_table, marshalled_at)) {
        return 1;
    }

    return 0;
}

template<typename T>
po::typed_value<T>* make_defaulted_option(T& variable) {
    return po::value(&variable)->default_value(variable);
}


po::options_description define_options(circgen_options &opts)
{
    po::options_description desc("circgen options");

    desc.add_options()
        ("help", "Print help")
        ("field", make_defaulted_option(opts.field), "Circuit field")
        ("rows", make_defaulted_option(opts.rows), "Number of rows to generate")
        ("a", make_defaulted_option(opts.a), "Public input a")
        ("b", make_defaulted_option(opts.b), "Public input b")
        ("output-dir", make_defaulted_option(opts.output_dir), "Output directory")
        ("circuit", make_defaulted_option(opts.circuit), "Circuit filename")
        ("assignment", make_defaulted_option(opts.assignment_table), "Assignment table filename")
        ;

    return desc;
}


int main(int argc, char *argv[])
{

    circgen_options opts {
        .field = "pallas",
        .rows = 127,
        .a = "1",
        .b = "1",
        .output_dir = ".",
        .circuit = "circuit.crct",
        .assignment_table = "assignment.tbl"
    };

    po::options_description desc = define_options(opts);

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm); 

    if (vm.count("help")) {
        usage(desc);
        return 0;
    }

    if (opts.field == "bn_base") {
        using curve_type = nil::crypto3::algebra::curves::alt_bn128_254;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "bn_scalar") {
        using curve_type = nil::crypto3::algebra::curves::alt_bn128_254;
        using circuit_field = typename curve_type::scalar_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "bls12_381_base") {
        using curve_type = nil::crypto3::algebra::curves::bls12_381;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "bls12_381_scalar") {
        using curve_type = nil::crypto3::algebra::curves::bls12_381;
        using circuit_field = typename curve_type::scalar_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "bls12_377_base") {
        using curve_type = nil::crypto3::algebra::curves::bls12_377;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "bls12_377_scalar") {
        using curve_type = nil::crypto3::algebra::curves::bls12_377;
        using circuit_field = typename curve_type::scalar_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "mnt4") {
        using curve_type = nil::crypto3::algebra::curves::mnt4_298;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "mnt6") {
        using curve_type = nil::crypto3::algebra::curves::mnt6_298;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "pallas") {
        using curve_type = nil::crypto3::algebra::curves::pallas;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "vesta") {
        using curve_type = nil::crypto3::algebra::curves::vesta;
        using circuit_field = typename curve_type::base_field_type;
        return run_main<circuit_field>(opts);
    } else if (opts.field == "goldilocks") {
        using circuit_field = nil::crypto3::algebra::fields::goldilocks64_base_field;
        return run_main<circuit_field>(opts);
    } else {
        std::cout << "Unknown field: '" << opts.field << "'. Use --help to get list of fields." << std::endl;
        return 1;
    }

    /* unreachable */
    return 0;
}
