#include <gtest/gtest.h>

#include <fstream>
#include <vector>
#include <sstream>
#include <format>
#include <algorithm>

#include <boost/algorithm/string.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>

#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/output_artifacts/assignment_table_writer.hpp>

using Endianness = nil::crypto3::marshalling::option::big_endian;
using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

using BlueprintField = typename nil::crypto3::algebra::curves::pallas::base_field_type;

using Writer = nil::proof_producer::assignment_table_writer<Endianness, BlueprintField>;
using AssignmentTable = Writer::AssignmentTable;
using AssignmentTableDescription = Writer::AssignmentTableDescription;

using MarshalledTable = nil::crypto3::marshalling::types::plonk_assignment_table<TTypeBase, AssignmentTable>;

using nil::proof_producer::OutputArtifacts;
using nil::proof_producer::Ranges;
using nil::proof_producer::Range;


class AssignmentTableWriterTest: public ::testing::Test {
    protected:
        void SetUp() override {

            // open & stat file with table content
            std::string test_table_file_path = std::string(TEST_DATA_DIR) + "assignment.tbl";
            std::ifstream in(test_table_file_path, std::ios::binary | std::ios::in | std::ios::ate);
            ASSERT_TRUE(in.is_open());
            const auto fsize = in.tellg();
            ASSERT_FALSE(fsize == 0);

            // read file content to memory
            in.seekg(0, std::ios::beg);
            table_bytes_.resize(fsize);
            in.read(reinterpret_cast<char*>(table_bytes_.data()), fsize);
            ASSERT_FALSE(in.fail());

            // decode input via marshalling lib
            MarshalledTable marshalled_table;
            auto read_iter = table_bytes_.begin();
            auto const status = marshalled_table.read(read_iter, table_bytes_.size());
            ASSERT_TRUE(status == nil::crypto3::marshalling::status_type::success);

            // unpack decoded data to table & description
            auto [desc, table] = nil::crypto3::marshalling::types::make_assignment_table<Endianness, AssignmentTable>(marshalled_table);

            table_ = std::move(table);
            desc_ = std::move(desc);
        }

        std::stringstream write_table_to_stringstream(const OutputArtifacts& opts) {
            std::stringstream out;
            out.exceptions(std::ios::failbit | std::ios::badbit); // interrupt test on any write error
            Writer::write_text_assignment(out, table_, desc_, opts);
            return out;
        }

        void read_and_check_text_header(std::istream& in) {
            std::string expected_header = std::format("witnesses_size: {} public_inputs_size: {} constants_size: {} selectors_size: {} usable_rows_amount: {}",
                table_.witnesses_amount(),
                table_.public_inputs_amount(),
                table_.constants_amount(),
                table_.selectors_amount(),
                desc_.usable_rows_amount
            );

            std::string actual_header;
            std::getline(in, actual_header);
            EXPECT_EQ(expected_header, actual_header);
        }

        void read_separator(std::istream& in) {
            std::string separator;
            in >> separator;
            EXPECT_EQ("|", separator);
        }

        // multiprectision number impl is quite library-specific (current boost impl works really strange with read from string)
        // so for this test it is enough to compare string representations
        std::string read_stringified_field(std::istream& in) {
            std::string str;
            in >> str;

            constexpr auto is_zero = [](char c) { return c == '0'; };

            // merge 000000... to 0
            if (std::all_of(str.begin(), str.end(), is_zero)) {
                return "0";
            }

            // remove leading zeros inserted by setw
            boost::algorithm::trim_left_if(str, is_zero);
            return str;
        }

        void read_rest_of_line(std::istream& in) {
            std::string rest;
            std::getline(in, rest);
            EXPECT_TRUE(std::all_of(rest.begin(), rest.end(), [] (char c) { return std::isspace(c); }));
        }


    protected:

        std::vector<std::uint8_t> table_bytes_;
        AssignmentTable table_;
        AssignmentTableDescription desc_{0,0,0,0};
};

TEST_F(AssignmentTableWriterTest, WriteBinaryAssignment)
{
    std::stringstream out;
    Writer::write_binary_assignment(out, table_, desc_);
    out.flush();

    ASSERT_EQ(out.tellp(), table_bytes_.size());
    const auto written = out.rdbuf();
    ASSERT_TRUE(std::memcmp(written->view().data(), table_bytes_.data(), table_bytes_.size()) == 0);
}

TEST_F(AssignmentTableWriterTest, WriteFullTextAssignment)
{
    OutputArtifacts artifacts;
    artifacts.write_full = true;

    auto mem_stream = write_table_to_stringstream(artifacts);

    read_and_check_text_header(mem_stream);
    for (auto row = 0; row < desc_.usable_rows_amount; row++) {

        for (auto col = 0; col < table_.witnesses_amount(); col++) {
            auto expected = table_.witness(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_separator(mem_stream);

        for (auto col = 0; col < table_.public_inputs_amount(); col++) {
            auto expected = table_.public_input(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_separator(mem_stream);

        for (auto col = 0; col < table_.constants_amount(); col++) {
            auto expected = table_.constant(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_separator(mem_stream);

        for (auto col = 0; col < table_.selectors_amount(); col++) {
            auto expected = table_.selector(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_rest_of_line(mem_stream);
    }
    ASSERT_EQ(mem_stream.tellg(), mem_stream.tellp());
}


TEST_F(AssignmentTableWriterTest, WritePartialColumns)
{
    constexpr size_t WitnessColumnsToDump = 2;

    OutputArtifacts artifacts;
    artifacts.rows.push_back(Range::new_lower(0));
    artifacts.witness_columns.push_back(Range::new_upper(WitnessColumnsToDump));

    auto mem_stream = write_table_to_stringstream(artifacts);

    read_and_check_text_header(mem_stream);
    for (auto row = 0; row < desc_.usable_rows_amount; row++) {
        for (auto col = 0; col <= WitnessColumnsToDump; col++) {
            auto expected = table_.witness(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }

        read_separator(mem_stream); // witnesses
        read_separator(mem_stream); // public inputs
        read_separator(mem_stream); // constants

        read_rest_of_line(mem_stream); // selectors
    }
    ASSERT_EQ(mem_stream.tellg(), mem_stream.tellp());
}


TEST_F(AssignmentTableWriterTest, TextWrite_Smoke)
{
    OutputArtifacts artifacts;

    // [0, 10] rows
    artifacts.rows.push_back(Range(0));
    artifacts.rows.push_back(Range(10));

    // [0-1] witnesses, all public inputs
    artifacts.witness_columns.push_back(Range::new_upper(2));
    artifacts.public_input_columns.push_back(Range::new_lower(0));

    // [1-3, 5-7] constants
    artifacts.constant_columns.insert(
        artifacts.constant_columns.end(),
        {{1,3}, {5,7}}
    );

    // selectors are not dumped at all

    auto mem_stream = write_table_to_stringstream(artifacts);

    read_and_check_text_header(mem_stream);
    for (auto row: {0,10}){
        for (auto col = 0; col <= 2; col++) {
            auto expected = table_.witness(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_separator(mem_stream); // witnesses

        for (auto col = 0; col < table_.public_inputs_amount(); col++) {
            auto expected = table_.public_input(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_separator(mem_stream); // public inputs


        for (auto col = 1; col <= 3; col++) {
            auto expected = table_.constant(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        for (auto col = 5; col <= 7; col++) {
            auto expected = table_.constant(col)[row];
            auto str = read_stringified_field(mem_stream);
            ASSERT_EQ(expected.to_integral().str(std::ios_base::hex), str) << "row: " << row << " col: " << col;
        }
        read_separator(mem_stream); // constants


        read_rest_of_line(mem_stream); // selectors
    }
    ASSERT_EQ(mem_stream.tellg(), mem_stream.tellp());
}
