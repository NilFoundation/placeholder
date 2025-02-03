#include <gtest/gtest.h>

#include <fstream>
#include <vector>
#include <sstream>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>

#include <nil/proof-generator/output_artifacts/circuit_writer.hpp>

using Endianness = nil::crypto3::marshalling::option::big_endian;
using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

using BlueprintField = typename nil::crypto3::algebra::curves::pallas::base_field_type;

using Writer = nil::proof_producer::circuit_writer<Endianness, BlueprintField>;
using Circuit = Writer::Circuit;

class CircuitWriterTest: public ::testing::Test {
    protected:
        void SetUp() override {

            // open & stat file with circuit content
            std::string test_circuit_file_path(TEST_DATA_DIR);
            test_circuit_file_path += "circuit.crct";
            std::ifstream in(test_circuit_file_path, std::ios::binary | std::ios::in | std::ios::ate);
            ASSERT_TRUE(in.is_open());
            const auto fsize = in.tellg();
            ASSERT_FALSE(fsize == 0);

            // read file content to memory
            in.seekg(0, std::ios::beg);
            circuit_bytes_.resize(fsize);
            in.read(reinterpret_cast<char*>(circuit_bytes_.data()), fsize);
            ASSERT_FALSE(in.fail());

            using CircuitMarshalling = nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, Circuit>;

            CircuitMarshalling marshalled_circuit;
            auto read_iter = circuit_bytes_.begin();
            auto const status = marshalled_circuit.read(read_iter, circuit_bytes_.size());
            ASSERT_TRUE(status == nil::crypto3::marshalling::status_type::success);

            circuit_ = nil::crypto3::marshalling::types::make_plonk_constraint_system<Endianness, Circuit>(marshalled_circuit);
        }

    protected:

        std::vector<uint8_t> circuit_bytes_;
        Circuit circuit_;
};


TEST_F(CircuitWriterTest, WriteBinaryCircuit)
{
    std::stringstream out;
    Writer::write_binary_circuit(out, circuit_, circuit_.public_input_sizes());
    out.flush();

    ASSERT_EQ(out.tellp(), circuit_bytes_.size());
    const auto written = out.rdbuf();
    ASSERT_TRUE(std::memcmp(written->view().data(), circuit_bytes_.data(), circuit_bytes_.size()) == 0);
}
