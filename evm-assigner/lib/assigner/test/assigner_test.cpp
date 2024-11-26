#include <map>
#include <algorithm>

#include <assigner.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <evmc.hpp>
#include <instructions_opcodes.hpp>
#include <vm_host.hpp>

#include <gtest/gtest.h>

class AssignerTest : public testing::Test
{
public:
    using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    static void SetUpTestSuite()
    {
        const std::size_t WitnessColumns = 65;
        const std::size_t PublicInputColumns = 1;

        const std::size_t ConstantColumns = 5;
        const std::size_t SelectorColumns = 30;

        nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(
            WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

        assignments.insert(std::pair<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<ArithmetizationType>>(nil::evm_assigner::zkevm_circuit::BYTECODE, nil::blueprint::assignment<ArithmetizationType>(desc)));
        assignments.insert(std::pair<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<ArithmetizationType>>(nil::evm_assigner::zkevm_circuit::RW, nil::blueprint::assignment<ArithmetizationType>(desc)));

        assigner_ptr =
            std::make_shared<nil::evm_assigner::assigner<BlueprintFieldType>>(assignments);

        const uint8_t input[] = "Hello World!";
        const evmc_uint256be value = {{1, 0}};
        const evmc_address sender_addr = {{0, 1, 2}};
        const evmc_address recipient_addr = {{1, 1, 2}};
        const evmc_address code_addr = {{2, 1, 2}};
        const int64_t gas = 200000;
        struct evmc_tx_context tx_context = {
            .block_number = 42,
            .block_timestamp = 66,
            .block_gas_limit = gas * 2,
        };

        msg = evmc_message {
            .kind = EVMC_CALL,
            .flags = 0,
            .depth = 0,
            .gas = gas,
            .recipient = recipient_addr,
            .sender = sender_addr,
            .input_data = input,
            .input_size = sizeof(input),
            .value = value,
            .create2_salt = {0},
            .code_address = code_addr
        };


        host_interface = &evmc::Host::get_interface();
        ctx = vm_host_create_context<BlueprintFieldType>(tx_context, assigner_ptr);
    }

    static void TearDownTestSuite()
    {
        assigner_ptr.reset();
        vm_host_destroy_context<BlueprintFieldType>(ctx);
    }

    static std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> assigner_ptr;
    static std::unordered_map<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<ArithmetizationType>> assignments;
    static const struct evmc_host_interface* host_interface;
    static struct evmc_host_context* ctx;
    static evmc_revision rev;
    static struct evmc_message msg;
};

std::shared_ptr<nil::evm_assigner::assigner<AssignerTest::BlueprintFieldType>>
    AssignerTest::assigner_ptr;
std::unordered_map<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<AssignerTest::ArithmetizationType>>
    AssignerTest::assignments;
const struct evmc_host_interface* AssignerTest::host_interface;
struct evmc_host_context* AssignerTest::ctx;
evmc_revision AssignerTest::rev = {};
struct evmc_message AssignerTest::msg;

inline void check_eq(const uint8_t* l, const uint8_t* r, size_t len) {
    for (int i = 0; i < len; i++) {
        EXPECT_EQ(l[i], r[i]);
    }
}

inline void rw_circuit_check(const std::unordered_map<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<AssignerTest::ArithmetizationType>> &assignments,
                             uint32_t start_row_index,
                             uint8_t operation_type,
                             uint32_t call_id,
                             const typename AssignerTest::BlueprintFieldType::value_type& address,
                             const typename AssignerTest::BlueprintFieldType::value_type& stoage_key_hi,
                             const typename AssignerTest::BlueprintFieldType::value_type& stoage_key_lo,
                             uint32_t rw_id,
                             bool is_write,
                             const typename AssignerTest::BlueprintFieldType::value_type& value_hi,
                             const typename AssignerTest::BlueprintFieldType::value_type& value_lo) {
    auto it = assignments.find(nil::evm_assigner::zkevm_circuit::RW);
    if (it == assignments.end()) {
        return;
    }
    auto& rw_table = it->second;
    // OP_TYPE
    EXPECT_EQ(rw_table.witness(0, start_row_index), operation_type);
    // CALL ID
    EXPECT_EQ(rw_table.witness(1, start_row_index), call_id);
    // address (stack size)
    EXPECT_EQ(rw_table.witness(2, start_row_index), address);
    // storage key hi
    EXPECT_EQ(rw_table.witness(3, start_row_index), stoage_key_hi);
    // storage key lo
    EXPECT_EQ(rw_table.witness(4, start_row_index), stoage_key_lo);
    // RW ID
    EXPECT_EQ(rw_table.witness(6, start_row_index), rw_id);
    // is write
    EXPECT_EQ(rw_table.witness(7, start_row_index), (is_write ? 1 : 0));
    // value hi
    EXPECT_EQ(rw_table.witness(8, start_row_index), value_hi);
    // value lo
    EXPECT_EQ(rw_table.witness(9, start_row_index), value_lo);
}

inline std::string bytes_to_string(const uint8_t *data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i) {
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    }

    // Cut all preceding zeros
    std::string res = ss.str();
    while (res[0] == '0') res.erase(0,1);

    return res;
}

TEST_F(AssignerTest, conversions_uint256be_to_zkevm_word)
{
    evmc::uint256be uint256be_number;
    uint256be_number.bytes[2] = 10;  // Some big number, 10 << 128
    // conversion to zkevm_word
    auto tmp = nil::evm_assigner::zkevm_word<BlueprintFieldType>(uint256be_number);
    // compare string representations of the data
    ASSERT_EQ(bytes_to_string(uint256be_number.bytes, 32), intx::to_string(tmp.get_value(), 16));
    // conversion back to uint256be
    evmc::uint256be uint256be_result = tmp.to_uint256be();
    // check if same
    check_eq(uint256be_number.bytes, uint256be_result.bytes, 32);
}

TEST_F(AssignerTest, conversions_address_to_zkevm_word)
{
    evmc::address address;
    address.bytes[19] = 10;
    // conversion to zkevm_word
    auto tmp = nil::evm_assigner::zkevm_word<BlueprintFieldType>(address);
    // compare string representations of the data
    ASSERT_EQ(bytes_to_string(address.bytes, 20), intx::to_string(tmp.get_value(), 16));
    // conversion back to address
    evmc::address address_result = tmp.to_address();
    // check if same
    check_eq(address.bytes, address_result.bytes, 20);
    // Check conversion to field
    std::ostringstream ss;
    ss << std::hex << tmp.to_field_as_address();
    ASSERT_EQ(bytes_to_string(address.bytes, 20), ss.str());
}

TEST_F(AssignerTest, conversions_hash_to_zkevm_word)
{
    ethash::hash256 hash {.bytes = {0}};
    hash.bytes[2] = 10;
    // conversion to zkevm_word
    auto tmp = nil::evm_assigner::zkevm_word<BlueprintFieldType>(hash);
    // compare string representations of the data
    ASSERT_EQ(bytes_to_string(hash.bytes, 32), intx::to_string(tmp.get_value(), 16));
    // conversion back to address
    ethash::hash256 hash_result = tmp.to_hash();
    // check if same
    check_eq(hash.bytes, hash_result.bytes, 32);
}

TEST_F(AssignerTest, conversions_uint64_to_zkevm_word)
{
    uint64_t number = std::numeric_limits<uint64_t>::max();
    // conversion to zkevm_word
    auto tmp = nil::evm_assigner::zkevm_word<BlueprintFieldType>(number);
    // compare string representations of the data
    std::ostringstream ss;
    ss << std::hex << number;
    ASSERT_EQ(ss.str(), intx::to_string(tmp.get_value(), 16));
    // conversion back to address
    auto number_result = tmp.to_uint64();
    // check if same
    EXPECT_EQ(number_result, number);
}

TEST_F(AssignerTest, conversions_load_store)
{
    uint32_t number = std::numeric_limits<uint32_t>::max();
    // initialize from byte array
    auto tmp = nil::evm_assigner::zkevm_word<BlueprintFieldType>(
        reinterpret_cast<uint8_t*>(&number), sizeof(number));

    // compare string representations of the data
    std::ostringstream ss;
    ss << std::hex << number;
    ASSERT_EQ(ss.str(), intx::to_string(tmp.get_value(), 16));
    // check store result
    uint32_t restored_number = 0;
    tmp.store<uint32_t>(reinterpret_cast<uint8_t *>(&restored_number));
    // check if same
    EXPECT_EQ(restored_number, number);
}

TEST_F(AssignerTest, load_partial_zkevm_word)
{
    uint64_t number = std::numeric_limits<uint64_t>::max();
    std::array<uint8_t, 26> bytes;
    for (unsigned i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(bytes.size() + i);
    }

    nil::evm_assigner::zkevm_word<BlueprintFieldType> tmp;
    constexpr size_t word_size = 8;
    constexpr auto num_full_words = bytes.size() / word_size;
    constexpr auto num_partial_bytes = bytes.size() % word_size;
    auto data = bytes.data();

    // Load top partial word.
    if constexpr (num_partial_bytes != 0)
    {
        tmp.load_partial_data(data, num_partial_bytes, num_full_words);
        data += num_partial_bytes;
    }

    // Load full words.
    for (size_t i = 0; i < num_full_words; ++i)
    {
        tmp.load_partial_data(data, word_size, num_full_words - 1 - i);
        data += word_size;
    }
    ASSERT_EQ(bytes_to_string(bytes.data(), bytes.size()), intx::to_string(tmp.get_value(), 16));
}

TEST_F(AssignerTest, field_bitwise_and) {
    using intx::operator""_u256;
    auto bits_set_zkevm_word = [](std::initializer_list<unsigned> bits) {
        nil::evm_assigner::zkevm_word<BlueprintFieldType> tmp(0);
        for (unsigned bit_number : bits)
        {
            tmp = tmp + nil::evm_assigner::zkevm_word<BlueprintFieldType>(1_u256 << bit_number);
        }
        return tmp;
    };
    auto bits_set_integral = [](std::initializer_list<unsigned> bits) {
        BlueprintFieldType::integral_type tmp = 0;
        for (unsigned bit_number : bits)
        {
            tmp.bit_set(bit_number);
        }
        return tmp;
    };
    auto bits_test_integral = [&](BlueprintFieldType::integral_type val,
                                  std::unordered_set<unsigned> bits) {
        for (unsigned bit_number = 0; bit_number < BlueprintFieldType::number_bits; ++bit_number)
        {
            EXPECT_EQ(val.bit_test(bit_number), bits.contains(bit_number));
        }
    };
    std::initializer_list<unsigned> init_bits = {1, 12, 42, 77, 136, 201, 222};
    nil::evm_assigner::zkevm_word<BlueprintFieldType> init = bits_set_zkevm_word(init_bits);

    std::initializer_list<unsigned> conjunction_bits = {4, 12, 77, 165, 222};
    BlueprintFieldType::integral_type op = bits_set_integral(conjunction_bits);

    BlueprintFieldType::integral_type res = init & op;

    std::unordered_set<unsigned> res_bit_set;
    std::set_intersection(init_bits.begin(), init_bits.end(), conjunction_bits.begin(),
        conjunction_bits.end(), std::inserter(res_bit_set, res_bit_set.begin()));
    bits_test_integral(res, res_bit_set);
}

TEST_F(AssignerTest, w_hi_lo)
{
    using intx::operator""_u256;
    intx::uint256 hi = 0x12345678901234567890_u256;
    intx::uint256 lo = 0x98765432109876543210_u256;
    nil::evm_assigner::zkevm_word<BlueprintFieldType> tmp((hi << 128) + lo);
    std::ostringstream original_numbers;
    original_numbers << intx::to_string(hi, 16) << "|" << intx::to_string(lo, 16);
    std::ostringstream result_numbers;
    result_numbers << std::hex << tmp.w_hi() << "|" << tmp.w_lo();
    EXPECT_EQ(original_numbers.str(), result_numbers.str());
}

TEST_F(AssignerTest, set_val)
{
    using intx::operator""_u256;
    nil::evm_assigner::zkevm_word<BlueprintFieldType> tmp;
    tmp.set_val(0x1, 0);
    tmp.set_val(0x12, 1);
    tmp.set_val(0x123, 2);
    tmp.set_val(0x1234, 3);
    intx::uint256 expected_val =
        (0x1234_u256 << 64 * 3) + (0x123_u256 << 64 * 2) + (0x12_u256 << 64) + 0x1;
    ASSERT_EQ(tmp.get_value(), expected_val);
}

TEST_F(AssignerTest, mul) {

    std::vector<uint8_t> code = {
        evmone::OP_PUSH1,
        4,
        evmone::OP_PUSH1,
        8,
        evmone::OP_MUL,
    };

    nil::evm_assigner::evaluate<BlueprintFieldType>(host_interface, ctx, rev, &msg, code.data(), code.size(), assigner_ptr);

    uint32_t start_row_index = 0;
    uint32_t call_id = 0;
    //PUSH
    rw_circuit_check(assignments, start_row_index, 1/*STACK_OP*/, call_id, 0/*address in stack*/, 0/*storage key hi*/, 0/*storage key lo*/,
                     0/*trace size*/, true/*is_write*/, 0/*value_hi*/, 4/*value_lo*/);
    //MUL
    rw_circuit_check(assignments, start_row_index + 1, 1/*STACK_OP*/, call_id, 0/*address in stack*/, 0/*storage key hi*/, 0/*storage key lo*/,
                     2/*trace size*/, false/*is_write*/, 0/*value_hi*/, 4/*value_lo*/);
    //MUL
    rw_circuit_check(assignments, start_row_index + 2, 1/*STACK_OP*/, call_id, 0/*address in stack*/, 0/*storage key hi*/, 0/*storage key lo*/,
                     4/*trace size*/, true/*is_write*/, 0/*value_hi*/, 32/*value_lo*/);
    //PUSH
    rw_circuit_check(assignments, start_row_index + 3, 1/*STACK_OP*/, call_id, 1/*address in stack*/, 0/*storage key hi*/, 0/*storage key lo*/,
                     1/*trace size*/, true/*is_write*/, 0/*value_hi*/, 8/*value_lo*/);
    //MUL
    rw_circuit_check(assignments, start_row_index + 4, 1/*STACK_OP*/, call_id, 1/*address in stack*/, 0/*storage key hi*/, 0/*storage key lo*/,
                     3/*trace size*/, false/*is_write*/, 0/*value_hi*/, 8/*value_lo*/);
}
