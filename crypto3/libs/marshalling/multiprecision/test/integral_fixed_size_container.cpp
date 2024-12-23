//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_integral_fixed_size_container_test

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <iostream>
#include <limits>
#include <vector>

#include <boost/algorithm/string/case_conv.hpp>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/array_list.hpp>

#include <nil/crypto3/multiprecision/big_uint.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

template<class T>
T generate_random() {
    static_assert(std::numeric_limits<T>::is_specialized
                  && std::numeric_limits<T>::is_bounded
                  && std::numeric_limits<T>::is_integer
                  && std::numeric_limits<T>::radix == 2, "Only integer types are supported");

    static boost::random::uniform_int_distribution<std::size_t> len_distr(1, std::numeric_limits<T>::digits);
    static boost::random::mt19937 gen;
    std::size_t len = len_distr(gen);
    boost::random::uniform_int_distribution<T> num_distr(T(1) << (len - 1), len == std::numeric_limits<T>::digits ? ~T(0) : (T(1) << len) - 1);
    return num_distr(gen);
}

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<class T, std::size_t TSize, typename OutputType>
void test_round_trip_fixed_size_container_fixed_precision_big_endian(
    std::array<T, TSize> val_container) {

    using namespace nil::crypto3::marshalling;

    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : sizeof(OutputType) * 8;
    using unit_type = OutputType;
    using integral_type = types::integral<nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::big_endian>, T>;

    using container_type = nil::crypto3::marshalling::types::standard_array_list<
        nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::little_endian>,
        integral_type>;

    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    container_type test_val_container;

    std::vector<unit_type> cv;
    cv.resize(unitblob_size * TSize, 0x00);

    for (std::size_t i = 0; i < TSize; i++) {
        std::size_t begin_index =
            unitblob_size - ((val_container[i].msb() + 1) / units_bits +
                             (((val_container[i].msb() + 1) % units_bits) ? 1 : 0));

        val_container[i].export_bits(cv.begin() + unitblob_size * i + begin_index, units_bits,
                                     true);
    }

    nil::crypto3::marshalling::status_type status;
    std::array<T, TSize> test_val = 
        nil::crypto3::marshalling::pack<nil::crypto3::marshalling::option::big_endian>(cv, status);

    BOOST_CHECK(std::equal(val_container.begin(), val_container.end(), test_val.begin()));
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    std::vector<unit_type> test_cv = 
        nil::crypto3::marshalling::pack<nil::crypto3::marshalling::option::big_endian>(val_container, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
}

template<class T, std::size_t TSize, typename OutputType>
void test_round_trip_fixed_size_container_fixed_precision_little_endian(
    std::array<T, TSize> val_container) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : sizeof(OutputType) * 8;
    using unit_type = OutputType;
    using integral_type = types::integral<nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::little_endian>, T>;

    using container_type = nil::crypto3::marshalling::types::standard_array_list<
        nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::little_endian>,
        integral_type>;

    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    container_type test_val_container;

    std::vector<unit_type> cv;
    cv.resize(unitblob_size * TSize, 0x00);

    for (std::size_t i = 0; i < TSize; i++) {
        val_container[i].export_bits(cv.begin() + unitblob_size * i, units_bits, false);
    }

    nil::crypto3::marshalling::status_type status;
    std::array<T, TSize> test_val = 
        nil::crypto3::marshalling::pack<nil::crypto3::marshalling::option::little_endian>(cv, status);

    BOOST_CHECK(std::equal(val_container.begin(), val_container.end(), test_val.begin()));
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    std::vector<unit_type> test_cv = 
        nil::crypto3::marshalling::pack<nil::crypto3::marshalling::option::little_endian>(val_container, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
}

template<class T, std::size_t TSize, typename OutputType>
void test_round_trip_fixed_size_container_fixed_precision() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        std::array<T, TSize> val_container;
        for (std::size_t i = 0; i < TSize; i++) {
            val_container[i] = generate_random<T>();
        }
        test_round_trip_fixed_size_container_fixed_precision_big_endian<T, TSize, OutputType>(val_container);
        test_round_trip_fixed_size_container_fixed_precision_little_endian<T, TSize, OutputType>(val_container);
    }
}


BOOST_AUTO_TEST_SUITE(integral_fixed_test_suite)

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_1024) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::uint1024_t, 128, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_512) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::uint512_t, 128, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_64) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::big_uint<64>, 128, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_23) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::big_uint<23>, 128, unsigned char>();
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(integral_fixed_test_suite_bits)

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_1024_bits) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::uint1024_t, 128, bool>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_512_bits) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::uint512_t, 128, bool>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_23_bits) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::big_uint<23>, 128, bool>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_big_uint_64_bits) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::big_uint<64>, 128, bool>();
}

BOOST_AUTO_TEST_SUITE_END()
