//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ressol_test

#include <stdexcept>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"
#include "nil/crypto3/multiprecision/ressol.hpp"

using namespace nil::crypto3::multiprecision;

BOOST_AUTO_TEST_SUITE(ressol_runtime_tests)

BOOST_AUTO_TEST_CASE(ressol_runtime_4_bit_tests) {
    using T = big_uint<4>;
    BOOST_CHECK_EQUAL(ressol(T(0u), T(11u)), 0u);
    BOOST_CHECK_EQUAL(ressol(T(5u), T(11u)), 4u);

    BOOST_CHECK_THROW(ressol(T(10u), T(11u)), std::invalid_argument);
    BOOST_CHECK_THROW(ressol(T(2u), T(11u)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_521_bit_tests) {
    using T = big_uint<521>;
    BOOST_CHECK_EQUAL(
        ressol(T(5u), T("68647976601306097149819007990813932172694353001433054093944634591855431833"
                        "9765605212255"
                        "9640661454554977296311391480858037121987999716643812574028291115057151")),
        T("5128001483797946816458955548662741861156429216952843873274631897232136999791540518339021"
          "539968"
          "609345897897688700798659762992302941280478805021587896033442584"));

    BOOST_CHECK_THROW(
        ressol(T(4), T("686479766013060971498190079908139321726943530014330540939446345918554318339"
                       "765605212255"
                       "9640661454554977296311391480858037121987999716643812574028291115057149")),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_224_bit_tests) {
    using T = big_uint<224>;
    BOOST_CHECK_EQUAL(
        ressol(T("20749193632488214633180774027217139706413443729200940480695355894185"),
               T("26959946667150639794667015087019630673557916260026308143510066298881")),
        T("1825097171398375765346899906888660610489759292065918530856859649959"));
}

BOOST_AUTO_TEST_CASE(ressol_runtime_315_bit_tests) {
    using T = big_uint<315>;
    BOOST_CHECK_EQUAL(
        ressol(
            T(1024u),
            T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        32u);
    BOOST_CHECK_EQUAL(
        ressol(
            T(16u),
            T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        4u);
    BOOST_CHECK_EQUAL(
        ressol(
            T(120846049u),
            T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e"));
    BOOST_CHECK_EQUAL(
        ressol(
            T(1025),
            T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        T("7195614950510915163755738138441999335431224576038191833055420996031360079131617522512565"
          "985187"));
}

BOOST_AUTO_TEST_CASE(ressol_runtime_18_bit_tests) {
    using T = big_uint<18>;

    BOOST_CHECK_EQUAL(ressol(T(1024u), T(174763u)), 174731u);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_7_bit_tests) {
    using T = big_uint<7>;

    BOOST_CHECK_THROW(ressol(T(64), T(85)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_8_bit_tests) {
    using T = big_uint<8>;

    BOOST_CHECK_THROW(ressol(T(181), T(217)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_16_bit_tests) {
    using T = big_uint<16>;

    BOOST_CHECK_THROW(ressol(T(4225), T(33153)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_15_bit_tests) {
    using T = big_uint<15>;

    BOOST_CHECK_THROW(ressol(T(2048), T(31417)), std::logic_error);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_13_bit_tests) {
    using T = big_uint<13>;

    BOOST_CHECK_THROW(ressol(T(2), T(4369)), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()  // ressol_runtime_tests

void test_static() {
    constexpr auto a1 = 0x5_big_uint4;
    constexpr auto p1 = 0xb_big_uint4;
    constexpr auto res1 = 0x4_big_uint4;
    static_assert(ressol(a1, p1) == res1, "ressol error");

    constexpr auto a2 = 0x5_big_uint521;
    constexpr auto p2 =
        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_big_uint521;
    constexpr auto res2 =
        0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_big_uint521;
    static_assert(ressol(a2, p2) == res2, "ressol error");

    // constexpr auto a3 = 0x4_big_uint521;
    // constexpr auto p3 =
    //     0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_big_uint521;
    // static_assert(ressol(a3, p3) == -1, "ressol error");

    constexpr auto a4 =
        0xc5067ee5d80302e0561545a8467c6d5c98bc4d37672eb301c38ce9a9_big_uint224;
    constexpr auto p4 =
        0xffffffffffffffffffffffffffffffff000000000000000000000001_big_uint224;
    constexpr auto res4 =
        0x115490c2141baa1c2407abe908fcf3416b0cb0d290dcd3960c3ec7a7_big_uint224;
    static_assert(ressol(a4, p4) == res4, "ressol error");

    // constexpr auto a5 = 0x40_big_uint7;
    // constexpr auto p5 = 0x55_big_uint7;
    // static_assert(ressol(a5, p5) == -1, "ressol error");

    // constexpr auto a6 = 0xb5_big_uint8;
    // constexpr auto p6 = 0xd9_big_uint8;
    // static_assert(ressol(a6, p6) == -1, "ressol error");

    // constexpr auto a7 = 0x1081_big_uint16;
    // constexpr auto p7 = 0x8181_big_uint16;
    // static_assert(ressol(a7, p7) == -1, "ressol error");

    // constexpr auto a8 = 0x800_big_uint15;
    // constexpr auto p8 = 0x7ab9_big_uint15;
    // static_assert(ressol(a8, p8) == -1, "ressol error");

    // constexpr auto a9 = 0x2_big_uint13;
    // constexpr auto p9 = 0x1111_big_uint13;
    // static_assert(ressol(a9, p9) == -1, "ressol error");

    constexpr auto a10 = 0x400_big_uint315;
    constexpr auto p10 =
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315;
    constexpr auto res10 = 0x20_big_uint315;
    static_assert(ressol(a10, p10) == res10, "ressol error");

    constexpr auto a11 = 0x400_big_uint18;
    constexpr auto p11 = 0x2aaab_big_uint18;
    constexpr auto res11 = 0x2aa8b_big_uint18;
    static_assert(ressol(a11, p11) == res11, "ressol error");

    constexpr auto a12 = 0x401_big_uint315;
    constexpr auto p12 =
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315;
    constexpr auto res12 =
        0xdcc6506af06fe9e142cacb7b5ff56c1864fe7a0b2f7fb10739990aed564e07beb533b5edd95fa3_big_uint315;
    static_assert(ressol(a12, p12) == res12, "ressol error");

    constexpr auto a13 = 0x10_big_uint315;
    constexpr auto p13 =
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315;
    constexpr auto res13 = 0x4_big_uint315;
    static_assert(ressol(a13, p13) == res13, "ressol error");

    constexpr auto a14 = 0x733f6e1_big_uint315;
    constexpr auto p14 =
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315;
    constexpr auto res14 =
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e_big_uint315;
    static_assert(ressol(a14, p14) == res14, "ressol error");
}

void test_mod_static() {
    constexpr auto a1_m = big_mod_rt<4>(0x5_big_uint4, 0xb_big_uint4);
    constexpr auto res1 = 0x4_big_uint4;
    static_assert(ressol(a1_m).to_integral() == res1, "ressol error");

    constexpr auto a2_m = big_mod_rt<521>(
        0x5_big_uint521,
        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_big_uint521);
    constexpr auto res2 =
        0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_big_uint521;
    static_assert(ressol(a2_m).to_integral() == res2, "ressol error");

    // constexpr auto a3_m = big_mod_rt<521>(
    //     0x4_big_uint521,
    //     0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_big_uint521);
    // constexpr auto negone_3 = big_mod_rt<521>(
    //     0x0_big_uint512,
    //     0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_big_uint521);
    // static_assert(ressol(a3_m) == negone_3, "ressol error");

    constexpr auto a4_m = big_mod_rt<224>(
        0xc5067ee5d80302e0561545a8467c6d5c98bc4d37672eb301c38ce9a9_big_uint224,
        0xffffffffffffffffffffffffffffffff000000000000000000000001_big_uint224);
    constexpr auto res4 =
        0x115490c2141baa1c2407abe908fcf3416b0cb0d290dcd3960c3ec7a7_big_uint224;
    static_assert(ressol(a4_m).to_integral() == res4, "ressol error");

    // constexpr auto a5_m = big_mod_rt<7>(0x40_big_uint7, 0x55_big_uint7);
    // constexpr auto negone_5 = big_mod_rt<7>(0, 0x55_big_uint7);
    // static_assert(ressol(a5_m) == negone_5, "ressol error");

    // constexpr auto a6_m = big_mod_rt<8>(0xb5_big_uint8, 0xd9_big_uint8);
    // constexpr auto negone_6 = big_mod_rt<8>(0, 0xd9_big_uint8);
    // static_assert(ressol(a6_m) == negone_6, "ressol error");

    // constexpr auto a7_m = big_mod_rt<16>(0x1081_big_uint16, 0x8181_big_uint16);
    // constexpr auto negone_7 = big_mod_rt<16>(big_uint<16>(-1), 0x8181_big_uint16);
    // static_assert(ressol(a7_m) == negone_7, "ressol error");

    // constexpr auto a8_m = big_mod_rt<15>(0x800_big_uint15, 0x7ab9_big_uint15);
    // constexpr auto negone_8 = big_mod_rt<15>(big_uint<15>(-1), 0x7ab9_big_uint15);
    // static_assert(ressol(a8_m) == negone_8, "ressol error");

    // constexpr auto a9_m = big_mod_rt<13>(0x2_big_uint13, 0x1111_big_uint13);
    // constexpr auto negone_9 = big_mod_rt<13>(big_uint<13>(-1), 0x1111_big_uint13);
    // static_assert(ressol(a9_m) == negone_9, "ressol error");

    constexpr auto a10_m = big_mod_rt<315>(
        0x400_big_uint315,
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315);
    constexpr auto res10 = 0x20_big_uint315;
    static_assert(ressol(a10_m).to_integral() == res10, "ressol error");

    constexpr auto a11_m = big_mod_rt<18>(0x400_big_uint18, 0x2aaab_big_uint18);
    constexpr auto res11 = 0x2aa8b_big_uint18;
    static_assert(ressol(a11_m).to_integral() == res11, "ressol error");

    constexpr auto a12_m = big_mod_rt<315>(
        0x401_big_uint315,
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315);
    constexpr auto res12 =
        0xdcc6506af06fe9e142cacb7b5ff56c1864fe7a0b2f7fb10739990aed564e07beb533b5edd95fa3_big_uint315;
    static_assert(ressol(a12_m).to_integral() == res12, "ressol error");

    constexpr auto a13_m = big_mod_rt<315>(
        0x10_big_uint315,
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315);
    constexpr auto res13 = 0x4_big_uint315;
    static_assert(ressol(a13_m).to_integral() == res13, "ressol error");

    constexpr auto a14_m = big_mod_rt<315>(
        0x733f6e1_big_uint315,
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_big_uint315);
    constexpr auto res14 =
        0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e_big_uint315;
    static_assert(ressol(a14_m).to_integral() == res14, "ressol error");
}
