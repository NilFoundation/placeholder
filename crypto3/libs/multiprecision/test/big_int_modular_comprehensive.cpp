//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_int_modular_comprehensive_test

#include <array>
#include <boost/test/unit_test.hpp>
#include <cstddef>

// We need cpp_int to compare to it.
#include <boost/multiprecision/cpp_int.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/cpp_int_conversions.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"
#include "nil/crypto3/multiprecision/big_mod.hpp"

using namespace nil::crypto3::multiprecision::literals;

enum test_set_enum : std::size_t {
    mod_e,
    a_e,
    b_e,
    // a_add_b_e, a_sub_b_e, a_mul_b_e, a_div_b_e, a_mod_b_e, a_pow_b_e,
    test_set_len
};

template<typename big_uint_t>
constexpr void pow_test(const big_uint_t& a, const big_uint_t& b, const big_uint_t& m) {
    typedef nil::crypto3::multiprecision::big_mod_rt<big_uint_t::Bits> modular_number;
    typedef nil::crypto3::multiprecision::unsigned_cpp_int_type<big_uint_t::Bits> standard_number;

    modular_number a_m(a, m);
    modular_number b_m(b, m);

    standard_number a_cppint = to_cpp_int(a);
    standard_number b_cppint = to_cpp_int(b);
    standard_number m_cppint = to_cpp_int(m);

    standard_number a_powm_b = powm(a_cppint, b_cppint, m_cppint);
    // pow could be used only with modular_numbers
    // modular_number a_m_pow_b_m = pow(a_m, b_m);
    // powm could be used with mixed types
    // modular_number a_m_powm_b_m = powm(a_m, b_m);
    modular_number a_m_powm_b = pow(a_m, b);
    // BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_m_powm_b_m)) == a_powm_b, "powm error");
    BOOST_ASSERT_MSG(to_cpp_int(a_m_powm_b.base()) == a_powm_b, "powm error");
}

template<typename big_uint_t>
bool base_operations_test(std::array<big_uint_t, test_set_len> test_set) {
    typedef
        typename nil::crypto3::multiprecision::unsigned_cpp_int_type<big_uint_t::Bits>::backend_type
            CppIntBackend;

    typedef nil::crypto3::multiprecision::big_uint<big_uint_t::Bits * 2> Backend_doubled;
    typedef typename boost::multiprecision::default_ops::double_precision_type<CppIntBackend>::type
        CppIntBackend_doubled;
    typedef nil::crypto3::multiprecision::big_mod_rt<big_uint_t::Bits> modular_number;
    typedef boost::multiprecision::number<CppIntBackend> standard_number;
    typedef boost::multiprecision::number<CppIntBackend_doubled> dbl_standard_number;

    // Convert from cpp_int_modular_backend to cpp_int_backend numbers.
    standard_number a_cppint = to_cpp_int(test_set[a_e]);
    standard_number b_cppint = to_cpp_int(test_set[b_e]);
    standard_number e_cppint = to_cpp_int(test_set[mod_e]);

    dbl_standard_number a_add_b_s =
        (static_cast<dbl_standard_number>(a_cppint) + static_cast<dbl_standard_number>(b_cppint)) %
        e_cppint;
    dbl_standard_number a_sub_b_s = (static_cast<dbl_standard_number>(a_cppint) -
                                     static_cast<dbl_standard_number>(b_cppint) + e_cppint) %
                                    e_cppint;
    dbl_standard_number a_mul_b_s =
        (static_cast<dbl_standard_number>(a_cppint) * static_cast<dbl_standard_number>(b_cppint)) %
        e_cppint;
    // dbl_standard_number a_mod_b_s =
    //     (static_cast<dbl_standard_number>(a_cppint) % static_cast<dbl_standard_number>(b_cppint))
    //     % e_cppint;
    // standard_number a_and_b_s = (a_cppint & b_cppint) % e_cppint;
    // standard_number a_or_b_s = (a_cppint | b_cppint) % e_cppint;
    // standard_number a_xor_b_s = (a_cppint ^ b_cppint) % e_cppint;
    standard_number a_powm_b_s = powm(a_cppint, b_cppint, e_cppint);
    // standard_number a_bit_set_s = a_cppint;
    // bit_set(a_bit_set_s, 1);
    // a_bit_set_s %= e_cppint;
    // standard_number a_bit_unset_s = a_cppint;
    // a_bit_unset_s %= e_cppint;
    // bit_unset(a_bit_unset_s, 2);
    // standard_number a_bit_flip_s = a_cppint;
    // bit_flip(a_bit_flip_s, 3);
    // a_bit_flip_s %= e_cppint;

    // int b_msb_s = msb(b_cppint);
    // int b_lsb_s = lsb(b_cppint);

    modular_number a(test_set[a_e], test_set[mod_e]);
    modular_number b(test_set[b_e], test_set[mod_e]);

    modular_number a_add_b = a + b;
    modular_number a_sub_b = a - b;
    modular_number a_mul_b = a * b;
    // modular_number a_and_b = a & b;
    // modular_number a_or_b = a | b;
    // modular_number a_xor_b = a ^ b;
    modular_number a_powm_b = pow(a, b.base());
    // modular_number a_bit_set = a;
    // bit_set(a_bit_set, 1);
    // modular_number a_bit_unset = a;
    // bit_unset(a_bit_unset, 2);
    // modular_number a_bit_flip = a;
    // bit_flip(a_bit_flip, 3);

    // int b_msb = msb(b);
    // int b_lsb = lsb(b);

    // We cannot use convert_to here, because there's a bug inside boost, convert_to is constexpr,
    // but it calls function generic_interconvert which is not.
    BOOST_ASSERT_MSG(to_cpp_int(a_add_b.base()) == a_add_b_s, "addition error");
    BOOST_ASSERT_MSG(to_cpp_int(a_sub_b.base()) == a_sub_b_s, "subtraction error");
    BOOST_ASSERT_MSG(to_cpp_int(a_mul_b.base()) == a_mul_b_s, "multiplication error");

    // BOOST_ASSERT_MSG((a > b) == (a_cppint > b_cppint), "g error");
    // BOOST_ASSERT_MSG((a >= b) == (a_cppint >= b_cppint), "ge error");
    BOOST_ASSERT_MSG((a == b) == (a_cppint == b_cppint), "e error");
    // BOOST_ASSERT_MSG((a < b) == (a_cppint < b_cppint), "l error");
    // BOOST_ASSERT_MSG((a <= b) == (a_cppint <= b_cppint), "le error");
    BOOST_ASSERT_MSG((a != b) == (a_cppint != b_cppint), "ne error");

    // BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_and_b)) == a_and_b_s, "and error");
    // BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_or_b)) == a_or_b_s, "or error");
    // BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_xor_b)) == a_xor_b_s, "xor error");

    BOOST_ASSERT_MSG(to_cpp_int(a_powm_b.base()) == a_powm_b_s, "powm error");
    pow_test(test_set[a_e], test_set[b_e], test_set[mod_e]);

    // BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_bit_set)) == a_bit_set_s, "bit set error");
    // BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_bit_unset)) == a_bit_unset_s, "bit unset
    // error"); BOOST_ASSERT_MSG(standard_number(to_cpp_int(a_bit_flip)) == a_bit_flip_s, "bit flip
    // error");

    // BOOST_ASSERT_MSG(b_msb_s == b_msb, "msb error");
    // BOOST_ASSERT_MSG(b_lsb_s == b_lsb, "lsb error");

    return true;
}

template<typename Number, std::size_t N, std::size_t enum_len>
bool base_operations_test(const std::array<std::array<Number, enum_len>, N>& test_data) {
    for (const auto& test_set : test_data) {
        base_operations_test(test_set);
    }
    return true;
}

BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(base_ops_prime_mod_backend_130) {
    using standard_number = nil::crypto3::multiprecision::big_uint<130>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 50>;
    constexpr test_data_t test_data = {{
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1902d38b6904893e90b9c5b8732d1f37d_big_uint130,
         0x2b9060b88dea177d5213deb6f3794434_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x20de70b3f1426ef30b2b2c85d75e2ff2a_big_uint130,
         0x1a50227dc3bd742a232db8798e16d1fbb_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2395c23e8da249dec864da20301b1b64a_big_uint130,
         0xdf185b46a84f318f34160415cc2cc010_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x43c06149ee7c03529dc8a03d091b4e94_big_uint130,
         0x310216180d322187af2c938af5a1ce59_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x26352a54193fd97c1b30ba3e4f624abf3_big_uint130,
         0x271cc74f6ca6cb859a1c1420922eb29ae_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x55cc328d5cc8b9d3362664a61c49d05_big_uint130,
         0x203c88f7c00196a19ca13f3956d823cf9_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2b7b43b1d5e1d838e06ac851dd57c2921_big_uint130,
         0x1c3e4586b67511bdc48a424ab7934f3e2_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x71bff3e8b1dca8851adc38f3f7949f15_big_uint130,
         0x1aa747f949397fd5dd7c8651e8150552_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1a2ce759cfc6960d663313054f1bb102f_big_uint130,
         0xc7a66c97d85f5662ffeebbb953476196_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x29e2517b6b554a879c74e8c4e0516f177_big_uint130,
         0x1f1218f45001011d29934c8cf15c52970_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x24633cbd7c7bfc5f2bd53ee68d61c35d2_big_uint130,
         0x144cedf22adfea125bb43d0be11ca1d0c_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0xfa48dc5dd7b4b1489220e933791b4338_big_uint130,
         0x2b234e335952ad1681afa214a74622526_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x15b8a80d1056036fb5b43afa7acf2fba1_big_uint130,
         0x20100f6e5147f7eae0dd456dcb21a8b57_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x11ad3e87c291c9ee81d50b80086315fff_big_uint130,
         0x21f4e281ab8da64819ab4c2311bb5b18e_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1cac9e60c8ba9fe1dd02a72bd7f302986_big_uint130,
         0x1ca1068fbfa3b573d8f1f189dd5747a16_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1ed35770d0d86801f43eeb651aff88be9_big_uint130,
         0x1906ec17bd1c75f7427c8c94bd7d1baa8_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x159635b82f84b811c9dd90d5cb6b178b_big_uint130,
         0x140f2dea986ddcb181072cb9211f57a8d_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x27d6f0f737bacbce899e43dc682b5624d_big_uint130,
         0x1011587e1de922107a18d7b925c77dd54_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x280f4c62adaa0ffd674affb50fe2e1695_big_uint130,
         0x1d094e72b514dcbf1c711fdcf3e53cb8_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x6e5882e4497adbf5bb25efec29dfc7d8_big_uint130,
         0x1a842e4abcdeedbc8abc583f41e46b125_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0xdf8e9c5a1aef9fb8a84c47e4c13a8e32_big_uint130,
         0x1a60dcd50617841662e100abea05666b4_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1f80459133a5f8b5049a346d931edca2e_big_uint130,
         0x130fe586a5ec4e0045a6e16c4ebac2486_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1f284be48f9037159abfc1c11bd1e06e6_big_uint130,
         0x31251cfead95629cb37cf61595785efa6_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x63766cb772cbaf3e4dfedffb2af6f181_big_uint130,
         0x311d5240457feecb26f8c0e214a1bca75_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2ce5755bfe84b7cb37503711fe5585523_big_uint130,
         0x1f028047ad558bd3208927b6644ae2ab9_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2bee37fdda5691f95381d391f9194f3f_big_uint130,
         0xcbba87247175168e5d40dfb270b3427a_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x9bff8375de0961c15151ff7bc1c97589_big_uint130,
         0x4ccf8b525bf3db5773680b031b007029_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2b861409455060d7b6a5e1d5f6c652548_big_uint130,
         0x220fdc8a8d41a6ef2b2c0a1ec4569300b_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x239d57e467841c5247327e4eaa8d001f8_big_uint130,
         0x10dfd3fb5b333abdaf5529542ce52b843_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x8c555f62b02b7f2c94987bd4e0c400a4_big_uint130,
         0x326eaaaa17ba3ffef1b2622038e4277a_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2b7199f47c784514517cb65fbc3681820_big_uint130,
         0x53368a9f4b547e43867c3b0fbbb55ba0_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1c867f8a6c7f7ba691baba7c34c8972c0_big_uint130,
         0x18a36d27f551b90f3b70990c02be4040f_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0xe08f32c086174483eb5c0fd194284789_big_uint130,
         0x232cee45b9fafa3dd99b916f0da6b5b9f_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2fa93bf0d7dcdd1d2490b228602c11bc4_big_uint130,
         0x313e75ddb32849fc2f920b7dac0784b8e_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0xfa23f38fe8ee768390a947885b402fbb_big_uint130,
         0x1ed41f3daece99382858b91eb9341352_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x19046693c278bc3362c21e3369d28337b_big_uint130,
         0x213100709424048752d19aaba00d597d2_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1c50381e9fe77faacbb4625d8a73454a9_big_uint130,
         0x4c27748ded9d69446a518953eda5ea0c_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x19038fc207ecfca9a1a474489cd184a6d_big_uint130,
         0xcf46092c1d5ccf5e41dff63f92c079b9_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x248e3a01cf8cd1147bfa3e5ed0b6e4a41_big_uint130,
         0x7388310b8e62700604f76f2d45f98e52_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x282252b232f1c43f5f014529ee6e3134e_big_uint130,
         0xc324f7242a9d93665f3f3d72bf731500_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x136d5cc4b596ecbacbcbea6385708cea8_big_uint130,
         0x2eceb23b47b8beeb5cd704605f0102a27_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0xa41d7a6deba861eb210e76fedf048120_big_uint130,
         0x2b80b6fe5fce48e77bc6529a43670fa89_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0xbe044d7bc860898b4b67f2b0e47b2957_big_uint130,
         0x1385abf4521b731a0ef6585e6fcbe1087_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x15431c536a4b40b7a2def9881b3ed3f65_big_uint130,
         0x2c7a86a326513aec20b909a5b06e1d724_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x22dae6c3c21886db3a222b319df2fcc18_big_uint130,
         0x29874fcdec2d26c29d56990f86e49921e_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x1966a81455bb9ae791b06c79361cb04a9_big_uint130,
         0x1ffebba8847893384f651589275aaceb1_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x2744dda0f21e9343d45d80cf7717947c4_big_uint130,
         0x5559c5bfee5bdd51d7695f8be84aa7e0_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x217faf49e078d4f40e8bed99a20a4e3f4_big_uint130,
         0x21e2c14e9f39cfdfc87a7eddbfa8de653_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x571a667c902421037c8d855907b904fd_big_uint130,
         0x873f600a7769bf94aab70506e04d3dee_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_big_uint130, 0x662ba0a5876b6f5f448563d9194ff704_big_uint130,
         0xc88c6b7366ae5740e6860d5f1c906c00_big_uint130},
    }};

    bool res = base_operations_test(test_data);
}

BOOST_AUTO_TEST_CASE(base_ops_even_mod_backend_130) {
    using standard_number = nil::crypto3::multiprecision::big_uint<130>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 50>;
    constexpr test_data_t test_data = {{
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xf6ce85e6f42595ffc6fcb50fdc3c9160_big_uint130,
         0x2f04006a57e467c0d45f180da37f9a602_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x6d9d6fed00c44c3eaa674b2b86004106_big_uint130,
         0x1f811a14b9a0ea15d873e532bb3364548_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x1f72515d6e96f189c58447d4424da9cf5_big_uint130,
         0x1cb8d94653cfbe79c97028957fd6b37d3_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x4c2fe1ff52320c73ec081a03082dfaf7_big_uint130,
         0xb156219a04e9ac54ba60ce2d79d706eb_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xb6222e4281e459f84c0bd5d77ce3493_big_uint130,
         0x32efd252fec869d766989d986cf31fc2_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x1043b1bfcefc15dbe214d68e1061d8645_big_uint130,
         0x43dede03370eb136ecbfa7ec396f0d6d_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x514c264f84ecf1c6e27d7c7c78e6b4a2_big_uint130,
         0x2e9bae255ae7a67003d91da36a76615b8_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2ff3bee3f9723332a002b583133320c93_big_uint130,
         0x25283c79b9b1e505f159c2fe560caffc9_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x1446284dc17091cd19bf687b8bcfa8829_big_uint130,
         0xc9e35084ad8092316a3ce0b77b61b998_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xc447bb62c4287d9f409ab060dae3ae92_big_uint130,
         0x22efe8c2ac2188ad9e638d88bb4c754b5_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x313265520502bb48dceca31b17afa02f0_big_uint130,
         0x109c4589d316e8ec374c1671ed51ee911_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2d639758db1ae7106138010f0e573079e_big_uint130,
         0x268a07bc08a254c23c9d71e3303352c1b_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x20898a292ba2360df9b8f42651f342554_big_uint130,
         0x13ea3770bbfab80ba966ddc255a419664_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x879758e1d55d9db504d0122b735255ac_big_uint130,
         0x2287b16011ef333a67b1984c1f8d2aa55_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xeff14b264f211d251f3852bd87ebeae2_big_uint130,
         0x1b5ebb5ef4a47e00cc6a801e5b383b69e_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xc2723880d0678f28cd177e8792d5ed2d_big_uint130,
         0x2a790884868d6fc5ef87d73d5b80ff46e_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x28a83dffca1513a29489e8835d244d6c5_big_uint130,
         0x15d4f2d8e0949e0aa82f178300c2da5d3_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x25ded52e8495fe687f442ab3579d22963_big_uint130,
         0x2754bb6b9fb861566833f59229e28e0b1_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x1ec91d30d83ac012534a9b7561f390be4_big_uint130,
         0x308d7237b1cfb01b5ca9fa894ae3c6c48_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xa8b175970e5266b7575376c254c5ad4_big_uint130,
         0x7bd2cb80c703ab2fe711022067a805f1_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x3068f458ab46abf38f3ab53368fefe1b3_big_uint130,
         0x44da306ee50c5462b9910fcba033ec28_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x7347fcf946c50eb24121d2695a74138_big_uint130,
         0x2cc6b5e5400509f854189e73f9e252331_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x13e5c415b09516c96134af94a77018a61_big_uint130,
         0x4b1f1e72fb30cffbef1bbe88d8d6c25_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x157cedbd74cdd229f3b43e8ab59199092_big_uint130,
         0x144db4073011653f19851e3b7231b8eb0_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xadbf28669d70f71efea08f2b7dcd3929_big_uint130,
         0x2352ba5d47b493e545238dc33f8018555_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x3118fbf21bf8820849498b777ae4369c2_big_uint130,
         0x8e3b38851b87235ab9e415c4f9973cb5_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2d87b88301585c45369f392edad58ebbb_big_uint130,
         0x17b9f6b9257dc97b99d2b43da9a557a76_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2836115435665dffa299a2e1dba2bc02_big_uint130,
         0x181aa88e10efd256cebb4563cbfb06436_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x4010011e94719b273a8f657daecb8154_big_uint130,
         0x16aa3735374efa31f48b9f0b63eca9f1e_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xfd82a47f158cf4773e6177c3b9087ce1_big_uint130,
         0x14686b4ba0accbb93c1fb046e69015338_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x662de620b44deb4469155819375bd2ae_big_uint130,
         0xa1a7f7e023df7165ca899d4366bbc7f5_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xd12ea24d1261fc11787313ef5906f58d_big_uint130,
         0x1c2a2731db836bc6156689cd762da9364_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x26d99465f1a39a64ef21a46d454161f24_big_uint130,
         0x27c3ed62253a11d4dc15d370704817498_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2570d84dca037136829b41df4809e3810_big_uint130,
         0x904beba3c2f174a54466d0bed0fb581b_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x1183aa1a729def2d3c7138aae27332134_big_uint130,
         0x208bc970b97cf55008c06fc620d025053_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xd8c70b07b915682a3d9f01ea5c51d34b_big_uint130,
         0x6584051efd453ff081e2189928a9a9c4_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xa14b405e334ae992f920fb9373508696_big_uint130,
         0x104aa2d49412388ae364af54a916fb501_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xe5f1875befdf2bc34c0ef450753afb87_big_uint130,
         0x20f84732af830324ed3949c93704a0ce2_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x22dea1e18f9ec2bdb731db37bcab995ad_big_uint130,
         0x1eb896b7179ab4a60a5cfb051c4f6805b_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x322c6c9cd1a662e0a20738db589ae298_big_uint130,
         0x2872647f25d62d395a64406fdcf9ea04b_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xbfde51cd756d321a25d54a3909890edb_big_uint130,
         0xbd2e612e27d726d58a8be3a643373147_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xb63cc77f71d194b5824946e44fe21831_big_uint130,
         0x556942440de628a1b78d70b8ce61cad5_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x28b231976fbb6484e07f1c36b709811c6_big_uint130,
         0x22da443e75ea4b64e4dd5b0e701948b9a_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2b564befbf84fb99e6d3e96a00e28a111_big_uint130,
         0x2680850f06cffc374d3c98dac2a3522ca_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x19738eb221a6b1cc01159dac5232f5f94_big_uint130,
         0x1888b0fd2c91a44559730f4772021e7ae_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x128cbc897d8a21f0924f0824cc0a2a2af_big_uint130,
         0x1667817727b346d00cfe296b83099260a_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x1176a4938cafb93365f979e0648a9b36d_big_uint130,
         0x1d424e90ed8b1d58a4e5f63a983f66b23_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0xe1d5e0b579b9ffabd79f55a3ad58095a_big_uint130,
         0x28facaa806c45f06b33f90a25a256cb57_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x29492c8c9736c8b22abbe8cc151c0bbe5_big_uint130,
         0x1e2e6cf551c64286202dbc4202eb950b4_big_uint130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_big_uint130, 0x2d38c6d88e4be77725f5a337fadacb890_big_uint130,
         0x2b711aed3a4d108fd95d3a8c3338bf713_big_uint130},
    }};

    bool res = base_operations_test(test_data);
}

// This one tests 64-bit numbers used in Goldilock fields.
BOOST_AUTO_TEST_CASE(base_ops_even_mod_backend_64) {
    using standard_number = nil::crypto3::multiprecision::big_uint<64>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 6>;
    constexpr test_data_t test_data = {{
        {0xffffffff00000001_big_uint64, 0x1_big_uint64, 0x2_big_uint64},
        {0xffffffff00000001_big_uint64, 0x7fffffff91725e00_big_uint64, 0x3fffffffe6869400_big_uint64},
        {0xffffffff00000001_big_uint64, 0x7ffaffff91745e00_big_uint64, 0x1fafff0fe6869400_big_uint64},
        {0xffffffff00000001_big_uint64, 0x7ffaffff91745e00_big_uint64, 0x1fafff0fe6869400_big_uint64},
        {0xffffffff00000001_big_uint64, 0x1ffaffff91745e00_big_uint64, 0xffffffff00000000_big_uint64},
        {0xffffffff00000001_big_uint64, 0x00_big_uint64, 0x1_big_uint64},
    }};

    bool res = base_operations_test(test_data);
}

// BOOST_AUTO_TEST_CASE(base_ops_even_mod_backend_17) {
//     using standard_number = nil::crypto3::multiprecision::big_uint<17>;
//     using test_set = std::array<standard_number, test_set_len>;
//     using test_data_t = std::array<test_set, 20>;
//     constexpr test_data_t test_data = {{
//         {0x1e240_big_uint17, 0x3a97_big_uint17, 0xc070_big_uint17},
//         {0x1e240_big_uint17, 0x1dea7_big_uint17, 0x1aaab_big_uint17},
//         {0x1e240_big_uint17, 0x1936f_big_uint17, 0xfb0b_big_uint17},
//         {0x1e240_big_uint17, 0x13067_big_uint17, 0x1566c_big_uint17},
//         {0x1e240_big_uint17, 0x1b960_big_uint17, 0x1773f_big_uint17},
//         {0x1e240_big_uint17, 0x101e4_big_uint17, 0x156ca_big_uint17},
//         {0x1e240_big_uint17, 0x167f3_big_uint17, 0x13c52_big_uint17},
//         {0x1e240_big_uint17, 0xc536_big_uint17, 0x14c8e_big_uint17},
//         {0x1e240_big_uint17, 0xed02_big_uint17, 0x1dafc_big_uint17},
//         {0x1e240_big_uint17, 0x126a6_big_uint17, 0x18a8b_big_uint17},
//         {0x1e240_big_uint17, 0x111ac_big_uint17, 0x94c2_big_uint17},
//         {0x1e240_big_uint17, 0x3a03_big_uint17, 0x89d8_big_uint17},
//         {0x1e240_big_uint17, 0x3add_big_uint17, 0x101ae_big_uint17},
//         {0x1e240_big_uint17, 0x8db4_big_uint17, 0x50e2_big_uint17},
//         {0x1e240_big_uint17, 0x1bab_big_uint17, 0x1d5f6_big_uint17},
//         {0x1e240_big_uint17, 0x144dc_big_uint17, 0x172f8_big_uint17},
//         {0x1e240_big_uint17, 0x1cd30_big_uint17, 0x1a5c_big_uint17},
//         {0x1e240_big_uint17, 0x13c3d_big_uint17, 0x4358_big_uint17},
//         {0x1e240_big_uint17, 0x18d68_big_uint17, 0x1299d_big_uint17},
//         {0x1e240_big_uint17, 0x10153_big_uint17, 0x2c8a_big_uint17},
//     }};

//     bool res = base_operations_test(test_data);
// }

// BOOST_AUTO_TEST_CASE(base_ops_odd_mod_backend_17) {
//     using Backend = cpp_int_modular_backend<17>;
//     using standard_number = boost::multiprecision::number<Backend>;
//     using test_set = std::array<standard_number, test_set_len>;
//     using test_data_t = std::array<test_set, 20>;
//     constexpr test_data_t test_data = {{
//         {0x1e241_big_uint17, 0x3a97_big_uint17, 0xc070_big_uint17},
//         {0x1e241_big_uint17, 0x1dea7_big_uint17, 0x1aaab_big_uint17},
//         {0x1e241_big_uint17, 0x1936f_big_uint17, 0xfb0b_big_uint17},
//         {0x1e241_big_uint17, 0x13067_big_uint17, 0x1566c_big_uint17},
//         {0x1e241_big_uint17, 0x1b960_big_uint17, 0x1773f_big_uint17},
//         {0x1e241_big_uint17, 0x101e4_big_uint17, 0x156ca_big_uint17},
//         {0x1e241_big_uint17, 0x167f3_big_uint17, 0x13c52_big_uint17},
//         {0x1e241_big_uint17, 0xc536_big_uint17, 0x14c8e_big_uint17},
//         {0x1e241_big_uint17, 0xed02_big_uint17, 0x1dafc_big_uint17},
//         {0x1e241_big_uint17, 0x126a6_big_uint17, 0x18a8b_big_uint17},
//         {0x1e241_big_uint17, 0x111ac_big_uint17, 0x94c2_big_uint17},
//         {0x1e241_big_uint17, 0x3a03_big_uint17, 0x89d8_big_uint17},
//         {0x1e241_big_uint17, 0x3add_big_uint17, 0x101ae_big_uint17},
//         {0x1e241_big_uint17, 0x8db4_big_uint17, 0x50e2_big_uint17},
//         {0x1e241_big_uint17, 0x1bab_big_uint17, 0x1d5f6_big_uint17},
//         {0x1e241_big_uint17, 0x144dc_big_uint17, 0x172f8_big_uint17},
//         {0x1e241_big_uint17, 0x1cd30_big_uint17, 0x1a5c_big_uint17},
//         {0x1e241_big_uint17, 0x13c3d_big_uint17, 0x4358_big_uint17},
//         {0x1e241_big_uint17, 0x18d68_big_uint17, 0x1299d_big_uint17},
//         {0x1e241_big_uint17, 0x10153_big_uint17, 0x2c8a_big_uint17},
//     }};

//     bool res = base_operations_test(test_data);
// }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(runtime_tests)

BOOST_AUTO_TEST_CASE(secp256k1_incorrect_multiplication) {
    using standart_number = nil::crypto3::multiprecision::big_uint<256>;
    using modular_number = nil::crypto3::multiprecision::big_mod_rt<256>;

    constexpr standart_number modulus =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
    constexpr standart_number x_standard =
        0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_big_uint256;
    constexpr standart_number res_standard =
        0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_big_uint256;
    constexpr modular_number x(x_standard, modulus);
    constexpr modular_number res(res_standard, modulus);
    BOOST_CHECK_EQUAL(x * x, res);
}

BOOST_AUTO_TEST_CASE(bad_negation) {
    using standart_number = nil::crypto3::multiprecision::big_uint<256>;
    using modular_number = nil::crypto3::multiprecision::big_mod_rt<256>;

    constexpr standart_number modulus =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
    constexpr modular_number x(0u, modulus);
    constexpr modular_number res = -x;
    // TODO
    // BOOST_CHECK(res == 0u);
    BOOST_CHECK(res == x);
    BOOST_CHECK(-res == x);
}

BOOST_AUTO_TEST_CASE(conversion_to_shorter_number) {
    using standart_number = nil::crypto3::multiprecision::big_uint<256>;
    using short_number = nil::crypto3::multiprecision::big_uint<128>;
    constexpr standart_number x =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
    short_number s = x.truncate<128>();
    // 2nd half of the number must stay.
    BOOST_CHECK_EQUAL(s, 0xfffffffffffffffffffffffefffffc2f_big_uint128);
}

BOOST_AUTO_TEST_SUITE_END()
