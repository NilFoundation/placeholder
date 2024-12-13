#define BOOST_TEST_MODULE big_int_modular_test

#include <boost/test/unit_test.hpp>
#include <utility>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"

using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::multiprecision::literals;

NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(2)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(32)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(36)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(57)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(60)

using namespace nil::crypto3::multiprecision::literals;

constexpr auto mod = 0x123456789ABCDEF_big_uint57;
using big_mod_t = montgomery_big_mod<mod>;

BOOST_AUTO_TEST_SUITE(smoke)

BOOST_AUTO_TEST_CASE(construct_constexpr) {
    constexpr big_mod_t a = static_cast<big_mod_t>(0x123_big_uint64);
}

BOOST_AUTO_TEST_CASE(construct_modular_ct_trivial_montgomery) {
    static constexpr auto mod = 0x3_big_uint2;
    auto_big_mod<mod> a = auto_big_mod<mod>(0x5_big_uint);
    BOOST_CHECK_EQUAL(a.str(), "0x2");
}

BOOST_AUTO_TEST_CASE(construct_modular_rt_trivial_montgomery) {
    big_mod_rt<2> a(0x5_big_uint, 0x3_big_uint2);
    BOOST_CHECK_EQUAL(a.str(), "0x2");
}

BOOST_AUTO_TEST_CASE(construct_modular_ct_small_montgomery) {
    static constexpr auto mod = 0x79_big_uint7;
    auto_big_mod<mod> a = auto_big_mod<mod>(0x1234_big_uint);
    BOOST_CHECK_EQUAL(a.str(), "0x3E");
}

BOOST_AUTO_TEST_CASE(construct_modular_rt_small_montgomery) {
    big_mod_rt<7> a(0x1234_big_uint, 0x79_big_uint7);
    BOOST_CHECK_EQUAL(a.str(), "0x3E");
}

BOOST_AUTO_TEST_CASE(construct_modular_ct_small) {
    static constexpr auto mod = 0x78_big_uint7;
    auto_big_mod<mod> a = auto_big_mod<mod>(0x1234_big_uint);
    BOOST_CHECK_EQUAL(a.str(), "0x64");
}

BOOST_AUTO_TEST_CASE(construct_modular_rt_small) {
    big_mod_rt<7> a(0x1234_big_uint, 0x78_big_uint7);
    BOOST_CHECK_EQUAL(a.str(), "0x64");
}

BOOST_AUTO_TEST_CASE(to_string_trivial) {
    BOOST_CHECK_EQUAL((static_cast<big_mod_t>(0x1_big_uint)).str(), "0x1");
}

BOOST_AUTO_TEST_CASE(to_string_small) {
    BOOST_CHECK_EQUAL((static_cast<big_mod_t>(0x20_big_uint)).str(), "0x20");
}

BOOST_AUTO_TEST_CASE(ops) {
    big_mod_t a = 2u, b;

    auto c1{a};
    auto c2{std::move(a)};
    auto c3{2};
    auto c4{2u};
    b = a;
    b = std::move(a);
    b = 2;
    b = 2u;

#define TEST_BINARY_OP(op) \
    do {                   \
        b = a op a;        \
        b = 2 op a;        \
        b = a op 2;        \
        b = 2u op a;       \
        b = a op 2u;       \
        b op## = a;        \
        b op## = 2;        \
        b op## = 2u;       \
    } while (false)

    TEST_BINARY_OP(+);
    ++b;
    b++;
    b = +b;

    TEST_BINARY_OP(-);
    --b;
    b--;
    b = -b;

#undef TEST_BINARY_OP
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(addition)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(
        static_cast<big_mod_t>(0x2_big_uint64) + static_cast<big_mod_t>(0x3_big_uint64),
        static_cast<big_mod_t>(0x5_big_uint64));
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(
        static_cast<big_mod_t>(0xAFFFFFFFF_big_uint64) + static_cast<big_mod_t>(0x2_big_uint36),
        static_cast<big_mod_t>(0xB00000001_big_uint64));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(multiplication)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(
        static_cast<big_mod_t>(0x2_big_uint64) * static_cast<big_mod_t>(0x3_big_uint64),
        static_cast<big_mod_t>(0x6_big_uint64));
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(
        static_cast<big_mod_t>(0xAFFFFFFFF_big_uint64) * static_cast<big_mod_t>(0x2_big_uint36),
        static_cast<big_mod_t>(0x15FFFFFFFE_big_uint64));
}

BOOST_AUTO_TEST_CASE(big) {
    static constexpr auto mod =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_uint224;
    big_mod<mod> a = 0xC5067EE5D80302E0561545A8467C6D5C98BC4D37672EB301C38CE9A9_big_uint224;

    big_mod<mod> b = 0xE632329C42040E595D127EB6889D22215DBE56F540425C705D6BF83_big_uint224;

    BOOST_CHECK_EQUAL((a * b).base(),
                      0x107BC09A9F3443A6F6458495ADD98CBA1FCD15F17D0EAB66302FEFA6_big_uint224);
}

BOOST_AUTO_TEST_CASE(big_assign) {
    static constexpr auto mod =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_uint224;
    big_mod<mod> a = 0xC5067EE5D80302E0561545A8467C6D5C98BC4D37672EB301C38CE9A9_big_uint224;

    big_mod<mod> b = 0xE632329C42040E595D127EB6889D22215DBE56F540425C705D6BF83_big_uint224;

    a *= b;

    BOOST_CHECK_EQUAL(a.base(),
                      0x107BC09A9F3443A6F6458495ADD98CBA1FCD15F17D0EAB66302FEFA6_big_uint224);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(convert)

// BOOST_AUTO_TEST_CASE(to_uint64_t) {
//     std::uint64_t a =
//         static_cast<std::uint64_t>(static_cast<big_mod_t>(0x123456789ABCDEF_big_uint64));
//     BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF);
// }

// BOOST_AUTO_TEST_CASE(from_uint64_t) {
//     big_mod_impl a = static_cast<std::uint64_t>(0x123456789ABCDEFull);
//     BOOST_CHECK_EQUAL(a, static_cast<big_mod_t>(0x123456789ABCDEF_big_uint64));
// }

// BOOST_AUTO_TEST_CASE(from_int64_t) {
//     big_mod_impl a = static_cast<std::int64_t>(0x123456789ABCDEFull);
//     BOOST_CHECK_EQUAL(a, static_cast<big_mod_t>(0x123456789ABCDEF_big_uint64));
// }

BOOST_AUTO_TEST_SUITE_END()
