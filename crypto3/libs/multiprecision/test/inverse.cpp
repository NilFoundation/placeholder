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

#define BOOST_TEST_MODULE inverse_test

#include <stdexcept>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/inverse.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"

using namespace nil::crypto3::multiprecision;

NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(6)

template<typename T>
void test_inverse_mod() {
    BOOST_CHECK_EQUAL(inverse_mod(T(5), T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x33333333333333333333333333333333"));
    BOOST_CHECK_EQUAL(inverse_mod(T(333), T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x17d4f2ee517d4f2ee517d4f2ee517d4f"));
    BOOST_CHECK_EQUAL(inverse_mod(T("0x435b21e35ccd62dbdbafa1368cf742f0"),
                                  T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x604ddb74e5a55e559a7320e45b06eaf6"));
    BOOST_CHECK_EQUAL(
        inverse_mod(T(2),
                    T("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
        T("0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          "00000000000000000000"
          "0000000000000000000000000"));
    BOOST_CHECK_EQUAL(inverse_mod(T(3), T(8)), T(3));
    BOOST_CHECK_THROW(inverse_mod(T(46), T(207)), std::invalid_argument);
    BOOST_CHECK_THROW(inverse_mod(T(2), T(2)), std::invalid_argument);
    BOOST_CHECK_THROW(inverse_mod(T(0), T(2)), std::invalid_argument);
    BOOST_CHECK_THROW(inverse_mod(T(46), T(46)), std::invalid_argument);
    BOOST_CHECK_EQUAL(inverse_mod(T(1), T(7)), T(1));
    BOOST_CHECK_EQUAL(inverse_mod(T(35), T(118)), T(27));
    BOOST_CHECK_THROW(inverse_mod(T(37), T(37)), std::invalid_argument);
    BOOST_CHECK_EQUAL(inverse_mod(T(32), T(247)), T(193));
    BOOST_CHECK_EQUAL(inverse_mod(T(3), T(232)), T(155));

    BOOST_CHECK_EQUAL(
        inverse_mod(
            T("256992387993922882115519242002267204163958280694902854777438773165028812741820300742"
              "384101"
              "620467227297951260702776745365693102268609333941403372929142489383748076291"),
            T("310556067329850632847208938574658589632291100674077275160516075249922714838542485036"
              "214015"
              "8165019680645739648726058090243814223511639161631852729287604717869259565828")),
        T("2322484593360248972803085811686365806060063797313230509497970163285203519904646342173323"
          "688226"
          "147654544918783691327115436052292182385106099615339567513136063879840431"));

    BOOST_CHECK_EQUAL(
        inverse_mod(
            T("657900513264442578215729259525804042708991731028255426638688946278845827095715186772"
              "097484"
              "16019817305674876843604308670298295897660589296995641401495105646770364032950"),
            T("146059874272782860583686068115674600616627249438711269370889274434354805551497286303"
              "947620"
              "1659720247220048664250204314648520085411164461712526657028588699682983099362771")),
        T("3701344688092353558099310214964185602579277616517826314317231208222417072861266226192312"
          "282752"
          "10678415132318220494260963802381448709723310690465171935975287188943190781"));

    BOOST_CHECK_EQUAL(inverse_mod(T(3), T(0x10)), T(11));
    BOOST_CHECK_EQUAL(inverse_mod(T(43000466091), T(0x10000000000)), T(140404367363));

    BOOST_CHECK_EQUAL(
        inverse_mod(T("3329223706171052463206866408355190852145308853551222855374206553291583"
                      "6412003628111698671675220667324272"
                      "5944106904545859091557017307727326666832362641891029072983311591760876"
                      "2612451607036836604560196526748133"
                      "2952294823154321608619569856617204150085028173765891223691691685030517"
                      "0057553436136073435791550700526779"
                      "1266056164843197115173542457409178397682412186017844044878477733706673"
                      "6659493124795020814172868481356070"
                      "6694079674126165187970576121654781364910559498699000784756722078722425"
                      "3724912309650653332895570458720843"
                      "3224850656811897686972917521497485758932335208567118381404016914945323"
                      "3350227887942508765678216349436356"
                      "7584633848194784070822245649557468578497368723157561724530746784741768"
                      "6461029368632606300888825458750471"
                      "73194357829837349405264332156553159"),
                    T("5159669275902268897019683770634129859849131442089512209466255369748647"
                      "8852950434581004530951396375324897"
                      "3237934933418399835900527154085143847573539006016005510145975736902509"
                      "4548935216928274885474920588457238"
                      "9321992128261328481129830302072287292303501430702452146150323300983736"
                      "0681685755548737891159735617529596"
                      "3296209024100980888874174104384926439773409352855895683162800486061893"
                      "6254613392484195923653331976713963"
                      "9022384965245831654887217363203207214249335996119270164515039005157887"
                      "5246900773560274606831152842526302"
                      "3211977032707524224960793107608042288596827341046613333670880853546357"
                      "0182780841768637479016464266039055"
                      "7925243983808216928421220094838103017958334974205040660858707963225716"
                      "1952224606791379941232782765846637"
                      "12976241848458904056941218720227786752")),
        T("16169765086855986127154046155397117295914963038387272783617457684599127447"
          "6610311080533553178926047190203266"
          "85568238777817971191773697446756550362276938623879013359293805261585253356"
          "1719117119940626105914149272955096"
          "43833787555922713773309241786955753178554821984186872072841194724366388916"
          "5526728787046894739482800359519447"
          "64596203739541946184136389849598657786471023022865585926888106336640072640"
          "1157990917652680450814220027329982"
          "28525926769366297380133831033446426381884582602684819819652397562413743816"
          "5546650367370131035732951388159175"
          "97189009924722836031296505773554187289297878370713302855264475968171422470"
          "4381891573964406129272600659255700"
          "50082441202586929437053251315496103922094819482313181774501817762229043061"
          "5352105032422136121552433314291445"
          "5291939319"));
    BOOST_CHECK_EQUAL(
        inverse_mod(T(65279),
                    T("0x100000000000000000000000000000000000000000000000000000000000000000000000"
                      "0000000000000000"
                      "00000000000000000000000000000000000000000000000000000000000")),
        T("2136191453734241471355287191702994357470910407859959447816962783332820558450714636705703"
          "817069"
          "8710253677755075362127788711957331760388539866898398399344480664991941861081743615"));
}

BOOST_AUTO_TEST_SUITE(runtime_tests)

BOOST_AUTO_TEST_CASE(inverse_tests) { test_inverse_mod<big_uint<4096>>(); }

BOOST_AUTO_TEST_CASE(test_big_mod_6_bits) {
    auto modular = big_mod_rt<6>(10_big_uint6, 37_big_uint6);
    BOOST_CHECK_EQUAL(inverse(modular).to_integral(), 26u);

    modular = big_mod_rt<6>(3_big_uint6, 8_big_uint6);
    BOOST_CHECK_EQUAL(inverse(modular).to_integral(), 3u);

    modular = big_mod_rt<6>(3_big_uint6, 16_big_uint6);
    BOOST_CHECK_EQUAL(inverse(modular).to_integral(), 11u);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(fixed_test) {
    using modular_number = nil::crypto3::multiprecision::big_mod_rt<585>;
    using T = nil::crypto3::multiprecision::big_uint<585>;

    constexpr auto mod =
        0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_big_uint585;
    constexpr auto a = 0xfeff_big_uint585;
    constexpr auto a_inv =
        0x565eb513c8dca58227a9d17b4cc814dcf1cec08f4fdf2f0e3d4b88d45d318ec04f0f5e6dcc3a06404686cd542175970ca3b05404585cb511c6d89f78178fa736de14f307fb02fe00ff_big_uint585;
    static_assert(a_inv == inverse_mod(a, mod), "inverse error");

    constexpr modular_number a_m(a, mod);
    constexpr modular_number a_inv_m(a_inv, mod);
    static_assert(a_inv_m == inverse(a_m), "inverse error");

    static_assert(inverse_mod(T(3), T(8)) == T(3));
    // static_assert(inverse_mod(T(46), T(207)) == T(0));
    // static_assert(inverse_mod(T(2), T(2)) == T(0));
    // static_assert(inverse_mod(T(0), T(2)) == T(0));
    // static_assert(inverse_mod(T(46), T(46)) == T(0));
    static_assert(inverse_mod(T(1), T(7)) == T(1));
    static_assert(inverse_mod(T(35), T(118)) == T(27));
    // static_assert(inverse_mod(T(37), T(37)) == T(0));
    static_assert(inverse_mod(T(32), T(247)) == T(193));
    static_assert(inverse_mod(T(3), T(232)) == T(155));
}

BOOST_AUTO_TEST_SUITE_END()
