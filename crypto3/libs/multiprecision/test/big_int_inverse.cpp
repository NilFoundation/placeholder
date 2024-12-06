//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_int_inverse_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"
#include "nil/crypto3/multiprecision/modular/big_mod.hpp"

using namespace nil::crypto3::multiprecision;

NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(6)

template<typename T>
void test_inverse_extended_euclidean_algorithm() {
    BOOST_CHECK_EQUAL(
        inverse_extended_euclidean_algorithm(T(5), T("0x7fffffffffffffffffffffffffffffff")),
        T("0x33333333333333333333333333333333"));
    BOOST_CHECK_EQUAL(
        inverse_extended_euclidean_algorithm(T(333), T("0x7fffffffffffffffffffffffffffffff")),
        T("0x17d4f2ee517d4f2ee517d4f2ee517d4f"));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T("0x435b21e35ccd62dbdbafa1368cf742f0"),
                                                           T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x604ddb74e5a55e559a7320e45b06eaf6"));
    BOOST_CHECK_EQUAL(
        inverse_extended_euclidean_algorithm(
            T(2), T("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
        T("0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          "00000000000000000000"
          "0000000000000000000000000"));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(3), T(8)), T(3));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(46), T(207)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(2), T(2)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(0), T(2)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(46), T(46)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(1), T(7)), T(1));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(35), T(118)), T(27));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(37), T(37)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(32), T(247)), T(193));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(3), T(232)), T(155));

    BOOST_CHECK_EQUAL(
        inverse_extended_euclidean_algorithm(
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
        inverse_extended_euclidean_algorithm(
            T("657900513264442578215729259525804042708991731028255426638688946278845827095715186772"
              "097484"
              "16019817305674876843604308670298295897660589296995641401495105646770364032950"),
            T("146059874272782860583686068115674600616627249438711269370889274434354805551497286303"
              "947620"
              "1659720247220048664250204314648520085411164461712526657028588699682983099362771")),
        T("3701344688092353558099310214964185602579277616517826314317231208222417072861266226192312"
          "282752"
          "10678415132318220494260963802381448709723310690465171935975287188943190781"));

    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(3), T(0x10)), T(11));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(43000466091), T(0x10000000000)),
                      T(140404367363));

    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(
                          T("3329223706171052463206866408355190852145308853551222855374206553291583"
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
        inverse_extended_euclidean_algorithm(
            T(65279), T("0x100000000000000000000000000000000000000000000000000000000000000000000000"
                        "0000000000000000"
                        "00000000000000000000000000000000000000000000000000000000000")),
        T("2136191453734241471355287191702994357470910407859959447816962783332820558450714636705703"
          "817069"
          "8710253677755075362127788711957331760388539866898398399344480664991941861081743615"));
}

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
    BOOST_CHECK_EQUAL(inverse_mod(T(46), T(207)), T(0));
    BOOST_CHECK_EQUAL(inverse_mod(T(2), T(2)), T(0));
    BOOST_CHECK_EQUAL(inverse_mod(T(0), T(2)), T(0));
    BOOST_CHECK_EQUAL(inverse_mod(T(46), T(46)), T(0));
    BOOST_CHECK_EQUAL(inverse_mod(T(1), T(7)), T(1));
    BOOST_CHECK_EQUAL(inverse_mod(T(35), T(118)), T(27));
    BOOST_CHECK_EQUAL(inverse_mod(T(37), T(37)), T(0));
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

    BOOST_CHECK_EQUAL(inverse_mod(T("33292237061710524632068664083551908521453088535512228553742065"
                                    "532915836412003628111698671675220667324272"
                                    "59441069045458590915570173077273266668323626418910290729833115"
                                    "917608762612451607036836604560196526748133"
                                    "29522948231543216086195698566172041500850281737658912236916916"
                                    "850305170057553436136073435791550700526779"
                                    "12660561648431971151735424574091783976824121860178440448784777"
                                    "337066736659493124795020814172868481356070"
                                    "66940796741261651879705761216547813649105594986990007847567220"
                                    "787224253724912309650653332895570458720843"
                                    "32248506568118976869729175214974857589323352085671183814040169"
                                    "149453233350227887942508765678216349436356"
                                    "75846338481947840708222456495574685784973687231575617245307467"
                                    "847417686461029368632606300888825458750471"
                                    "73194357829837349405264332156553159"),
                                  T("51596692759022688970196837706341298598491314420895122094662553"
                                    "697486478852950434581004530951396375324897"
                                    "32379349334183998359005271540851438475735390060160055101459757"
                                    "369025094548935216928274885474920588457238"
                                    "93219921282613284811298303020722872923035014307024521461503233"
                                    "009837360681685755548737891159735617529596"
                                    "32962090241009808888741741043849264397734093528558956831628004"
                                    "860618936254613392484195923653331976713963"
                                    "90223849652458316548872173632032072142493359961192701645150390"
                                    "051578875246900773560274606831152842526302"
                                    "32119770327075242249607931076080422885968273410466133336708808"
                                    "535463570182780841768637479016464266039055"
                                    "79252439838082169284212200948381030179583349742050406608587079"
                                    "632257161952224606791379941232782765846637"
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
        inverse_mod(T(65279), T("0x1000000000000000000000000000000000000000000000000000000000000000"
                                "000000000000000000000000"
                                "00000000000000000000000000000000000000000000000000000000000")),
        T("2136191453734241471355287191702994357470910407859959447816962783332820558450714636705703"
          "817069"
          "8710253677755075362127788711957331760388539866898398399344480664991941861081743615"));
}

template<typename T>
void test_monty_inverse() {
    // test for monty_inverse
    BOOST_CHECK_EQUAL(monty_inverse(T(12), T(5), T(5)), T(1823));
    BOOST_CHECK_EQUAL(monty_inverse(T(10), T(37), T(1)), T(26));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(2), T(3)), T(3));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(4), T(2)), T(11));
    BOOST_CHECK_EQUAL(monty_inverse(T(4), T(7), T(2)), T(37));
    BOOST_CHECK_EQUAL(monty_inverse(T(32), T(247), T(1)), T(193));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(7), T(7)), T(549029));
    BOOST_CHECK_EQUAL(monty_inverse(T(5317589), T(23), T(8)), T(32104978469));
}

BOOST_AUTO_TEST_SUITE(runtime_tests)

BOOST_AUTO_TEST_CASE(inverse_tests) {
    // test_monty_inverse<big_uint<4096>>();
    // test_inverse_mod<big_uint<4096>>();
    // test_inverse_extended_euclidean_algorithm<big_uint<4096>>();
}

BOOST_AUTO_TEST_CASE(test_big_mod_6_bits) {
    auto modular = big_mod_rt<6>(10_bigui6, 37_bigui6);
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(modular).base(), 26u);
}

// BOOST_AUTO_TEST_CASE(test_cpp_int_modular_backend_6_bits) {
//     using namespace boost::multiprecision;
//     using T = boost::multiprecision::cpp_int_modular_modular_backend<6>;
//
//     modular = number<backends::modular_adaptor<T, backends::modular_params_rt<T>>>(3, 8);
//     modular.backend().mod_data().adjust_regular(res.backend(),
//                                                 inverse_extended_euclidean_algorithm(modular).backend().base_data());
//     BOOST_CHECK_EQUAL(number<T>(res.backend()), number<T>(3));
//
//     modular = number<backends::modular_adaptor<T, backends::modular_params_rt<T>>>(3, 16);
//     modular.backend().mod_data().adjust_regular(res.backend(),
//                                                 inverse_extended_euclidean_algorithm(modular).backend().base_data());
//     BOOST_CHECK_EQUAL(number<T>(res.backend()), number<T>(11));
//
//     modular = number<backends::modular_adaptor<T, backends::modular_params_rt<T>>>(
//         65279,
//         "0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//         "000000000000000000000000000000000000000");
//     modular.backend().mod_data().adjust_regular(res.backend(),
//                                                 inverse_extended_euclidean_algorithm(modular).backend().base_data());
//     BOOST_CHECK_EQUAL(
//         number<T>(res.backend()),
//         number<T>("213619145373424147135528719170299435747091040785995944781696278333282055845071463670570381706987102536"
//                 "77755075362127788711957331760388539866898398399344480664991941861081743615"));
//
//     modular = number<backends::modular_adaptor<T, backends::modular_params_rt<T>>>(
//         "33292237061710524632068664083551908521453088535512228553742065532915836412003628111698671675220667324272594410"
//         "69045458590915570173077273266668323626418910290729833115917608762612451607036836604560196526748133295229482315"
//         "43216086195698566172041500850281737658912236916916850305170057553436136073435791550700526779126605616484319711"
//         "51735424574091783976824121860178440448784777337066736659493124795020814172868481356070669407967412616518797057"
//         "61216547813649105594986990007847567220787224253724912309650653332895570458720843322485065681189768697291752149"
//         "74857589323352085671183814040169149453233350227887942508765678216349436356758463384819478407082224564955746857"
//         "8497368723157561724530746784741768646102936863260630088882545875047173194357829837349405264332156553159",
//         "51596692759022688970196837706341298598491314420895122094662553697486478852950434581004530951396375324897323793"
//         "49334183998359005271540851438475735390060160055101459757369025094548935216928274885474920588457238932199212826"
//         "13284811298303020722872923035014307024521461503233009837360681685755548737891159735617529596329620902410098088"
//         "88741741043849264397734093528558956831628004860618936254613392484195923653331976713963902238496524583165488721"
//         "73632032072142493359961192701645150390051578875246900773560274606831152842526302321197703270752422496079310760"
//         "80422885968273410466133336708808535463570182780841768637479016464266039055792524398380821692842122009483810301"
//         "7958334974205040660858707963225716195222460679137994123278276584663712976241848458904056941218720227786752");
//     modular.backend().mod_data().adjust_regular(res.backend(),
//                                                 inverse_extended_euclidean_algorithm(modular).backend().base_data());
//     BOOST_CHECK_EQUAL(
//         number<T>(res.backend()),
//         number<T>("161697650868559861271540461553971172959149630383872727836174576845991274476610311080533553178926047190"
//                 "203266855682387778179711917736974467565503622769386238790133592938052615852533561719117119940626105914"
//                 "149272955096438337875559227137733092417869557531785548219841868720728411947243663889165526728787046894"
//                 "739482800359519447645962037395419461841363898495986577864710230228655859268881063366400726401157990917"
//                 "652680450814220027329982285259267693662973801338310334464263818845826026848198196523975624137438165546"
//                 "650367370131035732951388159175971890099247228360312965057735541872892978783707133028552644759681714224"
//                 "704381891573964406129272600659255700500824412025869294370532513154961039220948194823131817745018177622"
//                 "2904306153521050324221361215524333142914455291939319"));
//     number<cpp_int_modular_backend<255>>
//     t1("46183318524466423714385242700212935662232011232920767824642233133732825160423");
//     number<cpp_int_modular_backend<255>>
//     t2("52435875175126190479447740508185965837690552500527637822603658699938581184513");
//     std::cout << "res1=" << inverse_mod(t1, t2) << std::endl;
//     std::cout << std::endl;
//     std::cout << "res1=" << inverse_mod(number<backends::modular_adaptor<T,
//     backends::modular_params_rt<T>>>(t1, t2)) << std::endl;
////5340958855958624790350191648327454295961274282628640357656781123563169745534
//    modular = number<backends::modular_adaptor<T, backends::modular_params_rt<T>>>(43000466091,
//    0x10000000000); modular.backend().mod_data().adjust_regular(res.backend(),
//                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
//    BOOST_CHECK_EQUAL(number<T>(res.backend()), number<T>(140404367363));
//}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(static_tests)
//
// BOOST_AUTO_TEST_CASE(cpp_int_fixed_test) {
//     using Backend = cpp_int_modular_backend<585>;
//     using Backend_modular = modular_adaptor<Backend, backends::modular_params_rt<Backend>>;
//     using modular_number = number<Backend_modular>;
//
//     constexpr auto mod =
//         0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_cppui_modular585;
//     constexpr auto a = 0xfeff_cppui_modular585;
//     constexpr auto a_inv =
//         0x565eb513c8dca58227a9d17b4cc814dcf1cec08f4fdf2f0e3d4b88d45d318ec04f0f5e6dcc3a06404686cd542175970ca3b05404585cb511c6d89f78178fa736de14f307fb02fe00ff_cppui_modular585;
//     static_assert(a_inv == inverse_extended_euclidean_algorithm(a, mod), "inverse error");
//
//     constexpr modular_number a_m(a, mod);
//     constexpr modular_number a_inv_m(a_inv, mod);
//     static_assert(a_inv_m == inverse_extended_euclidean_algorithm(a_m), "inverse error");
//
//     using T = number<Backend>;
//
//     static_assert(inverse_extended_euclidean_algorithm(T(3), T(8)) == T(3));
//     static_assert(inverse_extended_euclidean_algorithm(T(46), T(207)) == T(0));
//     static_assert(inverse_extended_euclidean_algorithm(T(2), T(2)) == T(0));
//     static_assert(inverse_extended_euclidean_algorithm(T(0), T(2)) == T(0));
//     static_assert(inverse_extended_euclidean_algorithm(T(46), T(46)) == T(0));
//     static_assert(inverse_extended_euclidean_algorithm(T(1), T(7)) == T(1));
//     static_assert(inverse_extended_euclidean_algorithm(T(35), T(118)) == T(27));
//     static_assert(inverse_extended_euclidean_algorithm(T(37), T(37)) == T(0));
//     static_assert(inverse_extended_euclidean_algorithm(T(32), T(247)) == T(193));
//     static_assert(inverse_extended_euclidean_algorithm(T(3), T(232)) == T(155));
//
//     static_assert(inverse_mod(T(3), T(8)) == T(3));
//     static_assert(inverse_mod(T(46), T(207)) == T(0));
//     static_assert(inverse_mod(T(2), T(2)) == T(0));
//     static_assert(inverse_mod(T(0), T(2)) == T(0));
//     static_assert(inverse_mod(T(46), T(46)) == T(0));
//     static_assert(inverse_mod(T(1), T(7)) == T(1));
//     static_assert(inverse_mod(T(35), T(118)) == T(27));
//     static_assert(inverse_mod(T(37), T(37)) == T(0));
//     static_assert(inverse_mod(T(32), T(247)) == T(193));
//     static_assert(inverse_mod(T(3), T(232)) == T(155));
//
//     static_assert(monty_inverse(T(12), T(5), T(5)) == T(1823));
//     static_assert(monty_inverse(T(10), T(37), T(1)) == T(26));
//     static_assert(monty_inverse(T(3), T(2), T(3)) == T(3));
//     static_assert(monty_inverse(T(3), T(4), T(2)) == T(11));
//     static_assert(monty_inverse(T(4), T(7), T(2)) == T(37));
//     static_assert(monty_inverse(T(32), T(247), T(1)) == T(193));
//     static_assert(monty_inverse(T(3), T(7), T(7)) == T(549029));
//     static_assert(monty_inverse(T(5317589), T(23), T(8)) == T(32104978469));
// }
//
// BOOST_AUTO_TEST_SUITE_END()
