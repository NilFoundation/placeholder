//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_curves_test

#include <iostream>
#include <type_traits>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/test/execution_monitor.hpp>

#include <boost/mpl/list.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>


#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>

#include <nil/crypto3/multiprecision/literals.hpp>

using namespace nil::crypto3::algebra;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

boost::property_tree::ptree string_data(std::string test_name) {
    // if target == check-algebra just data/curves.json
    static std::string test_data = std::string(TEST_DATA_DIR) + R"(curves.json)";
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
}

enum curve_operation_test_constants : std::size_t { C1, C2 };

enum curve_operation_test_points : std::size_t {
    p1,
    p2,
    p1_plus_p2,
    p1_minus_p2,
    p1_mul_C1,
    p2_mul_C1_plus_p2_mul_C2,
    p1_dbl,
    p1_mixed_add_p2,
    p1_to_affine,
    p2_to_special
};

template<typename CurveGroup>
void check_curve_operations(const std::vector<typename CurveGroup::value_type> &points,
                            const std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> &constants) {

    BOOST_CHECK_EQUAL(points[p1] + CurveGroup::value_type::zero(), points[p1]);
    BOOST_CHECK_EQUAL(points[p1] - CurveGroup::value_type::zero(), points[p1]);
    BOOST_CHECK_EQUAL(points[p1] - points[p1], CurveGroup::value_type::zero());
    BOOST_CHECK_EQUAL(points[p1] * (0u), CurveGroup::value_type::zero());

    BOOST_CHECK_EQUAL(points[p1] + points[p2], points[p1_plus_p2]);
    BOOST_CHECK_EQUAL(points[p1] - points[p2], points[p1_minus_p2]);
    typename CurveGroup::value_type p_copy = points[p1];
    p_copy.double_inplace();
    BOOST_CHECK_EQUAL(p_copy, points[p1_dbl]);
    BOOST_CHECK_EQUAL(points[p1] * (constants[C1]), points[p1_mul_C1]);
    BOOST_CHECK_EQUAL((points[p2] * (constants[C1])) +
                          (points[p2] * (constants[C2])),
                      points[p2_mul_C1_plus_p2_mul_C2]);
    BOOST_CHECK_EQUAL((points[p2] * (constants[C1])) +
                          (points[p2] * (constants[C2])),
                      points[p2] * (constants[C1] + constants[C2]));
    p_copy = points[p2];
    p_copy.mixed_add(points[p1_to_affine]);
    BOOST_CHECK_EQUAL(p_copy, points[p1_mixed_add_p2]);
    // typename CurveGroup::value_type p1_copy = points[p1].to_affine();
    BOOST_CHECK_EQUAL(points[p1].to_affine().X, points[p1_to_affine].to_affine().X);
    BOOST_CHECK_EQUAL(points[p1].to_affine().Y, points[p1_to_affine].to_affine().Y);
    // typename CurveGroup::value_type p2_copy = typename CurveGroup::value_type(points[p2]).to_projective();
    // BOOST_CHECK_EQUAL(p2_copy, points[p2_to_special]);

    // Check in place addition, substraction, etc.
    typename CurveGroup::value_type result = points[p1];
    result += points[p2];

    BOOST_CHECK_EQUAL(result, points[p1_plus_p2]);
    result = points[p1];
    result -= points[p2];
    BOOST_CHECK_EQUAL(result, points[p1_minus_p2]);

    result = points[p1];
    result *= (constants[C1]);
    BOOST_CHECK_EQUAL(result, points[p1_mul_C1]);

    result = points[p2];
    result *= (constants[C1]);
    result += points[p2] * (constants[C2]);
    BOOST_CHECK_EQUAL(result, points[p2_mul_C1_plus_p2_mul_C2]);
}

// temporary separated test for JubJub and BabyJubJub
template<typename CurveGroup>
void check_curve_operations_twisted_edwards(
    std::vector<typename CurveGroup::value_type> &points,
    const std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> &constants) {

    using scalar = typename CurveGroup::params_type::scalar_field_type::value_type;

    BOOST_CHECK_MESSAGE(subgroup_check(points[p1]), "Point p1 subgroup check");
    BOOST_CHECK_MESSAGE(subgroup_check(points[p2]), "Point p2 subgroup check");

    BOOST_CHECK_EQUAL(points[p1] + points[p2], points[p1_plus_p2]);
    BOOST_CHECK_EQUAL(points[p1] - points[p2], points[p1_minus_p2]);
    typename CurveGroup::value_type p_copy = points[p1];
    p_copy.double_inplace();
    BOOST_CHECK_EQUAL(p_copy, points[p1_dbl]);
    BOOST_CHECK_EQUAL( points[p1] * (constants[C1]), points[p1_mul_C1]);
    BOOST_CHECK_EQUAL((points[p2] * (constants[C1])) +
                      (points[p2] * (constants[C2])), points[p2_mul_C1_plus_p2_mul_C2]);
    BOOST_CHECK_EQUAL((points[p2] * (constants[C1])) +
                      (points[p2] * (constants[C2])),
                       points[p2] * (constants[C1] + constants[C2]));
    // BOOST_CHECK_EQUAL(points[p1].mixed_add(points[p2]), points[p1_mixed_add_p2]);
    // typename CurveGroup::value_type p1_copy = typename CurveGroup::value_type(points[p1]).to_affine();
    // BOOST_CHECK_EQUAL(p1_copy, points[p1_to_affine]);
    // typename CurveGroup::value_type p2_copy = typename CurveGroup::value_type(points[p2]).to_projective();
    // BOOST_CHECK_EQUAL(p2_copy, points[p2_to_special]);

    // Check in place addition, substraction, etc.
    typename CurveGroup::value_type result = points[p1];
    result += points[p2];

    BOOST_CHECK_EQUAL(result, points[p1_plus_p2]);
    result = points[p1];
    result -= points[p2];
    BOOST_CHECK_EQUAL(result, points[p1_minus_p2]);

    result = points[p1];
    result *= (constants[C1]);
    BOOST_CHECK_EQUAL(result, points[p1_mul_C1]);

    result = points[p2];
    result *= (constants[C1]);
    result += points[p2] * (constants[C2]);
    BOOST_CHECK_EQUAL(result, points[p2_mul_C1_plus_p2_mul_C2]);
}

template<typename CurveParams>
void check_montgomery_twisted_edwards_conversion(
    const std::vector<
        curves::detail::curve_element<CurveParams, curves::forms::montgomery, curves::coordinates::affine>> &points,
    const std::vector<typename CurveParams::scalar_field_type::value_type> &constants) {
    BOOST_CHECK_EQUAL(points[p1], points[p1].to_twisted_edwards().to_montgomery());
    BOOST_CHECK_EQUAL(points[p1] + points[p2],
                      (points[p1].to_twisted_edwards() + points[p2].to_twisted_edwards()).to_montgomery());
}

template<typename FpCurveGroup, typename TestSet>
void fp_curve_test_init(std::vector<typename FpCurveGroup::value_type> &points,
                        std::vector<typename FpCurveGroup::params_type::scalar_field_type::value_type> &constants,
                        const TestSet &test_set) {
    typedef typename FpCurveGroup::field_type::value_type field_value_type;
    std::array<field_value_type, 3> coordinates;

    int p = 0;
    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::integral_type(coordinate.second.data()));
        }

        if (p1_to_affine == p) {
            typename FpCurveGroup::value_type curve_element(coordinates[0], coordinates[1]);
            BOOST_CHECK_MESSAGE(curve_element.is_well_formed(), "point " << p << " is not well-formed");
            points.emplace_back(curve_element);
        } else {
            typename FpCurveGroup::value_type curve_element(coordinates[0], coordinates[1], coordinates[2]);
            BOOST_CHECK_MESSAGE(curve_element.is_well_formed(), "point " << p << " is not well-formed");
            points.emplace_back(curve_element);
        }
        ++p;
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename FpCurveGroup, typename TestSet>
void fp_curve_twisted_edwards_test_init(
        std::vector<typename FpCurveGroup::value_type> &points,
        std::vector<typename FpCurveGroup::params_type::scalar_field_type::value_type> &constants,
        const TestSet &test_set) {
    typedef typename FpCurveGroup::field_type::value_type field_value_type;
    std::array<field_value_type, 2> coordinates;
    using scalar_field_type = typename FpCurveGroup::params_type::scalar_field_type;
    using scalar_value_type = typename scalar_field_type::value_type;
    using integral_type = typename scalar_field_type::integral_type;

    int p = 0;
    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::integral_type(coordinate.second.data()));
        }
        typename FpCurveGroup::value_type curve_element(coordinates[0], coordinates[1]);
        BOOST_CHECK_MESSAGE(curve_element.is_well_formed(), "point " << p << " is not well-formed");
        points.emplace_back(curve_element);
        ++p;
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(scalar_value_type(integral_type(constant.second.data())));
    }
}

template<typename FpCurveGroup, typename TestSet>
void fp_extended_curve_twisted_edwards_test_init(
    std::vector<typename FpCurveGroup::value_type> &points,
    std::vector<typename FpCurveGroup::params_type::scalar_field_type::value_type> &constants,
    const TestSet &test_set) {
    typedef typename FpCurveGroup::field_type::value_type field_value_type;
    typedef
        typename FpCurveGroup::curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>
            group_affine_type;
    using scalar_field_type = typename FpCurveGroup::params_type::scalar_field_type;
    using scalar_value_type = typename scalar_field_type::value_type;
    using integral_type = typename scalar_field_type::integral_type;

    std::array<field_value_type, 2> coordinates;

    int p = 0;
    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::integral_type(coordinate.second.data()));
        }
        typename group_affine_type::value_type curve_element_affine(coordinates[0], coordinates[1]);
        BOOST_CHECK_MESSAGE(curve_element_affine.is_well_formed(), "point " << p << " is not well-formed");
        auto curve_element_extended = curve_element_affine.to_extended_with_a_minus_1();
        BOOST_CHECK_MESSAGE(curve_element_extended.is_well_formed(), "point " << p << " is not well-formed");
        points.emplace_back(curve_element_extended);
        ++p;
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(scalar_value_type(integral_type(constant.second.data())));
    }
}

template<typename Fp2CurveGroup, typename TestSet>
void fp2_curve_test_init(std::vector<typename Fp2CurveGroup::value_type> &points,
                         std::vector<typename Fp2CurveGroup::params_type::scalar_field_type::value_type> &constants,
                         const TestSet &test_set) {
    using fp2_value_type = typename Fp2CurveGroup::field_type::value_type;
    using integral_type = typename fp2_value_type::underlying_type::integral_type;
    std::array<integral_type, 6> coordinates;
    using scalar_field_type = typename Fp2CurveGroup::params_type::scalar_field_type;
    using scalar_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;


    int p = 0;
    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate_pairs : point.second) {
            for (auto &coordinate : coordinate_pairs.second) {
                coordinates[i++] = integral_type(coordinate.second.data());
            }
        }
        typename Fp2CurveGroup::value_type curve_element(
                    fp2_value_type(coordinates[0], coordinates[1]),
                    fp2_value_type(coordinates[2], coordinates[3]),
                    fp2_value_type(coordinates[4], coordinates[5]));
        BOOST_CHECK_MESSAGE(curve_element.is_well_formed(), "point " << p << " is not well-formed");
        points.emplace_back(curve_element);
        ++p;
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(scalar_value_type(scalar_integral_type(constant.second.data())));
    }
}

template<typename Fp3CurveGroup, typename TestSet>
void fp3_curve_test_init(std::vector<typename Fp3CurveGroup::value_type> &points,
                         std::vector<typename Fp3CurveGroup::params_type::scalar_field_type::value_type> &constants,
                         const TestSet &test_set) {
    using fp3_value_type = typename Fp3CurveGroup::field_type::value_type;
    using integral_type = typename fp3_value_type::underlying_type::integral_type;
    using scalar_field_type = typename Fp3CurveGroup::params_type::scalar_field_type;
    using scalar_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;

    std::array<integral_type, 9> coordinates;

    int p = 0;
    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate_pairs : point.second) {
            for (auto &coordinate : coordinate_pairs.second) {
                coordinates[i++] = integral_type(coordinate.second.data());
            }
        }
        typename Fp3CurveGroup::value_type curve_element(
                    fp3_value_type(coordinates[0], coordinates[1], coordinates[2]),
                    fp3_value_type(coordinates[3], coordinates[4], coordinates[5]),
                    fp3_value_type(coordinates[6], coordinates[7], coordinates[8]));
        BOOST_CHECK_MESSAGE(curve_element.is_well_formed(), "point " << p << " is not well-formed");
        points.emplace_back(curve_element);
        ++p;
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(scalar_value_type(scalar_integral_type(constant.second.data())));
    }
}

template<typename CurveGroup, typename TestSet>
void curve_operation_test(
        const TestSet &test_set,
        void (&test_init)(std::vector<typename CurveGroup::value_type> &,
            std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> &,
            const TestSet &)) {

    std::vector<typename CurveGroup::value_type> points;
    std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> constants;

    test_init(points, constants, test_set);

    check_curve_operations<CurveGroup>(points, constants);
}

template<typename CurveGroup, typename TestSet>
void curve_operation_test_twisted_edwards(
    const TestSet &test_set,
    void (&test_init)(std::vector<typename CurveGroup::value_type> &,
                      std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> &,
                      const TestSet &)) {

    std::vector<typename CurveGroup::value_type> points;
    std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> constants;

    test_init(points, constants, test_set);

    check_curve_operations_twisted_edwards<CurveGroup>(points, constants);
}

template<typename CurveGroup, typename TestSet>
void curve_operation_test_montgomery(
        const TestSet &test_set,
        void (&test_init)(std::vector<typename CurveGroup::value_type> &,
            std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> &,
            const TestSet &)) {

    std::vector<typename CurveGroup::value_type> points;
    std::vector<typename CurveGroup::params_type::scalar_field_type::value_type> constants;

    test_init(points, constants, test_set);

    check_curve_operations_twisted_edwards<CurveGroup>(points, constants);
    check_montgomery_twisted_edwards_conversion(points, constants);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)
/**/

BOOST_DATA_TEST_CASE(curve_operation_test_jubjub_g1, string_data("curve_operation_test_jubjub_g1"), data_set) {
    using policy_type = curves::jubjub::g1_type<>;

    curve_operation_test_twisted_edwards<policy_type>(data_set, fp_curve_twisted_edwards_test_init<policy_type>);
}

BOOST_AUTO_TEST_CASE(curve_operation_test_babyjubjub_g1) {
    using policy_type = curves::babyjubjub::g1_type<>;
    using integral_type = typename policy_type::params_type::scalar_field_type::integral_type;
    using scalar_value_type = typename policy_type::params_type::scalar_field_type::value_type;

    typename policy_type::value_type P1(
        typename policy_type::field_type::value_type(
            0x274DBCE8D15179969BC0D49FA725BDDF9DE555E0BA6A693C6ADB52FC9EE7A82C_big_uint254),
        typename policy_type::field_type::value_type(
            0x5CE98C61B05F47FE2EAE9A542BD99F6B2E78246231640B54595FEBFD51EB853_big_uint251)),
        P2(typename policy_type::field_type::value_type(
               0x2491ABA8D3A191A76E35BC47BD9AFE6CC88FEE14D607CBE779F2349047D5C157_big_uint254),
           typename policy_type::field_type::value_type(
               0x2E07297F8D3C3D7818DBDDFD24C35583F9A9D4ED0CB0C1D1348DD8F7F99152D7_big_uint254)),
        P3(typename policy_type::field_type::value_type(
               0x11805510440A3488B3B811EAACD0EC7C72DDED51978190E19067A2AFAEBAF361_big_uint253),
           typename policy_type::field_type::value_type(
               0x1F07AA1B3C598E2FF9FF77744A39298A0A89A9027777AF9FA100DD448E072C13_big_uint253));

    BOOST_CHECK_EQUAL(P1 + P2, P3);

    typename policy_type::value_type P4(
        typename policy_type::field_type::value_type(
            0xF3C160E26FC96C347DD9E705EB5A3E8D661502728609FF95B3B889296901AB5_big_uint),
        typename policy_type::field_type::value_type(
            0x9979273078B5C735585107619130E62E315C5CAFE683A064F79DFED17EB14E1_big_uint));

    P1.double_inplace();
    BOOST_CHECK_EQUAL(P1, P4);

    typename policy_type::value_type P5(
        typename policy_type::field_type::value_type(
            0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c_big_uint),
        typename policy_type::field_type::value_type(
            0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853_big_uint)),
        et_s1P5(typename policy_type::field_type::value_type(
                    0x2ad46cbfb78773b6254adc1d80c6efa02f3bf948c37e5a2222136421d7bec942_big_uint),
                typename policy_type::field_type::value_type(
                    0x14e9693f16d75f7065ce51e1f46ae6c60841ca1e0cf264eda26398e36ca2ed69_big_uint)),
        et_s2P5(typename policy_type::field_type::value_type(
                    0x031b924a83fbbdc206fb2d3bc85b7a724000714627f681a60b34885e4deca1d6_big_uint),
                typename policy_type::field_type::value_type(
                    0x242e364702e64a6850c9aee7ece7ca79ba019ca7a63684e2df0873ca0d8f7e87_big_uint)),
        P6(typename policy_type::field_type::value_type(
               0xf3c160e26fc96c347dd9e705eb5a3e8d661502728609ff95b3b889296901ab5_big_uint),
           typename policy_type::field_type::value_type(
               0x9979273078b5c735585107619130e62e315c5cafe683a064f79dfed17eb14e1_big_uint)),
        et_s1P6(typename policy_type::field_type::value_type(
                    0x2e6475817d356adbbfcec42b2f7b90500d6f74e8cd4ec1ac0b6effd00ba854d7_big_uint),
                typename policy_type::field_type::value_type(
                    0x195a50f93ff3f3e68bd593be5781301c32962777dc8237b099c23d39c24ec76a_big_uint));

    BOOST_CHECK_EQUAL(et_s1P5, scalar_value_type(integral_type(3u)) * P5);
    BOOST_CHECK_EQUAL(et_s2P5, scalar_value_type(integral_type(
                    "14035240266687799601661095864649209771790948434046947201833777492504781")) * P5);
    BOOST_CHECK_EQUAL(et_s1P6, scalar_value_type(integral_type(
                    "20819045374670962167435360035096875258406992893633759881276124905556507")) * P6);
    BOOST_CHECK(P5.is_well_formed());
    BOOST_CHECK(P6.is_well_formed());

    // curve_operation_test_twisted_edwards<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_jubjub_montgomery_affine,
                     string_data("curve_operation_test_jubjub_montgomery_affine"),
                     data_set) {
    using policy_type = curves::jubjub::g1_type<curves::coordinates::affine, curves::forms::montgomery>;

    curve_operation_test_montgomery<policy_type>(data_set, fp_curve_twisted_edwards_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_babyjubjub_montgomery_affine,
                     string_data("curve_operation_test_babyjubjub_montgomery_affine"),
                     data_set) {
    using policy_type = curves::babyjubjub::g1_type<curves::coordinates::affine, curves::forms::montgomery>;

    curve_operation_test_montgomery<policy_type>(data_set, fp_curve_twisted_edwards_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt4_g1, string_data("curve_operation_test_mnt4_g1"), data_set) {
    using policy_type = curves::mnt4<298>::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt6_g1, string_data("curve_operation_test_mnt6_g1"), data_set) {
    using policy_type = curves::mnt6<298>::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt4_g2, string_data("curve_operation_test_mnt4_g2"), data_set) {
    using policy_type = curves::mnt4<298>::g2_type<>;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt6_g2, string_data("curve_operation_test_mnt6_g2"), data_set) {
    using policy_type = curves::mnt6<298>::g2_type<>;

    curve_operation_test<policy_type>(data_set, fp3_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_381_g1, string_data("curve_operation_test_bls12_381_g1"), data_set) {
    using policy_type = curves::bls12<381>::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_377_g1, string_data("curve_operation_test_bls12_377_g1"), data_set) {
    using policy_type = curves::bls12<377>::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_381_g2, string_data("curve_operation_test_bls12_381_g2"), data_set) {
    using policy_type = curves::bls12<381>::g2_type<>;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_377_g2, string_data("curve_operation_test_bls12_377_g2"), data_set) {
    using policy_type = curves::bls12<377>::g2_type<>;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_alt_bn128_g1, string_data("curve_operation_test_alt_bn128_g1"), data_set) {
    using policy_type = curves::alt_bn128<254>::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_alt_bn128_g2, string_data("curve_operation_test_alt_bn128_g2"), data_set) {
    using policy_type = curves::alt_bn128<254>::g2_type<>;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_secp256_r1_g1, string_data("curve_operation_test_secp256r1"), data_set) {
    using policy_type = curves::secp_r1<256>::g1_type<>;
    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_secp256_k1_g1, string_data("curve_operation_test_secp256k1"), data_set) {
    using policy_type = curves::secp_k1<256>::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_edwards25519, string_data("curve_operation_test_edwards25519"), data_set) {
    using policy_type = curves::ed25519::g1_type<>;

    static_assert(std::is_same<typename curves::ed25519::g1_type<>::curve_type, curves::ed25519>::value);

    curve_operation_test_twisted_edwards<policy_type>(data_set, fp_extended_curve_twisted_edwards_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_pallas, string_data("curve_operation_test_pallas"), data_set) {
    using policy_type = curves::pallas::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}
BOOST_DATA_TEST_CASE(curve_operation_test_vesta, string_data("curve_operation_test_vesta"), data_set) {
    using policy_type = curves::vesta::g1_type<>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

/*
 * Tests for "NOTE: does not handle O and pts of order 2,4"
 * short Weierstrass forms
 */
template<typename coordinates>
class bls12_377_orders_2_4_runner {
    using curve_type = curves::bls12_377;
    using g1_type = curve_type::g1_type<coordinates>;

    // point of order 2
    static constexpr curve_type::base_field_type::value_type
        o2_X = curve_type::base_field_type::modulus - 1,
        o2_Y = 0u;
    // point of order 4
    static constexpr curve_type::base_field_type::value_type
        o4_X = 0x126f980765bb3d634f9d5cb49909db8af2e185fb13bdb7dc4aedcadf9d8dad86bba02eda906066c9153bdf72ddce76c_big_uint377,
        o4_Y = 0x06e4b66bb23ef4bef715f597162d6662d8161cd062d6212d39392e17232444a0760b5dc479db98123ab3887aa3cb34e_big_uint377;

    public:
    bool static run() {
        typename g1_type::value_type o4(o4_X, o4_Y), o2(o2_X, o2_Y), check;

        BOOST_CHECK(o4.is_well_formed());
        BOOST_CHECK(o2.is_well_formed());

        check = o4 + o4 + o4 + o4;
        BOOST_CHECK_EQUAL(check, g1_type::value_type::zero());
        check = o2 + o2;
        BOOST_CHECK_EQUAL(check, g1_type::value_type::zero());
        return true;
    }

};

using bls12_377_orders_2_4_runners = boost::mpl::list<
    bls12_377_orders_2_4_runner<curves::coordinates::projective>,
    bls12_377_orders_2_4_runner<curves::coordinates::jacobian>,
    bls12_377_orders_2_4_runner<curves::coordinates::jacobian_with_a4_0> >;

/* No tests for projective_with_a4_minus_3 and jacobian_with_a4_minus_3
 * Only secp<Version>_r1 curves have a4 = -3, but these curves have cofactor = 1,
 * so there are no points of order 2 and 4 */

BOOST_AUTO_TEST_CASE_TEMPLATE(bls12_377_order_test, runner, bls12_377_orders_2_4_runners) {
    BOOST_CHECK(runner::run());
}

/*
 * Twisted Edwards forms
 * extended coordinates
 */
BOOST_AUTO_TEST_CASE(twisted_edwards_extended_order_test) {
    using curve_type = curves::ed25519;
    using g1_type = typename curve_type::g1_type<>;

    /* Point of order 2 */
    curve_type::base_field_type::value_type
        o2_X = 0x0_big_uint255,
        o2_Y = curve_type::base_field_type::modulus - 1;

    /* Point of order 4 */
    curve_type::base_field_type::value_type
        o4_X = 0x547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d_big_uint255,
        o4_Y = 0x0_big_uint255;

    typename g1_type::value_type o4(o4_X, o4_Y), o2(o2_X, o2_Y), check;

    BOOST_CHECK(o4.is_well_formed());
    BOOST_CHECK(o2.is_well_formed());

    check = o4 + o4 + o4 + o4;
    BOOST_CHECK_EQUAL(check, g1_type::value_type::zero());
    check = o2 + o2;
    BOOST_CHECK_EQUAL(check, g1_type::value_type::zero());
}

BOOST_AUTO_TEST_SUITE_END()
