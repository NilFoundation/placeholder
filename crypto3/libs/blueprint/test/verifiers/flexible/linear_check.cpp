//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_verifiers_plonk_dfri_linear_check_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/linear_check.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::size_t WitnessAmount, std::size_t GatesAmount>
void test_dfri_linear_check(const std::vector<typename BlueprintFieldType::value_type> &public_input, typename BlueprintFieldType::value_type expected_res,
                            std::size_t m,
                            std::vector<std::pair<std::size_t, std::size_t>> &eval_map) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = GatesAmount;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::dfri_linear_check<ArithmetizationType, BlueprintFieldType>;

    std::vector<var> xi;
    std::vector<var> y;
    std::vector<var> z;

    var theta = var(0, 0, false, var::column_type::public_input);
    var x = var(0, 1, false, var::column_type::public_input);


    std::vector<std::size_t> eval_map_ij;
    eval_map_ij.resize(m);
    std::size_t ctr = 0, I = 0, K = 0;

    for(std::size_t l = 0; l < eval_map.size(); l++){
        auto il = eval_map[l].first;
        auto jl = eval_map[l].second;

        eval_map_ij[il]++;
        I = std::max(I, il+1);
        K = std::max(K, jl+1);
    }

    for (std::size_t i = 0; i < K; i++){
        xi.push_back(var(0, i + 2, false, var::column_type::public_input));
    }

    for (std::size_t i = 0; i < I; i++){
        y.push_back(var(0, i + 2 + K, false, var::column_type::public_input));
    }

    ctr = I + K + 2;
    for(std::size_t i = 0; i < I; i++){
        // std::vector<var> z_i;
        for(std::size_t j = 0; j < eval_map_ij[i]; j++){
            z.push_back(var(0, ctr++, false, var::column_type::public_input));
        }
        // z.push_back(z_i);
    }

    typename component_type::input_type instance_input = {theta, x, xi, y, z};

    auto result_check = [&expected_res](AssignmentType &assignment,
                                        typename component_type::result_type &real_res) {
        // std::cout << "expected: " << expected_res << std::endl;
        // std::cout << "real res: " << var_value(assignment, real_res.output) <<
        // std::endl;
        BOOST_ASSERT(var_value(assignment, real_res.output) == expected_res);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 1>(), std::array<std::uint32_t, 1>(), m, eval_map);

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input, nil::blueprint::connectedness_check_type::type::STRONG, m);
}

// template<typename BlueprintFieldType, std::size_t RandomTestsAmount>
// void dfri_linear_check_tests() {
//     static boost::random::mt19937 seed_seq;
//     static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

//     for (std::size_t i = 0; i < RandomTestsAmount; i++) {
//         test_dfri_linear_check<BlueprintFieldType>(
//             {generate_random(), generate_random(), generate_random(), generate_random()});
//     }
// }

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_dfri_linear_check_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_1_k_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);

    value_type theta = generate_random();
    value_type x     = generate_random();
    value_type xi = generate_random();
    value_type y  = generate_random();
    value_type z  = generate_random();

    std::vector<value_type> public_inputs = {theta, x, xi, y, z};

    std::vector<std::pair<std::size_t, std::size_t> > eval_map = {std::make_pair(0,0)};
    std::size_t m = 1;
    
    value_type expected_res = (y - z) * ((x - xi).inversed());
    
    test_dfri_linear_check<field_type, 3, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 4, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 5, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 6, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 7, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 8, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 9, 1>(public_inputs, expected_res, m, eval_map);

}

BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_2_k_2) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);

    value_type theta = generate_random();
    value_type x     = generate_random();
    std::array<value_type, 2> xi = {generate_random(), generate_random()};
    std::array<value_type, 2> y  = {generate_random(), generate_random()};
    std::array<value_type, 2> z  = {generate_random(), generate_random()};

    std::vector<value_type> public_inputs = {theta, x, xi[0], xi[1], y[0],y[1], z[0], z[1]};

    std::vector<std::pair<std::size_t, std::size_t> > eval_map = {std::make_pair(0,1), std::make_pair(1,0)};
    std::size_t m = 2;
    
    value_type expected_res = (y[0] - z[0]) * ((x - xi[1]).inversed()) + theta * (y[1] - z[1]) * ((x - xi[0]).inversed());
    
    test_dfri_linear_check<field_type, 3, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 4, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 5, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 6, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 7, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 8, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 9, 1>(public_inputs, expected_res, m, eval_map);

}

BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_2_k_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);

    value_type theta = generate_random();
    value_type x     = generate_random();
    std::array<value_type, 2> y = {generate_random(), generate_random()};
    value_type xi  = generate_random();
    std::array<value_type, 2> z  = {generate_random(), generate_random()};

    std::vector<value_type> public_inputs = {theta, x, xi, y[0], y[1], z[0], z[1]};

    std::vector<std::pair<std::size_t, std::size_t> > eval_map = {std::make_pair(0,0), std::make_pair(1,0)};
    std::size_t m = 2;
    
    value_type expected_res = (y[0] - z[0]) * ((x - xi).inversed()) + theta * (y[1] - z[1]) * ((x - xi).inversed());
    
    test_dfri_linear_check<field_type, 3, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 4, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 5, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 6, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 7, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 8, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 9, 1>(public_inputs, expected_res, m, eval_map);

}

BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_20_k_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);

    constexpr std::size_t m = 20;
    value_type theta = generate_random();
    value_type x     = generate_random();
    std::array<value_type, m> y;
    for(std::size_t i = 0; i < m; i++) {y[i] = generate_random();};
    value_type xi  = generate_random();
    std::array<value_type, m> z;
    for(std::size_t i = 0; i < m; i++) {z[i] = generate_random();};

    std::vector<value_type> public_inputs = {theta, x, xi};
    public_inputs.insert(public_inputs.end(), y.begin(), y.end());
    public_inputs.insert(public_inputs.end(), z.begin(), z.end());

    std::vector<std::pair<std::size_t, std::size_t> > eval_map;
    for(std::size_t i = 0; i < m; i++) {
        eval_map.push_back(std::make_pair(i,0));
    }

    
    value_type expected_res = 0; 
    value_type theta_acc = 1;
    for(std::size_t i = 0; i < m; i++){
        expected_res = expected_res + theta_acc * (y[i] - z[i]) * ((x - xi).inversed());
        theta_acc = theta * theta_acc;
    }

    test_dfri_linear_check<field_type, 9, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 18, 2>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 27, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 15, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 21, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 24, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 30, 4>(public_inputs, expected_res, m, eval_map);

}



BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_13_k_3) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    constexpr std::size_t m = 13;
    constexpr std::size_t k = 3;
    constexpr std::size_t n = 7;
    value_type theta = 0x17f3269be06ff6c76417c00b03b877502ec58a8292c09a689aad0de2e3e6a209_big_uint255;
    value_type x   = 0x1109ad4c5183f69681888cf1ac9c73233ae4e3bd5ca9ad8e34b81c1a11794627_big_uint255;
    std::array<value_type, n> y = {
        0x109c08b6434fdac4656b1b3b9c169ea0bb3763c54a0f226544f2e7cbb07699d3_big_uint255,
        0x29807c67ad0e77f1cb7df52eaacda8c8aeb7323998949e1e6dc96ace49d7ffdb_big_uint255,
        0x1e3b7cc212edf2735ccafdfe4ed9cb66692b11ad423a6980084a7fc3fd3c174c_big_uint255,
        0x2597470a24d0a2cbbbc6d526352a994e8238fc24baeb88e8101812c861ac984b_big_uint255,
        0x1ce5a2c4753bad5ebe0a964361f32d6407d1b2b3424371d7202059510025a368_big_uint255,
        0x171f218f4a75c541784cc7754b0ce73200eeb37529f6d49df003e453ca9243b4_big_uint255,
        0xbd0de19ad7279aef43773c595c3d8b8cfd9c7469e3192e86f1f9abf3adb3ad2_big_uint255
    };
    
    std::array<value_type, k> xi = {
        0x3c4b5c29d2934183497c35596d868ddb8e0005397f67d2f26c91188ada9bd1c3_big_uint255,
        0x21ec40745cf822c5d422dc11f80a07845c4cb6ba727804c56a340f52bcfc6ace_big_uint255,
        0x15f359e7d0a1a4b1eff1de3a593890a472f721a83b8d7145bd1a4e830bc72298_big_uint255
    };


    std::vector<std::pair<std::size_t, std::size_t> > eval_map;
    
    eval_map.push_back(std::make_pair(0,0));  // (0, 0)
    eval_map.push_back(std::make_pair(1,0));  // (2, 0)
    eval_map.push_back(std::make_pair(2,0));  // (2, 1)
    eval_map.push_back(std::make_pair(3,0));  // (2, 2)
    eval_map.push_back(std::make_pair(4,0));  // (3, 0)
    eval_map.push_back(std::make_pair(5,0));  // (4, 0)
    eval_map.push_back(std::make_pair(6,0));  // (4, 1)
    eval_map.push_back(std::make_pair(3,1));  // (2, 2)
    eval_map.push_back(std::make_pair(4,1));  // (3, 0)
    eval_map.push_back(std::make_pair(3,2));  // (2, 2)
    eval_map.push_back(std::make_pair(4,2));  // (3, 0)
    eval_map.push_back(std::make_pair(5,2));  // (4, 0)
    eval_map.push_back(std::make_pair(6,2));  // (4, 1)

    std::vector<std::vector<value_type>> z(n, std::vector<value_type>());
    std::array<std::array<value_type, k>, n> z_ij;
    
    z_ij[0][0] = 0x20d25fb8470fd8fabc58145cb26ad8742c475753ae5ca5d8f3c1b44684ce4f0_big_uint255;
    z_ij[1][0] = 0x33c5922b908b7477233c66f1794147c57e3efd2bb2521669380e8178fac300c1_big_uint255;
    z_ij[2][0] = 0xd4c90ee14439e9196e9d185b8ca15dda515922c05ca40df31cf7f770e6aa49d_big_uint255;
    z_ij[3][0] = 0x228cee3a770a9e2f04a8fa727b31864730a2183747a1ef6d6a2b6b0946d099a4_big_uint255;
    z_ij[3][1] = 0x1784c045ae5ab50022bc3f598811196d5c195a66ec67b8d0aa43c45d321288bb_big_uint255;
    z_ij[3][2] = 0x23df4e8277cb5df68d32d783b1887bfb179f15717571db08c5579894e8c0ea42_big_uint255;
    z_ij[4][0] = 0x3806fca6f22cd78d49d22c125e67d81f6fd336faed8e8d16303309e4f9165b90_big_uint255;
    z_ij[4][1] = 0x3e5190c6669cce05fb6b3d63156f59f100cea0ff9730894e6133407213b8fc4b_big_uint255;
    z_ij[4][2] = 0x175df5a226a4870b5b45d0b050471dee42c433c8ecc42cab79829156528711bf_big_uint255;
    z_ij[5][0] = 0x2e8f89d9ffb7318286019c2ff4b8eba03fa812c97243a3e636b158c25e858c70_big_uint255;
    z_ij[5][2] = 0x29c647fa69040c8b336a6bd63fc97477441b147f4c98e6d9632ba3290f434b8d_big_uint255;
    z_ij[6][0] = 0x2a6a12ac90b00570b8b7dcb18540363ee0d7069aab9ab74bc30e92b8c3534cf1_big_uint255;
    z_ij[6][2] = 0xf244b829bb26edce0aed5a36c70c09c43e6e612cd9b328bbc6518f427fe5988_big_uint255;

    for(std::size_t i=0; i<n; i++){
        for(std::size_t j=0; j<k; j++){
            if(z_ij[i][j] != 0){
                z[i].push_back(z_ij[i][j]);
            }
        }
    }

    std::vector<value_type> public_inputs = {theta, x};
    public_inputs.insert(public_inputs.end(), xi.begin(), xi.end());
    public_inputs.insert(public_inputs.end(), y.begin(), y.end());
    for(const auto &z_i : z){
        public_inputs.insert(public_inputs.end(), z_i.begin(), z_i.end());
    }
    
    
    value_type expected_res = 0x349c635dc7675c9f442067d5ebd60641e51c89a1a049a4e3bf917fcc47c346c2_big_uint255;

    test_dfri_linear_check<field_type, 9, 1>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 18, 2>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 27, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 15, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 21, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 24, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 30, 4>(public_inputs, expected_res, m, eval_map);

}

BOOST_AUTO_TEST_SUITE_END()
