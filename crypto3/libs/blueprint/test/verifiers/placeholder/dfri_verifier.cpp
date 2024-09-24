//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
#define BOOST_TEST_MODULE flexible_placeholder_verifier_test

#include <iostream>
#include <fstream>

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/eval_storage.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
// #include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/common_data.hpp>
#include <nil/blueprint/components/systems/snark/plonk/verifier/dfri_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/verifier/dfri_proof_wrapper.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

bool read_buffer_from_file(std::ifstream &ifile, std::vector<std::uint8_t> &v) {
    char c;
    char c1;
    uint8_t b;

    ifile >> c;
    if (c != '0')
        return false;
    ifile >> c;
    if (c != 'x')
        return false;
    while (ifile) {
        std::string str = "";
        ifile >> c >> c1;
        if (!isxdigit(c) || !isxdigit(c1))
            return false;
        str += c;
        str += c1;
        b = stoi(str, 0, 0x10);
        v.push_back(b);
    }
    return true;
}

struct default_zkllvm_params {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    using constraint_system_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using table_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using ColumnType = nil::crypto3::zk::snark::plonk_column<field_type>;
    using assignment_table_type = nil::crypto3::zk::snark::plonk_table<field_type, ColumnType>;

    using ColumnsRotationsType = std::vector<std::set<int>>;
    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
    using Hash = nil::crypto3::hashes::poseidon<poseidon_policy>;
    using transcript_hash_type = Hash;
    using circuit_params_type = nil::crypto3::zk::snark::placeholder_circuit_params<field_type>;

    using lpc_params_type = nil::crypto3::zk::commitments::list_polynomial_commitment_params<Hash, Hash, 2>;
    using lpc_type = nil::crypto3::zk::commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using commitment_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type>;
    using commitment_scheme_params_type = typename commitment_scheme_type::fri_type::params_type;
    using placeholder_params = nil::crypto3::zk::snark::placeholder_params<circuit_params_type, commitment_scheme_type>;
    using policy_type = nil::crypto3::zk::snark::detail::placeholder_policy<field_type, placeholder_params>;

    using circuit_marshalling_type =
        nil::crypto3::marshalling::types::plonk_constraint_system<default_zkllvm_params::TTypeBase,
                                                                  constraint_system_type>;
    using table_marshalling_type =
        nil::crypto3::marshalling::types::plonk_assignment_table<TTypeBase, assignment_table_type>;
    static table_description_type load_table_description(std::string filename) {
        std::ifstream iassignment;
        iassignment.open(filename, std::ios_base::binary | std::ios_base::in);
        BOOST_ASSERT(iassignment.is_open());
        std::vector<std::uint8_t> v;
        iassignment.seekg(0, std::ios_base::end);
        const auto fsize = iassignment.tellg();
        v.resize(fsize);
        iassignment.seekg(0, std::ios_base::beg);
        iassignment.read(reinterpret_cast<char *>(v.data()), fsize);
        BOOST_ASSERT(iassignment);
        iassignment.close();

        table_marshalling_type marshalled_table_data;
        auto read_iter = v.begin();
        auto status = marshalled_table_data.read(read_iter, v.size());
        auto [table_description, assignment_table] =
            nil::crypto3::marshalling::types::make_assignment_table<Endianness, assignment_table_type>(
                marshalled_table_data);

        return table_description;
    }

    static constraint_system_type load_circuit(std::string filename) {
        constraint_system_type constraint_system;
        {
            std::ifstream ifile;
            ifile.open(filename, std::ios_base::binary | std::ios_base::in);
            BOOST_ASSERT(ifile.is_open());

            std::vector<std::uint8_t> v;
            ifile.seekg(0, std::ios_base::end);
            const auto fsize = ifile.tellg();
            v.resize(fsize);
            ifile.seekg(0, std::ios_base::beg);
            ifile.read(reinterpret_cast<char *>(v.data()), fsize);
            BOOST_ASSERT(ifile);
            ifile.close();

            circuit_marshalling_type marshalled_data;
            auto read_iter = v.begin();
            auto status = marshalled_data.read(read_iter, v.size());
            constraint_system =
                nil::crypto3::marshalling::types::make_plonk_constraint_system<Endianness, constraint_system_type>(
                    marshalled_data);
        }
        return constraint_system;
    }
};

// template<typename ValueType>
// struct field_element_init{

//     template<typename ElementData>
//     static inline ValueType process(const ElementData &element_data) {
//         return ValueType(typename ValueType::integral_type(element_data.second.data()));
//     }
// };

// TODO(martun): consider moving these functions to some shared location so other tests can re-use them.
template<typename SrcParams>
static typename nil::blueprint::components::detail::dfri_proof_wrapper<typename SrcParams::placeholder_params> load_proof_json(std::string filename) {
    std::cout << "Loading proof from " << filename << std::endl;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    boost::property_tree::ptree jsontree;
    boost::property_tree::read_json(filename, jsontree);

    using PlaceholderParams = typename SrcParams::placeholder_params;
    using field_type = typename PlaceholderParams::field_type;
    using value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, PlaceholderParams>;
    using common_data_type = typename nil::crypto3::zk::snark::
        placeholder_public_preprocessor<field_type, PlaceholderParams>::preprocessed_data_type::common_data_type;

    constexpr static const std::size_t m = 2;
    typedef std::array<typename field_type::value_type, m> polynomial_value_type;
    typedef std::vector<polynomial_value_type> polynomial_values_type;

    // For initial proof only, size of all values are similar
    typedef std::vector<polynomial_values_type> polynomials_values_type;

    using merkle_proof_type = typename containers::merkle_proof<typename SrcParams::Hash, 2>;

    proof_type placeholder_proof;
    auto &eval_proof = placeholder_proof.eval_proof.eval_proof;
    std::size_t i, j, b, k, q;
    std::vector<value_type> evaluation_points;

    for (const auto &p : jsontree.get_child("evaluation_points")) {
        evaluation_points.push_back(value_type(integral_type(p.second.data())));
    }

    const boost::property_tree::ptree lpc_proof = jsontree.get_child("lpc_proof");

    i=0;
    for(const auto &batch_size : jsontree.get_child("params.batch_size")){
        eval_proof.z.set_batch_size(i, batch_size.second.get_value<std::size_t>());
        i++;
    }


    for(const auto &ev : lpc_proof.get_child("evaluations")){
        std::size_t batch_id = ev.second.get_child("batch_id").get_value<std::size_t>();
        std::size_t value_id = 0;
        std::size_t poly_id  = 0;
        std::size_t points   = 0;
        for(const auto &batch : ev.second.get_child("batch")){
            poly_id = batch.second.get_child("polynomial_index").get_value<std::size_t>();
            points  = batch.second.get_child("evaluation").size();
            eval_proof.z.set_poly_points_number(batch_id, poly_id, points);
            i = 0;
            for(const auto& value : batch.second.get_child("evaluation")){
                eval_proof.z.set(batch_id, poly_id, i, value_type(integral_type(value.second.data())));
                i++;
            }
        }
    }
    
    const boost::property_tree::ptree fri_proof = lpc_proof.get_child("fri_proof");
    for (const auto &fri_root : fri_proof.get_child("fri_roots")) {
        eval_proof.fri_proof.fri_roots.push_back(value_type(integral_type(fri_root.second.data())));
    }

    
    const boost::property_tree::ptree query_proofs = fri_proof.get_child("query_proofs");
    eval_proof.fri_proof.query_proofs.resize(query_proofs.size());
    BOOST_ASSERT(eval_proof.fri_proof.query_proofs.size() == jsontree.get<std::size_t>("params.lambda"));
    q = 0;
    for (const auto &query_proof : query_proofs) {
        for (const auto &batch : query_proof.second.get_child("initial_round_proof")) {
            std::size_t batch_id = batch.second.get_child("batch_id").get_value<std::size_t>();

            polynomials_values_type y;
            y.resize(batch.second.get_child("values").size());
            i = 0;
            for (const auto &yi : batch.second.get_child("values")) {
                y[i].resize(m-1);
                j = 0;
                for (const auto &yj : yi.second) {
                    y[i][0][j] = value_type(integral_type(yj.second.data()));
                    j++;
                }
                i++;
            }
            merkle_proof_type merkle_path;
            const auto path = batch.second.get_child("p");
            std::size_t li = path.get_child("leaf_index").get_value<std::size_t>();
            value_type root = value_type(integral_type(path.get_child("root").data()));

            typename merkle_proof_type::path_type auth_path;
            for (const auto &path_element : path.get_child("path")) {
                auth_path.push_back({typename merkle_proof_type::path_element_type(
                    value_type(integral_type(path_element.second.get_child("hash").data())),
                    path_element.second.get_child("position").get_value<std::size_t>())});
            }

            eval_proof.fri_proof.query_proofs[q].initial_proof.insert({batch_id, {y, merkle_proof_type(li, root, auth_path)}});
        }

        for(const auto &round_proof : query_proof.second.get_child("round_proofs")){
            polynomial_values_type y;
            y.resize(m-1);
            i = 0;
            for (const auto &yi : round_proof.second.get_child("y")) {
                y[0][i] = value_type(integral_type(yi.second.data()));
                i++;
            }

            merkle_proof_type merkle_path;
            const auto path = round_proof.second.get_child("p");
            std::size_t li = path.get_child("leaf_index").get_value<std::size_t>();
            value_type root = value_type(integral_type(path.get_child("root").data()));

            typename merkle_proof_type::path_type auth_path;
            for (const auto &path_element : path.get_child("path")) {
                auth_path.push_back({typename merkle_proof_type::path_element_type(
                    value_type(integral_type(path_element.second.get_child("hash").data())),
                    path_element.second.get_child("position").get_value<std::size_t>())});
            }
            eval_proof.fri_proof.query_proofs[q].round_proofs.push_back({y, merkle_proof_type(li, root, auth_path)});
        }
        q++;
    }

    math::polynomial<typename field_type::value_type> final_polynomial;
    for(const auto &coeffs : fri_proof.get_child("final_polynomial")){
        final_polynomial.push_back(value_type(integral_type(coeffs.second.data())));
    }
    eval_proof.fri_proof.final_polynomial = final_polynomial;

    return nil::blueprint::components::detail::dfri_proof_wrapper<PlaceholderParams>(placeholder_proof, evaluation_points);
}

// template<typename PlaceholderParams>
// static typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename PlaceholderParams::field_type,
// PlaceholderParams>::preprocessed_data_type::common_data_type load_common_data(std::string filename){
//     std::ifstream ifile;
//     ifile.open(filename, std::ios_base::binary | std::ios_base::in);
//     BOOST_ASSERT(ifile.is_open());

//     std::vector<std::uint8_t> v;
//     ifile.seekg(0, std::ios_base::end);
//     const auto fsize = ifile.tellg();
//     v.resize(fsize);
//     ifile.seekg(0, std::ios_base::beg);
//     ifile.read(reinterpret_cast<char*>(v.data()), fsize);
//     BOOST_ASSERT(ifile);
//     ifile.close();

//     using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename
//     PlaceholderParams::field_type, PlaceholderParams>::preprocessed_data_type::common_data_type;

//     nil::crypto3::marshalling::types::placeholder_common_data<default_zkllvm_params::TTypeBase, common_data_type>
//     marshalled_data; auto read_iter = v.begin(); auto status = marshalled_data.read(read_iter, v.size()); return
//     nil::crypto3::marshalling::types::make_placeholder_common_data<nil::marshalling::option::big_endian,
//     common_data_type>(
//         marshalled_data
//     );
// }

// template <std::size_t Witnesses>
// struct dst_params{
//     using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

//     static constexpr std::size_t WitnessColumns = Witnesses;
//     static constexpr std::size_t PublicInputColumns = 1;
//     static constexpr std::size_t ConstantColumns = 2;
//     static constexpr std::size_t SelectorColumns = 35;

//     using constraint_system_type =
//         nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
//     using table_description_type =
//         nil::crypto3::zk::snark::plonk_table_description<field_type>;
//     using Endianness = nil::marshalling::option::big_endian;
//     using TTypeBase = nil::marshalling::field_type<Endianness>;

//     using ColumnType = nil::crypto3::zk::snark::plonk_column<field_type>;
//     using assignment_table_type =
//         nil::crypto3::zk::snark::plonk_table<field_type, ColumnType>;

//     using ColumnsRotationsType = std::vector<std::set<int>>;
//     static const std::size_t Lambda = 9;//ParametersPolicy::lambda;
//     using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
//     using Hash = nil::crypto3::hashes::poseidon<poseidon_policy>;
//     using circuit_params = nil::crypto3::zk::snark::placeholder_circuit_params<field_type>;
// };

// inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
//     using dist_type = std::uniform_int_distribution<int>;
//     static std::random_device random_engine;

//     std::vector<std::size_t> step_list;
//     std::size_t steps_sum = 0;
//     while (steps_sum != r) {
//         if (r - steps_sum <= max_step) {
//             while (r - steps_sum != 1) {
//                 step_list.emplace_back(r - steps_sum - 1);
//                 steps_sum += step_list.back();
//             }
//             step_list.emplace_back(1);
//             steps_sum += step_list.back();
//         } else {
//             step_list.emplace_back(dist_type(1, max_step)(random_engine));
//             steps_sum += step_list.back();
//         }
//     }
//     return step_list;
// }

// template<typename SrcParams>
// std::tuple<typename SrcParams::common_data_type, typename SrcParams::commitment_scheme_params_type, typename
// SrcParams::proof_type> gen_test_proof(
//     typename SrcParams::constraint_system_type constraint_system,
//     typename SrcParams::table_description_type table_description,
//     typename SrcParams::assignment_table_type assignment_table
// ){
//     using src_placeholder_params = typename SrcParams::placeholder_params;
//     using field_type = typename SrcParams::field_type;
//     using fri_params_type = typename SrcParams::lpc_type::fri_type::params_type;

//     fri_params_type fri_params(0, std::ceil(std::log2(table_description.rows_amount)),
//         src_placeholder_params::lambda, 4 /*expand_factor*/);
//     typename SrcParams::commitment_scheme_type lpc_scheme(fri_params);

//     std::cout <<"Preprocess public data" << std::endl;
//     typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
//         field_type, src_placeholder_params>::preprocessed_data_type public_preprocessed_data =
//     nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, src_placeholder_params>::process(
//         constraint_system, assignment_table.move_public_table(), table_description, lpc_scheme
//     );

//     std::cout <<"Preprocess private data" << std::endl;
//     typename nil::crypto3::zk::snark::placeholder_private_preprocessor<
//         field_type, src_placeholder_params>::preprocessed_data_type private_preprocessed_data =
//         nil::crypto3::zk::snark::placeholder_private_preprocessor<field_type, src_placeholder_params>::process(
//             constraint_system, assignment_table.move_private_table(), table_description
//         );

//     std::cout <<"Generate proof" << std::endl;
//     typename SrcParams::proof_type proof = nil::crypto3::zk::snark::placeholder_prover<field_type,
//     src_placeholder_params>::process(
//         public_preprocessed_data, private_preprocessed_data, table_description, constraint_system, lpc_scheme
//     );

//     bool verification_result =
//         nil::crypto3::zk::snark::placeholder_verifier<field_type, src_placeholder_params>::process(
//             public_preprocessed_data, proof, table_description, constraint_system, lpc_scheme
//         );
//     std::cout <<"Proof verified" << std::endl;

//     BOOST_ASSERT(verification_result);

//     return std::make_tuple(public_preprocessed_data.common_data, fri_params, proof);
// }

template<typename SrcParams, typename DstParams>
void test_flexible_verifier(
    const typename SrcParams::constraint_system_type &constraint_system,
    const typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename SrcParams::field_type, SrcParams>::
        preprocessed_data_type::common_data_type &common_data,
    const typename nil::crypto3::zk::snark::placeholder_proof<typename SrcParams::field_type, SrcParams> &proof,
    const typename SrcParams::commitment_scheme_params_type &fri_params) {
    std::cout << "****************** Test flexible verifier with " << DstParams::WitnessColumns
              << " witness rows ******************" << std::endl;
    // using src_placeholder_params = typename SrcParams::placeholder_params;
    // using field_type = typename SrcParams::field_type;
    // using value_type = typename field_type::value_type;

    // std::array<std::uint32_t, DstParams::WitnessColumns> witnesses;
    // for (std::uint32_t i = 0; i < DstParams::WitnessColumns; i++) {
    //     witnesses[i] = i;
    // }
    // using component_type = nil::blueprint::components::plonk_flexible_verifier<typename DstParams::field_type,
    // SrcParams>; using var = crypto3::zk::snark::plonk_variable<value_type>;

    // bool expected_res = true;
    // auto result_check = [&expected_res](
    //     typename DstParams::assignment_table_type &assignment,
    //     typename component_type::result_type &real_res) {
    //         return true;
    // };

    // nil::blueprint::components::detail::placeholder_proof_input_type<SrcParams> full_instance_input(common_data,
    // constraint_system, fri_params); nil::blueprint::components::detail::placeholder_proof_wrapper<SrcParams>
    // proof_ext(common_data, proof);

    // std::size_t value_vector_size = proof_ext.vector().size();
    // std::cout << "value vector size = " << value_vector_size << std::endl;
    // std::cout << "var vector size =   " << full_instance_input.vector().size() << std::endl;
    // BOOST_ASSERT(proof_ext.vector().size() == full_instance_input.vector().size());

    // std::vector<typename field_type::value_type> public_input = proof_ext.vector();
    // typename component_type::input_type instance_input(full_instance_input);

    // std::array<std::uint32_t, DstParams::WitnessColumns> witness_ids;
    // for (std::uint32_t i = 0; i < DstParams::WitnessColumns; i++) {
    //     witness_ids[i] = i;
    // }
    // component_type component_instance(
    //     witness_ids, std::array<std::uint32_t, 1>({0}), std::array<std::uint32_t, 0>(),
    //     SrcParams(), constraint_system, common_data, fri_params
    // );

    // zk::snark::plonk_table_description<field_type> desc(
    //     DstParams::WitnessColumns, DstParams::PublicInputColumns, DstParams::ConstantColumns,
    //     DstParams::SelectorColumns);
    // std::cout << "desc = " << desc.rows_amount << " " << desc.witness_columns << " " << desc.public_input_columns <<
    // " " << desc.constant_columns << " " << desc.selector_columns << std::endl;

    // nil::crypto3::test_component<component_type, field_type, typename DstParams::Hash, DstParams::Lambda> (
    //     component_instance, desc, public_input, result_check,
    //     instance_input, nil::blueprint::connectedness_check_type::type::NONE,
    //     SrcParams(), constraint_system, common_data, fri_params
    // );
    // std::cout << "desc = " << desc.rows_amount << " " << desc.witness_columns << " " << desc.public_input_columns <<
    // " " << desc.constant_columns << " " << desc.selector_columns << std::endl;

    //    auto r_circuit0 = component_instance.generate_circuit(constraint_system, common_data);
    //    auto [r_table_description0, r_asignment0] = component_instance.generate_assignment(constraint_system,
    //    common_data, assignment_table.public_inputs(), proof);
}

template<typename SrcParams>
void test_multiple_arithmetizations(std::string folder_name) {
    //    auto table_description = SrcParams::load_table_description(folder_name + "/assignment.tbl");
    // std::cout << "Start loading" << std::endl;
    //     auto constraint_system = SrcParams::load_circuit(folder_name + "/circuit.crct");
    //     std::cout << "Loaded the constraint system" << std::endl;

    //     auto common_data = load_common_data<SrcParams>(folder_name + "/common.dat");
    //     std::cout << "Loaded the common data" << std::endl;

    //     auto proof = load_proof<SrcParams>(folder_name + "/proof.bin");
    //     std::cout << "Loaded the proof" << std::endl;
    //     auto table_description = common_data.desc;
    //     auto fri_params = common_data.commitment_params;

    //     std::cout << "Usable rows = " << table_description.usable_rows_amount << std::endl;
    //     std::cout << "Rows amount = " << table_description.rows_amount << std::endl;
    //     std::cout << "Witness amount = " << table_description.witness_columns << std::endl;
    //     std::cout << "Public input amount = " << table_description.public_input_columns << std::endl;
    //     std::cout << "Constant amount = " << table_description.constant_columns << std::endl;
    //     std::cout << "Selector amount = " << table_description.selector_columns << std::endl;
    //     std::cout << "Lambda = " << fri_params.lambda << std::endl;

    // //    auto [common_data, fri_params, proof] = gen_test_proof<SrcParams>(constraint_system, table_description,
    // assignment_table);

    //     test_flexible_verifier<SrcParams, dst_params<15>>(constraint_system, common_data, proof, fri_params);
    //     test_flexible_verifier<SrcParams, dst_params<42>>(constraint_system, common_data, proof, fri_params);
    //     test_flexible_verifier<SrcParams, dst_params<84>>(constraint_system, common_data, proof, fri_params);
    //     test_flexible_verifier<SrcParams, dst_params<168>>(constraint_system, common_data, proof, fri_params);
}

BOOST_AUTO_TEST_SUITE(blueprint_pallas_test_suite)

BOOST_AUTO_TEST_CASE(basic_test) {
    // test_multiple_arithmetizations<default_zkllvm_params>("../test/verifiers/placeholder/data/merkle_tree_poseidon");
    auto loaded_proof = load_proof_json<default_zkllvm_params>("test1.json");
}

// TODO: add vesta tests
// Cannot add bls12 tests because poseidon circuit is not implemented for it.

BOOST_AUTO_TEST_SUITE_END()
