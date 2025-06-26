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
#define BOOST_TEST_MODULE blueprint_plonk_debugtt_test

#include <cstdlib>
#include <string_view>
#include <unordered_map>

#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
// #include <nil/crypto3/algebra/curves/pallas.hpp>
// #include <nil/crypto3/algebra/fields/goldilocks.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/babybear.hpp>
// #include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
// #include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include "./debugtt_test_fixture.hpp"

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_debugtt, zkEVMDebugTTTestFixture)
using big_field_type = typename nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
using small_field_extension_type = typename algebra::fields::babybear_fp4;

BOOST_AUTO_TEST_CASE(minimal_math) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 3;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;    // Doesn't matter for small fields

    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 100;
    max_sizes.max_zkevm_rows = 400;
    max_sizes.max_zkevm_small_field_rows = 250; // Used also for rw8, rw256
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 100;

    if (circuits_to_run.empty()) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("zkevm-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("minimal_math.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_counter) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(delegatecall_counter) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("delegatecall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(staticcall) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("staticcall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(counter) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(keccak) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 1000;
    max_sizes.max_copy_small_field_rows = 500; // For multicolumn copy testing
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("keccak");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_keccak) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if (circuits_to_run.empty()) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("keccak");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(indexed_log) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("indexed_log.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(cold_sstore) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("cold_sstore.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 1500;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("try_catch.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch2) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 6000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("try_catch2.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch_cold) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 6000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("try_catch_cold.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(sar) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("sar.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(scmp) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("scmp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(exp) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 3000;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("exp");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("exp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(modular) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 1000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 2000;
    max_sizes.max_copy = 70;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 10;
    max_sizes.max_exp_rows = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("modular.json", max_sizes);
}

// May be tested when block loader will be updated
BOOST_AUTO_TEST_CASE(precompiles) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 7;
    max_sizes.max_bytecode = 1000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 10;
    max_sizes.max_exp_rows = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("precompiles.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(mem) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 25;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("mem.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(codecopy) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 2000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("codecopy.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(transient_storage) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 2000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("transient_storage.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(transient_storage_revert) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 2000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("transient_storage_revert.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(large_calldata_key) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 1000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_zkevm_small_field_rows = 1000;

    if( circuits_to_run.empty() ) {
        // circuits_to_run.insert("zkevm"); //Previous version doesn't support large calldata keys
        // circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        // circuits_to_run.insert("copy"); //Previous version doesn't support large calldata keys
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("large_calldata_key.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_large_memory_key) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 4500;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_zkevm_small_field_rows = 6000;

    if( circuits_to_run.empty() ) {
        // circuits_to_run.insert("zkevm");       // Previous version doesn't support large memory keys
        // circuits_to_run.insert("rw");
        // circuits_to_run.insert("bytecode");    // Doesn't work for now
        // circuits_to_run.insert("copy");        // Previous version doesn't support large memory keys
        // circuits_to_run.insert("bytecode-s");  // Doesn't work for now
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_large_memory_key.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_large_mstore_key) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 8000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_zkevm_small_field_rows = 6000;

    if( circuits_to_run.empty() ) {
        // circuits_to_run.insert("zkevm");       // Previous version doesn't support large memory keys
        // circuits_to_run.insert("rw");
        // circuits_to_run.insert("bytecode");    // Doesn't work for now
        // circuits_to_run.insert("copy");        // Previous version doesn't support large memory keys
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_large_mstore_key.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_large_mstore8_key) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 8000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_zkevm_small_field_rows = 6000;

    if( circuits_to_run.empty() ) {
        // circuits_to_run.insert("zkevm");       // Previous version doesn't support large memory keys
        // circuits_to_run.insert("rw");
        // circuits_to_run.insert("bytecode");    // Doesn't work for now
        // circuits_to_run.insert("copy");        // Previous version doesn't support large memory keys
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("state-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_large_mstore8_key.json", max_sizes);
}

BOOST_AUTO_TEST_SUITE_END()
