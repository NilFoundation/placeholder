#define BOOST_AUTO_TEST_CASE_NO_MAIN

#include <nil/actor/test/unit_test_impl.hpp>

#include "core-test.hpp"

int main(int argc, char **argv) {
    using namespace nil::actor;
    init_global_meta_objects<id_block::core_test>();
    core::init_global_meta_objects();
    return test::main(argc, argv);
}
