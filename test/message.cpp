//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE message

#include <nil/actor/message.hpp>

#include "core-test.hpp"

#include <map>
#include <numeric>
#include <string>
#include <vector>

#include <nil/actor/init_global_meta_objects.hpp>
#include <nil/actor/message_handler.hpp>
#include <nil/actor/type_id.hpp>
#include <nil/actor/type_id_list.hpp>

using std::make_tuple;
using std::map;
using std::string;
using std::vector;

using namespace nil::actor;

using namespace std::literals::string_literals;

namespace {

    template<class... Ts>
    std::string msg_as_string(Ts &&... xs) {
        return to_string(make_message(std::forward<Ts>(xs)...));
    }

}    // namespace

ACTOR_TEST(messages allow index - based access) {
    auto msg = make_message("abc", uint32_t {10}, 20.0);
    BOOST_CHECK_EQUAL(msg.size(), 3u);
    BOOST_CHECK_EQUAL(msg.types(), (make_type_id_list<std::string, uint32_t, double>()));
    BOOST_CHECK_EQUAL(msg.get_as<std::string>(0), "abc");
    BOOST_CHECK_EQUAL(msg.get_as<uint32_t>(1), 10u);
    BOOST_CHECK_EQUAL(msg.get_as<double>(2), 20.0);
    BOOST_CHECK_EQUAL(msg.cdata().get_reference_count(), 1u);
}

BOOST_AUTO_TEST_CASE(compare_custom_types) {
    s2 tmp;
    tmp.value[0][1] = 100;
    ACTOR_CHECK_NOT_EQUAL(to_string(make_message(s2 {})), to_string(make_message(tmp)));
}

BOOST_AUTO_TEST_CASE(empty_to_string) {
    message msg;
    BOOST_CHECK_EQUAL(to_string(msg), "<empty-message>");
}

BOOST_AUTO_TEST_CASE(integers_to_string) {
    using ivec = vector<int32_t>;
    using svec = vector<std::string>;
    using sset = std::set<std::string>;
    using std::string;
    using itup = std::tuple<int, int, int>;
    BOOST_CHECK_EQUAL(make_message(ivec {}).types(), make_type_id_list<ivec>());
    BOOST_CHECK_EQUAL(make_type_id_list<ivec>()[0], type_id_v<ivec>);
    BOOST_CHECK_EQUAL(make_message(ivec {}).types()[0], type_id_v<ivec>);
    BOOST_CHECK_EQUAL(make_message(1.0).types()[0], type_id_v<double>);
    BOOST_CHECK_EQUAL(make_message(s1 {}).types()[0], type_id_v<s1>);
    BOOST_CHECK_EQUAL(make_message(s2 {}).types()[0], type_id_v<s2>);
    BOOST_CHECK_EQUAL(make_message(s3 {}).types()[0], type_id_v<s3>);
    BOOST_CHECK_EQUAL(make_message(svec {}).types()[0], type_id_v<svec>);
    BOOST_CHECK_EQUAL(make_message(string {}).types()[0], type_id_v<string>);
    BOOST_CHECK_EQUAL(make_message(sset {}).types()[0], type_id_v<sset>);
    BOOST_CHECK_EQUAL(make_message(itup(1, 2, 3)).types()[0], type_id_v<itup>);

    /*
      BOOST_CHECK_EQUAL(make_message(1, 2).types(), (make_type_id_list<int,
      int>())); BOOST_CHECK_EQUAL(msg_as_string(1, 2, 3), "(1, 2, 3)");
      BOOST_CHECK_EQUAL(msg_as_string(ivec{1, 2, 3}), "([1, 2, 3])");
      BOOST_CHECK_EQUAL(msg_as_string(ivec{1, 2}, 3, 4, ivec{5, 6, 7}),
                      "([1, 2], 3, 4, [5, 6, 7])");
      auto msg = make_message(ivec{1, 2, 3});
      ACTOR_MESSAGE("s1: " << type_id_v<s1>);
      ACTOR_MESSAGE("ivec: " << type_id_v<ivec>);
      ACTOR_MESSAGE("msg.types: " << msg.types());
      ACTOR_MESSAGE("msg.types[int]: " << msg.types()[0]);
      ACTOR_MESSAGE("types #1: " << make_type_id_list<s1>());
      ACTOR_MESSAGE("types #2: " << make_type_id_list<ivec>());
      BOOST_CHECK_EQUAL(msg.get_as<ivec>(0), ivec({1, 2, 3}));
      */
}

BOOST_AUTO_TEST_CASE(strings_to_string) {
    using svec = vector<string>;
    auto msg1 = make_message("one", "two", "three");
    BOOST_CHECK_EQUAL(to_string(msg1), R"__(("one", "two", "three"))__");
    auto msg2 = make_message(svec {"one", "two", "three"});
    BOOST_CHECK_EQUAL(to_string(msg2), R"__((["one", "two", "three"]))__");
    auto msg3 = make_message(svec {"one", "two"}, "three", "four", svec {"five", "six", "seven"});
    ACTOR_CHECK(to_string(msg3) == R"__((["one", "two"], "three", "four", ["five", "six", "seven"]))__");
    auto msg4 = make_message(R"(this is a "test")");
    BOOST_CHECK_EQUAL(to_string(msg4), "(\"this is a \\\"test\\\"\")");
}

BOOST_AUTO_TEST_CASE(maps_to_string) {
    map<int, int> m1 {{1, 10}, {2, 20}, {3, 30}};
    auto msg1 = make_message(move(m1));
    BOOST_CHECK_EQUAL(to_string(msg1), "({1 = 10, 2 = 20, 3 = 30})");
}

BOOST_AUTO_TEST_CASE(tuples_to_string) {
    auto msg1 = make_message(make_tuple(1, 2, 3), 4, 5);
    BOOST_CHECK_EQUAL(to_string(msg1), "((1, 2, 3), 4, 5)");
    auto msg2 = make_message(make_tuple("one"s, int32_t {2}, uint32_t {3}), 4, true);
    BOOST_CHECK_EQUAL(to_string(msg2), "((\"one\", 2, 3), 4, true)");
}

BOOST_AUTO_TEST_CASE(arrays_to_string) {
    BOOST_CHECK_EQUAL(msg_as_string(s1 {}), "([10, 20, 30])");
    auto msg2 = make_message(s2 {});
    s2 tmp;
    tmp.value[0][1] = 100;
    BOOST_CHECK_EQUAL(to_string(msg2), "([[1, 10], [2, 20], [3, 30], [4, 40]])");
    BOOST_CHECK_EQUAL(msg_as_string(s3 {}), "([1, 2, 3, 4])");
}

ACTOR_TEST(match_elements exposes element types) {
    auto msg = make_message(put_atom_v, "foo", int64_t {123});
    ACTOR_CHECK((msg.match_element<put_atom>(0)));
    ACTOR_CHECK((msg.match_element<string>(1)));
    ACTOR_CHECK((msg.match_element<int64_t>(2)));
    ACTOR_CHECK((msg.match_elements<put_atom, string, int64_t>()));
}
