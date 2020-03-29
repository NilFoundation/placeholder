//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE serialization

#include "core-test.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
#include <locale>
#include <memory>
#include <new>
#include <set>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/byte_buffer.hpp>
#include <nil/actor/deserializer.hpp>
#include <nil/actor/detail/get_mac_addresses.hpp>
#include <nil/actor/detail/ieee_754.hpp>
#include <nil/actor/detail/int_list.hpp>
#include <nil/actor/detail/safe_equal.hpp>
#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_handler.hpp>
#include <nil/actor/proxy_registry.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/serializer.hpp>
#include <nil/actor/variant.hpp>

using namespace nil::actor;

const char *test_enum_strings[] = {
    "a",
    "b",
    "c",
};

std::string to_string(test_enum x) {
    return test_enum_strings[static_cast<uint32_t>(x)];
}

void test_empty_non_pod::foo() {
    // nop
}

test_empty_non_pod::~test_empty_non_pod() {
    // nop
}

namespace {

    struct fixture : test_coordinator_fixture<> {
        int32_t i32 = -345;
        int64_t i64 = -1234567890123456789ll;
        float f32 = 3.45f;
        double f64 = 54.3;
        timestamp ts = timestamp {timestamp::duration {1478715821 * 1000000000ll}};
        test_enum te = test_enum::b;
        std::string str = "Lorem ipsum dolor sit amet.";
        raw_struct rs;
        test_array ta {
            {0, 1, 2, 3},
            {{0, 1, 2, 3}, {4, 5, 6, 7}},
        };
        int ra[3] = {1, 2, 3};

        message msg;
        message recursive;

        template<class... Ts>
        byte_buffer serialize(const Ts &... xs) {
            byte_buffer buf;
            binary_serializer sink {sys, buf};
            if (auto err = sink(xs...))
                BOOST_FAIL("serialization failed: " << sys.render(err)
                                                  << ", data: " << deep_to_string(std::forward_as_tuple(xs...)));
            return buf;
        }

        template<class... Ts>
        void deserialize(const byte_buffer &buf, Ts &... xs) {
            binary_deserializer source {sys, buf};
            if (auto err = source(xs...))
                BOOST_FAIL("deserialization failed: " << sys.render(err));
        }

        // serializes `x` and then deserializes and returns the serialized value
        template<class T>
        T roundtrip(T x) {
            T result;
            deserialize(serialize(x), result);
            return result;
        }

        // converts `x` to a message, serialize it, then deserializes it, and
        // finally returns unboxed value
        template<class T>
        T msg_roundtrip(const T &x) {
            message result;
            auto tmp = make_message(x);
            deserialize(serialize(tmp), result);
            if (!result.match_elements<T>())
                BOOST_FAIL("expected: " << x << ", got: " << result);
            return result.get_as<T>(0);
        }

        fixture() {
            rs.str.assign(std::string(str.rbegin(), str.rend()));
            msg = make_message(i32, i64, ts, te, str, rs);
            config_value::dictionary dict;
            put(dict, "scheduler.policy", "none");
            put(dict, "scheduler.max-threads", 42);
            put(dict, "nodes.preload", make_config_value_list("sun", "venus", "mercury", "earth", "mars"));
            recursive = make_message(config_value {std::move(dict)});
        }
    };

    struct is_message {
        explicit is_message(message &msgref) : msg(msgref) {
            // nop
        }

        message &msg;

        template<class T, class... Ts>
        bool equal(T &&v, Ts &&... vs) {
            bool ok = false;
            // work around for gcc 4.8.4 bug
            auto tup = std::tie(v, vs...);
            message_handler impl {[&](T const &u, Ts const &... us) { ok = tup == std::tie(u, us...); }};
            impl(msg);
            return ok;
        }
    };

}    // namespace

#define CHECK_RT(val) BOOST_CHECK_EQUAL(val, roundtrip(val))

#define CHECK_MSG_RT(val) BOOST_CHECK_EQUAL(val, msg_roundtrip(val))

BOOST_FIXTURE_TEST_SUITE(serialization_tests, fixture)

BOOST_AUTO_TEST_CASE(ieee_754_conversion) {
    // check conversion of float
    float f1 = 3.1415925f;                 // float value
    auto p1 = nil::actor::detail::pack754(f1);    // packet value
    BOOST_CHECK_EQUAL(p1, static_cast<decltype(p1)>(0x40490FDA));
    auto u1 = nil::actor::detail::unpack754(p1);    // unpacked value
    BOOST_CHECK_EQUAL(f1, u1);
    // check conversion of double
    double f2 = 3.14159265358979311600;    // double value
    auto p2 = nil::actor::detail::pack754(f2);    // packet value
    BOOST_CHECK_EQUAL(p2, static_cast<decltype(p2)>(0x400921FB54442D18));
    auto u2 = nil::actor::detail::unpack754(p2);    // unpacked value
    BOOST_CHECK_EQUAL(f2, u2);
}

BOOST_AUTO_TEST_CASE(serializing_and_then_deserializing_produces_the_same_value) {
    CHECK_RT(i32);
    CHECK_RT(i64);
    CHECK_RT(f32);
    CHECK_RT(f64);
    CHECK_RT(ts);
    CHECK_RT(te);
    CHECK_RT(str);
    CHECK_RT(rs);
}

BOOST_AUTO_TEST_CASE(messages_serialize_and_deserialize_their_content) {
    CHECK_MSG_RT(i32);
    CHECK_MSG_RT(i64);
    CHECK_MSG_RT(f32);
    CHECK_MSG_RT(f64);
    CHECK_MSG_RT(ts);
    CHECK_MSG_RT(te);
    CHECK_MSG_RT(str);
    CHECK_MSG_RT(rs);
}

BOOST_AUTO_TEST_CASE(raw_arrays) {
    auto buf = serialize(ra);
    int x[3];
    deserialize(buf, x);
    for (auto i = 0; i < 3; ++i)
        BOOST_CHECK_EQUAL(ra[i], x[i]);
}

BOOST_AUTO_TEST_CASE(arrays) {
    auto buf = serialize(ta);
    test_array x;
    deserialize(buf, x);
    for (auto i = 0; i < 4; ++i)
        BOOST_CHECK_EQUAL(ta.value[i], x.value[i]);
    for (auto i = 0; i < 2; ++i)
        for (auto j = 0; j < 4; ++j)
            BOOST_CHECK_EQUAL(ta.value2[i][j], x.value2[i][j]);
}

BOOST_AUTO_TEST_CASE(empty_non_pods) {
    test_empty_non_pod x;
    auto buf = serialize(x);
    ACTOR_REQUIRE(buf.empty());
    deserialize(buf, x);
}

std::string hexstr(const std::vector<char> &buf) {
    using namespace std;
    ostringstream oss;
    oss << hex;
    oss.fill('0');
    for (auto &c : buf) {
        oss.width(2);
        oss << int {c};
    }
    return oss.str();
}

BOOST_AUTO_TEST_CASE(messages) {
    // serialize original message which uses tuple_vals internally and
    // deserialize into a message which uses type_erased_value pointers
    message x;
    auto buf1 = serialize(msg);
    deserialize(buf1, x);
    BOOST_CHECK_EQUAL(to_string(msg), to_string(x));
    ACTOR_CHECK(is_message(x).equal(i32, i64, ts, te, str, rs));
    // serialize fully dynamic message again (do another roundtrip)
    message y;
    auto buf2 = serialize(x);
    BOOST_CHECK_EQUAL(buf1, buf2);
    deserialize(buf2, y);
    BOOST_CHECK_EQUAL(to_string(msg), to_string(y));
    ACTOR_CHECK(is_message(y).equal(i32, i64, ts, te, str, rs));
    BOOST_CHECK_EQUAL(to_string(recursive), to_string(roundtrip(recursive)));
}

BOOST_AUTO_TEST_CASE(multiple_messages) {
    auto m = make_message(rs, te);
    auto buf = serialize(te, m, msg);
    test_enum t;
    message m1;
    message m2;
    deserialize(buf, t, m1, m2);
    BOOST_CHECK_EQUAL(std::make_tuple(t, to_string(m1), to_string(m2)),
                    std::make_tuple(te, to_string(m), to_string(msg)));
    ACTOR_CHECK(is_message(m1).equal(rs, te));
    ACTOR_CHECK(is_message(m2).equal(i32, i64, ts, te, str, rs));
}

BOOST_AUTO_TEST_CASE(long_sequences) {
    byte_buffer data;
    binary_serializer sink {nullptr, data};
    size_t n = std::numeric_limits<uint32_t>::max();
    sink.begin_sequence(n);
    sink.end_sequence();
    binary_deserializer source {nullptr, data};
    size_t m = 0;
    source.begin_sequence(m);
    source.end_sequence();
    BOOST_CHECK_EQUAL(n, m);
}

BOOST_AUTO_TEST_CASE(non_empty_vector) {
    ACTOR_MESSAGE("deserializing into a non-empty vector overrides any content");
    std::vector<int> foo {1, 2, 3};
    std::vector<int> bar {0};
    auto buf = serialize(foo);
    deserialize(buf, bar);
    BOOST_CHECK_EQUAL(foo, bar);
}

BOOST_AUTO_TEST_CASE(variant_with_tree_types) {
    ACTOR_MESSAGE("deserializing into a non-empty vector overrides any content");
    using test_variant = variant<int, double, std::string>;
    test_variant x {42};
    BOOST_CHECK_EQUAL(x, roundtrip(x));
    x = 12.34;
    BOOST_CHECK_EQUAL(x, roundtrip(x));
    x = std::string {"foobar"};
    BOOST_CHECK_EQUAL(x, roundtrip(x));
}

// -- our vector<bool> serialization packs into an uint64_t. Hence, the
// critical sizes to test are 0, 1, 63, 64, and 65.

BOOST_AUTO_TEST_CASE(bool_vector_size_0) {
    std::vector<bool> xs;
    BOOST_CHECK_EQUAL(deep_to_string(xs), "[]");
    BOOST_CHECK_EQUAL(xs, roundtrip(xs));
    BOOST_CHECK_EQUAL(xs, msg_roundtrip(xs));
}

BOOST_AUTO_TEST_CASE(bool_vector_size_1) {
    std::vector<bool> xs {true};
    BOOST_CHECK_EQUAL(deep_to_string(xs), "[true]");
    BOOST_CHECK_EQUAL(xs, roundtrip(xs));
    BOOST_CHECK_EQUAL(xs, msg_roundtrip(xs));
}

BOOST_AUTO_TEST_CASE(bool_vector_size_2) {
    std::vector<bool> xs {true, true};
    BOOST_CHECK_EQUAL(deep_to_string(xs), "[true, true]");
    BOOST_CHECK_EQUAL(xs, roundtrip(xs));
    BOOST_CHECK_EQUAL(xs, msg_roundtrip(xs));
}

BOOST_AUTO_TEST_CASE(bool_vector_size_63) {
    std::vector<bool> xs;
    for (int i = 0; i < 63; ++i)
        xs.push_back(i % 3 == 0);
    BOOST_CHECK_EQUAL(deep_to_string(xs),
                    "[true, false, false, true, false, false, true, false, false, true, false, "
                    "false, true, false, false, true, false, false, true, false, false, true, "
                    "false, false, true, false, false, true, false, false, true, false, false, "
                    "true, false, false, true, false, false, true, false, false, true, false, "
                    "false, true, false, false, true, false, false, true, false, false, true, "
                    "false, false, true, false, false, true, false, false]");
    BOOST_CHECK_EQUAL(xs, roundtrip(xs));
    BOOST_CHECK_EQUAL(xs, msg_roundtrip(xs));
}

BOOST_AUTO_TEST_CASE(bool_vector_size_64) {
    std::vector<bool> xs;
    for (int i = 0; i < 64; ++i)
        xs.push_back(i % 5 == 0);
    BOOST_CHECK_EQUAL(deep_to_string(xs),
                    "[true, false, false, false, false, true, false, false, "
                    "false, false, true, false, false, false, false, true, "
                    "false, false, false, false, true, false, false, false, "
                    "false, true, false, false, false, false, true, false, "
                    "false, false, false, true, false, false, false, false, "
                    "true, false, false, false, false, true, false, false, "
                    "false, false, true, false, false, false, false, true, "
                    "false, false, false, false, true, false, false, false]");
    BOOST_CHECK_EQUAL(xs, roundtrip(xs));
    BOOST_CHECK_EQUAL(xs, msg_roundtrip(xs));
}

BOOST_AUTO_TEST_CASE(bool_vector_size_65) {
    std::vector<bool> xs;
    for (int i = 0; i < 65; ++i)
        xs.push_back(!(i % 7 == 0));
    BOOST_CHECK_EQUAL(deep_to_string(xs),
                    "[false, true, true, true, true, true, true, false, true, true, true, "
                    "true, true, true, false, true, true, true, true, true, true, false, true, "
                    "true, true, true, true, true, false, true, true, true, true, true, true, "
                    "false, true, true, true, true, true, true, false, true, true, true, true, "
                    "true, true, false, true, true, true, true, true, true, false, true, true, "
                    "true, true, true, true, false, true]");
    BOOST_CHECK_EQUAL(xs, roundtrip(xs));
    BOOST_CHECK_EQUAL(xs, msg_roundtrip(xs));
}

BOOST_AUTO_TEST_SUITE_END()
