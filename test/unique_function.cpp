//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.unique_function

#include <nil/actor/detail/unique_function.hpp>

#include <nil/actor/test/dsl.hpp>

namespace {

    using int_fun = nil::actor::detail::unique_function<int()>;

    int fourty_two() {
        return 42;
    }

    class instance_counting_wrapper final : public int_fun::wrapper {
    public:
        instance_counting_wrapper(size_t *instance_counter) : instance_counter_(instance_counter) {
            *instance_counter_ += 1;
        }

        ~instance_counting_wrapper() {
            *instance_counter_ -= 1;
        }

        int operator()() final {
            return 42;
        }

    private:
        size_t *instance_counter_;
    };

}    // namespace

#define CHECK_VALID(f)          \
    BOOST_CHECK(!f.is_nullptr()); \
    BOOST_CHECK(f);               \
    BOOST_CHECK(f != nullptr);    \
    BOOST_CHECK(nullptr != f);    \
    BOOST_CHECK(!(f == nullptr)); \
    BOOST_CHECK(!(nullptr == f)); \
    BOOST_CHECK(f() == 42)

#define CHECK_INVALID(f)        \
    BOOST_CHECK(f.is_nullptr());  \
    BOOST_CHECK(!f);              \
    BOOST_CHECK(f == nullptr);    \
    BOOST_CHECK(nullptr == f);    \
    BOOST_CHECK(!(f != nullptr)); \
    BOOST_CHECK(!(nullptr != f)); \
    BOOST_CHECK(!f.holds_wrapper())

BOOST_AUTO_TEST_CASE(default_construction) {
    int_fun f;
    CHECK_INVALID(f);
}

BOOST_AUTO_TEST_CASE(raw_function_pointer_construction) {
    int_fun f {fourty_two};
    CHECK_VALID(f);
}

BOOST_AUTO_TEST_CASE(stateless_lambda_construction) {
    int_fun f {[] { return 42; }};
    CHECK_VALID(f);
    BOOST_CHECK(!f.holds_wrapper());
}

BOOST_AUTO_TEST_CASE(stateful_lambda_construction) {
    int i = 42;
    int_fun f {[=] { return i; }};
    CHECK_VALID(f);
    BOOST_CHECK(f.holds_wrapper());
}

BOOST_AUTO_TEST_CASE(custom_wrapper_construction) {
    size_t instances = 0;
    {    // lifetime scope of our counting wrapper
        int_fun f {new instance_counting_wrapper(&instances)};
        CHECK_VALID(f);
        BOOST_CHECK(f.holds_wrapper());
        BOOST_CHECK(instances == 1);
    }
    BOOST_CHECK(instances == 0);
}

BOOST_AUTO_TEST_CASE(function_move_construction) {
    int_fun f {fourty_two};
    int_fun g {std::move(f)};
    CHECK_INVALID(f);
    CHECK_VALID(g);
    BOOST_CHECK(!g.holds_wrapper());
}

BOOST_AUTO_TEST_CASE(stateful_lambda_move_construction) {
    int i = 42;
    int_fun f {[=] { return i; }};
    int_fun g {std::move(f)};
    CHECK_INVALID(f);
    CHECK_VALID(g);
    BOOST_CHECK(g.holds_wrapper());
}

BOOST_AUTO_TEST_CASE(custom_wrapper_move_construction) {
    size_t instances = 0;
    {    // lifetime scope of our counting wrapper
        int_fun f {new instance_counting_wrapper(&instances)};
        int_fun g {std::move(f)};
        CHECK_INVALID(f);
        CHECK_VALID(g);
        BOOST_CHECK(g.holds_wrapper());
        BOOST_CHECK(instances == 1);
    }
    BOOST_CHECK(instances == 0);
}

BOOST_AUTO_TEST_CASE(function_assign) {
    size_t instances = 0;
    int_fun f;
    int_fun g {fourty_two};
    int_fun h {new instance_counting_wrapper(&instances)};
    BOOST_CHECK(instances == 1);
    CHECK_INVALID(f);
    CHECK_VALID(g);
    CHECK_VALID(h);
    f = fourty_two;
    g = fourty_two;
    h = fourty_two;
    BOOST_CHECK(instances == 0);
    CHECK_VALID(f);
    CHECK_VALID(g);
    CHECK_VALID(h);
}

BOOST_AUTO_TEST_CASE(move_assign) {
    size_t instances = 0;
    int_fun f;
    int_fun g {fourty_two};
    int_fun h {new instance_counting_wrapper(&instances)};
    BOOST_CHECK(instances == 1);
    CHECK_INVALID(f);
    CHECK_VALID(g);
    CHECK_VALID(h);
    g = std::move(h);
    BOOST_CHECK(instances == 1);
    CHECK_INVALID(f);
    CHECK_VALID(g);
    CHECK_INVALID(h);
    f = std::move(g);
    BOOST_CHECK(instances == 1);
    CHECK_VALID(f);
    CHECK_INVALID(g);
    CHECK_INVALID(h);
    f = int_fun {};
    BOOST_CHECK(instances == 0);
    CHECK_INVALID(f);
    CHECK_INVALID(g);
    CHECK_INVALID(h);
}
