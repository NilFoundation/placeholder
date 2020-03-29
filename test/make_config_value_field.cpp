//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE make_config_value_field

#include <nil/actor/make_config_value_field.hpp>

#include "core-test.hpp"

#include <nil/actor/spawner_config.hpp>
#include <nil/actor/config_option_set.hpp>
#include <nil/actor/config_value_object_access.hpp>

using namespace nil::actor;

namespace {

    struct foobar {
        int foo = 0;
        std::string bar;

        foobar() = default;
        foobar(int foo, std::string bar) : foo(foo), bar(std::move(bar)) {
            // nop
        }
    };

    std::string to_string(const foobar &x) {
        return deep_to_string(std::forward_as_tuple(x.foo, x.bar));
    }

    bool operator==(const foobar &x, const foobar &y) {
        return x.foo == y.foo && x.bar == y.bar;
    }

    bool foo_valid(const int &x) {
        return x >= 0;
    }

    int get_foo_fun(foobar x) {
        return x.foo;
    }

    void set_foo_fun(foobar &x, const int &value) {
        x.foo = value;
    }

    struct get_foo_t {
        int operator()(const foobar &x) const noexcept {
            return x.foo;
        }
    };

    struct set_foo_t {
        int &operator()(foobar &x, int value) const noexcept {
            x.foo = value;
            return x.foo;
        }
    };

    struct foobar_trait {
        using object_type = foobar;

        static std::string type_name() {
            return "foobar";
        }

        static span<config_value_field<object_type> *> fields() {
            static auto singleton = make_config_value_field_storage(make_config_value_field("foo", &foobar::foo, 123),
                                                                    make_config_value_field("bar", &foobar::bar));
            return singleton.fields();
        }
    };

    struct foobar_foobar {
        foobar x;
        foobar y;
        foobar_foobar() = default;
        foobar_foobar(foobar x, foobar y) : x(x), y(y) {
            // nop
        }
    };

    std::string to_string(const foobar_foobar &x) {
        return deep_to_string(std::forward_as_tuple(x.x, x.y));
    }

    bool operator==(const foobar_foobar &x, const foobar_foobar &y) {
        return x.x == y.x && x.y == y.y;
    }

    struct foobar_foobar_trait {
        using object_type = foobar_foobar;

        static std::string type_name() {
            return "foobar-foobar";
        }

        static span<config_value_field<object_type> *> fields() {
            static auto singleton = make_config_value_field_storage(make_config_value_field("x", &foobar_foobar::x),
                                                                    make_config_value_field("y", &foobar_foobar::y));
            return singleton.fields();
        }
    };

    struct fixture {
        get_foo_t get_foo;

        set_foo_t set_foo;

        config_option_set opts;

        void test_foo_field(config_value_field<foobar> &foo_field) {
            foobar x;
            BOOST_CHECK_EQUAL(foo_field.name(), "foo");
            BOOST_REQUIRE(foo_field.has_default());
            BOOST_CHECK_EQUAL(foo_field.get(x), config_value(0));
            foo_field.set_default(x);
            BOOST_CHECK_EQUAL(foo_field.get(x), config_value(42));
            BOOST_CHECK(!foo_field.valid_input(config_value(1.)));
            BOOST_CHECK(!foo_field.valid_input(config_value(-1)));
            BOOST_CHECK(!foo_field.set(x, config_value(-1)));
            string_view input = "123";
            string_parser_state ps {input.begin(), input.end()};
            foo_field.parse_cli(ps, x);
            BOOST_CHECK_EQUAL(ps.code, pec::success);
            BOOST_CHECK_EQUAL(foo_field.get(x), config_value(123));
        }

        template<class T>
        expected<T> read(std::vector<std::string> args) {
            settings cfg;
            auto res = opts.parse(cfg, args);
            if (res.first != pec::success)
                return make_error(res.first, *res.second);
            auto x = get_if<T>(&cfg, "value");
            if (x == none)
                return sec::invalid_argument;
            return *x;
        }
    };

}    // namespace

namespace nil {
    namespace actor {

        template<>
        struct config_value_access<foobar> : config_value_object_access<foobar_trait> {};

        template<>
        struct config_value_access<foobar_foobar> : config_value_object_access<foobar_foobar_trait> {};

    }    // namespace actor
}    // namespace nil

BOOST_FIXTURE_TEST_SUITE(make_config_value_field_tests, fixture)

BOOST_AUTO_TEST_CASE(construction_from_pointer_to_member) {
    make_config_value_field("foo", &foobar::foo);
    make_config_value_field("foo", &foobar::foo, none);
    make_config_value_field("foo", &foobar::foo, none, nullptr);
    make_config_value_field("foo", &foobar::foo, 42);
    make_config_value_field("foo", &foobar::foo, 42, nullptr);
    make_config_value_field("foo", &foobar::foo, 42, foo_valid);
    make_config_value_field("foo", &foobar::foo, 42, [](const int &x) { return x != 0; });
}

BOOST_AUTO_TEST_CASE(pointer_to_member_access) {
    auto foo_field = make_config_value_field("foo", &foobar::foo, 42, foo_valid);
    test_foo_field(foo_field);
}

BOOST_AUTO_TEST_CASE(construction_from_getter_and_setter) {
    auto get_foo_lambda = [](const foobar &x) { return x.foo; };
    auto set_foo_lambda = [](foobar &x, int value) { x.foo = value; };
    make_config_value_field("foo", get_foo, set_foo);
    make_config_value_field("foo", get_foo_fun, set_foo);
    make_config_value_field("foo", get_foo_fun, set_foo_fun);
    make_config_value_field("foo", get_foo_lambda, set_foo_lambda);
}

BOOST_AUTO_TEST_CASE(getter_and_setter_access) {
    auto foo_field = make_config_value_field("foo", get_foo, set_foo, 42, foo_valid);
    test_foo_field(foo_field);
}

BOOST_AUTO_TEST_CASE(object access from dictionary - foobar) {
    settings x;
    put(x, "my-value.bar", "hello");
    BOOST_TEST_MESSAGE("without foo member");
    {
        BOOST_REQUIRE(holds_alternative<foobar>(x, "my-value"));
        BOOST_REQUIRE(get_if<foobar>(&x, "my-value") != nil::actor::none);
        auto fb = get<foobar>(x, "my-value");
        BOOST_CHECK_EQUAL(fb.foo, 123);
        BOOST_CHECK_EQUAL(fb.bar, "hello");
    }
    BOOST_TEST_MESSAGE("with foo member");
    put(x, "my-value.foo", 42);
    {
        BOOST_REQUIRE(holds_alternative<foobar>(x, "my-value"));
        BOOST_REQUIRE(get_if<foobar>(&x, "my-value") != nil::actor::none);
        auto fb = get<foobar>(x, "my-value");
        BOOST_CHECK_EQUAL(fb.foo, 42);
        BOOST_CHECK_EQUAL(fb.bar, "hello");
    }
}

BOOST_AUTO_TEST_CASE(object access from dictionary - foobar_foobar) {
    settings x;
    put(x, "my-value.x.foo", 1);
    put(x, "my-value.x.bar", "hello");
    put(x, "my-value.y.bar", "world");
    BOOST_REQUIRE(holds_alternative<foobar_foobar>(x, "my-value"));
    BOOST_REQUIRE(get_if<foobar_foobar>(&x, "my-value") != nil::actor::none);
    auto fbfb = get<foobar_foobar>(x, "my-value");
    BOOST_CHECK_EQUAL(fbfb.x.foo, 1);
    BOOST_CHECK_EQUAL(fbfb.x.bar, "hello");
    BOOST_CHECK_EQUAL(fbfb.y.foo, 123);
    BOOST_CHECK_EQUAL(fbfb.y.bar, "world");
}

BOOST_AUTO_TEST_CASE(object access from CLI arguments - foobar) {
    opts.add<foobar>("value,v", "some value");
    BOOST_CHECK_EQUAL(read<foobar>({"--value={foo = 1, bar = hello}"}), foobar(1, "hello"));
    BOOST_CHECK_EQUAL(read<foobar>({"-v{bar = \"hello\"}"}), foobar(123, "hello"));
    BOOST_CHECK_EQUAL(read<foobar>({"-v", "{foo = 1, bar =hello ,}"}), foobar(1, "hello"));
}

BOOST_AUTO_TEST_CASE(object access from CLI arguments - foobar_foobar) {
    using fbfb = foobar_foobar;
    opts.add<fbfb>("value,v", "some value");
    BOOST_CHECK_EQUAL(read<fbfb>({"-v{x={bar = hello},y={foo=1,bar=world!},}"}), fbfb({123, "hello"}, {1, "world!"}));
}

namespace {

    constexpr const char *config_text = R"__(
arg1 = {
  foo = 42
  bar = "Don't panic!"
}
arg2 = {
  x = {
    foo = 1
    bar = "hello"
  }
  y = {
    foo = 2
    bar = "world"
  }
}
)__";

    struct test_config : spawner_config {
        test_config() {
            opt_group {custom_options_, "global"}
                .add(fb, "arg1,1", "some foobar")
                .add(fbfb, "arg2,2", "somme foobar-foobar");
        }
        foobar fb;
        foobar_foobar fbfb;
    };

}    // namespace

BOOST_AUTO_TEST_CASE(object access from actor system config - file input) {
    test_config cfg;
    std::istringstream in {config_text};
    if (auto err = cfg.parse(0, nullptr, in))
        BOOST_FAIL("cfg.parse failed: " << cfg.render(err));
    BOOST_CHECK_EQUAL(cfg.fb.foo, 42);
    BOOST_CHECK_EQUAL(cfg.fb.bar, "Don't panic!");
    BOOST_CHECK_EQUAL(cfg.fbfb.x.foo, 1);
    BOOST_CHECK_EQUAL(cfg.fbfb.y.foo, 2);
    BOOST_CHECK_EQUAL(cfg.fbfb.x.bar, "hello");
    BOOST_CHECK_EQUAL(cfg.fbfb.y.bar, "world");
}

BOOST_AUTO_TEST_CASE(object access from actor system config - file input and arguments) {
    std::vector<std::string> args {
        "-2",
        "{y = {bar = CAF, foo = 20}, x = {foo = 10, bar = hello}}",
    };
    test_config cfg;
    std::istringstream in {config_text};
    if (auto err = cfg.parse(std::move(args), in))
        BOOST_FAIL("cfg.parse failed: " << cfg.render(err));
    BOOST_CHECK_EQUAL(cfg.fb.foo, 42);
    BOOST_CHECK_EQUAL(cfg.fb.bar, "Don't panic!");
    BOOST_CHECK_EQUAL(cfg.fbfb.x.foo, 10);
    BOOST_CHECK_EQUAL(cfg.fbfb.y.foo, 20);
    BOOST_CHECK_EQUAL(cfg.fbfb.x.bar, "hello");
    BOOST_CHECK_EQUAL(cfg.fbfb.y.bar, "CAF");
}

BOOST_AUTO_TEST_SUITE_END()
