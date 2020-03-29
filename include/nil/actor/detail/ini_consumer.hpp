//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <string>

#include <nil/actor/config_option_set.hpp>
#include <nil/actor/config_value.hpp>

#include <nil/actor/dictionary.hpp>
#include <nil/actor/settings.hpp>

namespace nil::actor::detail {

    class ini_consumer;
    class ini_list_consumer;
    class ini_map_consumer;

    class BOOST_SYMBOL_VISIBLE abstract_ini_consumer {
    public:
        // -- constructors, destructors, and assignment operators --------------------

        explicit abstract_ini_consumer(abstract_ini_consumer *parent = nullptr);

        abstract_ini_consumer(const abstract_ini_consumer &) = delete;

        abstract_ini_consumer &operator=(const abstract_ini_consumer &) = delete;

        virtual ~abstract_ini_consumer();

        // -- properties -------------------------------------------------------------

        virtual void value_impl(config_value &&x) = 0;

        template<class T>
        void value(T &&x) {
            value_impl(config_value {std::forward<T>(x)});
        }

        inline abstract_ini_consumer *parent() {
            return parent_;
        }

        ini_map_consumer begin_map();

        ini_list_consumer begin_list();

    protected:
        // -- member variables -------------------------------------------------------

        abstract_ini_consumer *parent_;
    };

    class BOOST_SYMBOL_VISIBLE ini_map_consumer : public abstract_ini_consumer {
    public:
        // -- member types -----------------------------------------------------------

        using super = abstract_ini_consumer;

        using map_type = config_value::dictionary;

        using iterator = map_type::iterator;

        // -- constructors, destructors, and assignment operators --------------------

        ini_map_consumer(abstract_ini_consumer *ptr);

        ini_map_consumer(ini_map_consumer &&other);

        ~ini_map_consumer() override;

        // -- properties -------------------------------------------------------------

        void end_map();

        void key(std::string name);

        void value_impl(config_value &&x) override;

    private:
        // -- member variables -------------------------------------------------------

        map_type xs_;
        iterator i_;
    };

    class BOOST_SYMBOL_VISIBLE ini_list_consumer : public abstract_ini_consumer {
    public:
        // -- member types -----------------------------------------------------------

        using super = abstract_ini_consumer;

        // -- constructors, destructors, and assignment operators --------------------

        ini_list_consumer(abstract_ini_consumer *ptr);

        ini_list_consumer(ini_list_consumer &&other);

        // -- properties -------------------------------------------------------------

        void end_list();

        void value_impl(config_value &&x) override;

    private:
        // -- member variables -------------------------------------------------------

        config_value::list xs_;
    };

    /// Consumes a single value from an INI parser.
    class BOOST_SYMBOL_VISIBLE ini_value_consumer : public abstract_ini_consumer {
    public:
        // -- member types -----------------------------------------------------------

        using super = abstract_ini_consumer;

        // -- constructors, destructors, and assignment operators --------------------

        explicit ini_value_consumer(abstract_ini_consumer *parent = nullptr);

        // -- properties -------------------------------------------------------------

        void value_impl(config_value &&x) override;

        // -- member variables -------------------------------------------------------

        config_value result;
    };

    /// Consumes a config category.
    class BOOST_SYMBOL_VISIBLE ini_category_consumer : public abstract_ini_consumer {
    public:
        // -- member types -----------------------------------------------------------

        using super = abstract_ini_consumer;

        // -- constructors, destructors, and assignment operators --------------------

        ini_category_consumer(ini_consumer *parent, std::string category);

        ini_category_consumer(ini_category_consumer &&);

        // -- properties -------------------------------------------------------------

        void end_map();

        void key(std::string name);

        void value_impl(config_value &&x) override;

    private:
        // -- properties -------------------------------------------------------------

        ini_consumer *dparent();

        // -- member variables -------------------------------------------------------

        std::string category_;
        config_value::dictionary xs_;
        std::string current_key;
    };

    /// Consumes a series of dictionaries forming a application configuration.
    class BOOST_SYMBOL_VISIBLE ini_consumer : public abstract_ini_consumer {
    public:
        // -- friends ----------------------------------------------------------------

        friend class ini_category_consumer;

        // -- member types -----------------------------------------------------------

        using super = abstract_ini_consumer;

        using config_map = dictionary<config_value::dictionary>;

        // -- constructors, destructors, and assignment operators --------------------

        ini_consumer(const config_option_set &options, settings &cfg);

        // -- properties -------------------------------------------------------------

        ini_category_consumer begin_map();

        void key(std::string name);

        void value_impl(config_value &&x) override;

    private:
        // -- member variables -------------------------------------------------------

        const config_option_set &options_;
        settings &cfg_;
        std::string current_key_;
        std::vector<error> warnings_;
    };

}    // namespace nil::actor::detail