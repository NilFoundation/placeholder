//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <nil/actor/config_value.hpp>

#include <ostream>

#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/expected.hpp>
#include <nil/actor/pec.hpp>

namespace nil {
    namespace actor {

        namespace {

            const char *type_names[] {
                "integer", "boolean", "real", "atom", "timespan", "uri", "string", "list", "dictionary",
            };

        }    // namespace

        // -- constructors, destructors, and assignment operators ----------------------

        config_value::~config_value() {
            // nop
        }

        // -- properties ---------------------------------------------------------------

        void config_value::convert_to_list() {
            if (holds_alternative<list>(data_))
                return;
            using std::swap;
            config_value tmp;
            swap(*this, tmp);
            data_ = std::vector<config_value> {std::move(tmp)};
        }

        config_value::list &config_value::as_list() {
            convert_to_list();
            return get<list>(*this);
        }

        config_value::dictionary &config_value::as_dictionary() {
            if (!holds_alternative<dictionary>(*this))
                *this = dictionary {};
            return get<dictionary>(*this);
        }

        void config_value::append(config_value x) {
            convert_to_list();
            get<list>(data_).emplace_back(std::move(x));
        }

        const char *config_value::type_name() const noexcept {
            return type_name_at_index(data_.index());
        }

        const char *config_value::type_name_at_index(size_t index) noexcept {
            return type_names[index];
        }

        bool operator<(const config_value &x, const config_value &y) {
            return x.get_data() < y.get_data();
        }

        bool operator==(const config_value &x, const config_value &y) {
            return x.get_data() == y.get_data();
        }

        std::string to_string(const config_value &x) {
            return deep_to_string(x.get_data());
        }

        std::ostream &operator<<(std::ostream &out, const config_value &x) {
            return out << to_string(x);
        }

    }    // namespace actor
}    // namespace nil
