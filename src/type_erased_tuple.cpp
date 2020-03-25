//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#include <nil/actor/type_erased_tuple.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/raise_error.hpp>

#include <nil/actor/detail/try_match.hpp>

namespace nil {
    namespace actor {

        type_erased_tuple::~type_erased_tuple() {
            // nop
        }

        error type_erased_tuple::load(deserializer &source) {
            for (size_t i = 0; i < size(); ++i)
                if (auto err = load(i, source))
                    return err;
            return none;
        }

        error_code<sec> type_erased_tuple::load(binary_deserializer &source) {
            for (size_t i = 0; i < size(); ++i)
                if (auto err = load(i, source))
                    return err;
            return none;
        }

        bool type_erased_tuple::shared() const noexcept {
            return false;
        }

        bool type_erased_tuple::empty() const {
            return size() == 0;
        }

        std::string type_erased_tuple::stringify() const {
            if (size() == 0)
                return "()";
            std::string result = "(";
            result += stringify(0);
            for (size_t i = 1; i < size(); ++i) {
                result += ", ";
                result += stringify(i);
            }
            result += ')';
            return result;
        }

        error type_erased_tuple::save(serializer &sink) const {
            for (size_t i = 0; i < size(); ++i) {
                auto e = save(i, sink);
                if (e)
                    return e;
            }
            return none;
        }

        error_code<sec> type_erased_tuple::save(binary_serializer &sink) const {
            for (size_t i = 0; i < size(); ++i)
                save(i, sink);
            return none;
        }

        bool type_erased_tuple::matches(size_t pos, uint16_t nr, const std::type_info *ptr) const noexcept {
            ACTOR_ASSERT(pos < size());
            auto tp = type(pos);
            if (tp.first != nr)
                return false;
            if (nr == 0)
                return ptr != nullptr ? strcmp(tp.second->name(), ptr->name()) == 0 : false;
            return true;
        }

        empty_type_erased_tuple::~empty_type_erased_tuple() {
            // nop
        }

        void *empty_type_erased_tuple::get_mutable(size_t) {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::get_mutable");
        }

        error empty_type_erased_tuple::load(size_t, deserializer &) {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::get_mutable");
        }

        error_code<sec> empty_type_erased_tuple::load(size_t, binary_deserializer &) {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::load");
        }

        size_t empty_type_erased_tuple::size() const noexcept {
            return 0;
        }

        uint32_t empty_type_erased_tuple::type_token() const noexcept {
            return make_type_token();
        }

        auto empty_type_erased_tuple::type(size_t) const noexcept -> rtti_pair {
            ACTOR_CRITICAL("empty_type_erased_tuple::type");
        }

        const void *empty_type_erased_tuple::get(size_t) const noexcept {
            ACTOR_CRITICAL("empty_type_erased_tuple::get");
        }

        std::string empty_type_erased_tuple::stringify(size_t) const {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::stringify");
        }

        type_erased_value_ptr empty_type_erased_tuple::copy(size_t) const {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::copy");
        }

        error empty_type_erased_tuple::save(size_t, serializer &) const {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::save");
        }

        error_code<sec> empty_type_erased_tuple::save(size_t, binary_serializer &) const {
            ACTOR_RAISE_ERROR("empty_type_erased_tuple::save");
        }
    }    // namespace actor
}    // namespace nil
