//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#include <nil/actor/group.hpp>

#include <nil/actor/message.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/group_manager.hpp>

namespace nil {
    namespace actor {

        group::group(abstract_group *ptr) : ptr_(ptr) {
            // nop
        }

        group::group(abstract_group *ptr, bool add_ref) : ptr_(ptr, add_ref) {
            // nop
        }

        group::group(const invalid_group_t &) : ptr_(nullptr) {
            // nop
        }

        group::group(abstract_group_ptr gptr) : ptr_(std::move(gptr)) {
            // nop
        }

        group &group::operator=(const invalid_group_t &) {
            ptr_.reset();
            return *this;
        }

        intptr_t group::compare(const abstract_group *lhs, const abstract_group *rhs) {
            return reinterpret_cast<intptr_t>(lhs) - reinterpret_cast<intptr_t>(rhs);
        }

        intptr_t group::compare(const group &other) const noexcept {
            return compare(ptr_.get(), other.ptr_.get());
        }

        namespace {

            template<class Serializer>
            auto save_group(Serializer &sink, group &x) {
                std::string mod_name;
                auto ptr = x.get();
                if (ptr == nullptr)
                    return sink(mod_name);
                mod_name = ptr->module().name();
                if (auto err = sink(mod_name))
                    return err;
                return ptr->save(sink);
            }

        }    // namespace

        error inspect(serializer &sink, group &x) {
            return save_group(sink, x);
        }

        error_code<sec> inspect(binary_serializer &sink, group &x) {
            return save_group(sink, x);
        }

        namespace {

            template<class Deserializer>
            typename Deserializer::result_type load_group(Deserializer &source, group &x) {
                std::string module_name;
                if (auto err = source(module_name))
                    return err;
                if (module_name.empty()) {
                    x = invalid_group;
                    return none;
                }
                if (source.context() == nullptr)
                    return sec::no_context;
                auto &sys = source.context()->system();
                auto mod = sys.groups().get_module(module_name);
                if (!mod)
                    return sec::no_such_group_module;
                return mod->load(source, x);
            }

        }    // namespace

        error inspect(deserializer &source, group &x) {
            return load_group(source, x);
        }

        error_code<sec> inspect(binary_deserializer &source, group &x) {
            return load_group(source, x);
        }

        std::string to_string(const group &x) {
            if (x == invalid_group)
                return "<invalid-group>";
            std::string result = x.get()->module().name();
            result += ":";
            result += x.get()->identifier();
            return result;
        }

    }    // namespace actor
}    // namespace nil
