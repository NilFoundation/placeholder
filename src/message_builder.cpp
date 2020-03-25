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

#include <nil/actor/message_builder.hpp>

#include <vector>

#include <nil/actor/detail/dynamic_message_data.hpp>
#include <nil/actor/make_copy_on_write.hpp>
#include <nil/actor/message_handler.hpp>

namespace nil {
    namespace actor {

        message_builder::message_builder() {
            init();
        }

        message_builder::~message_builder() {
            // nop
        }

        void message_builder::init() {
            // this should really be done by delegating
            // constructors, but we want to support
            // some compilers without that feature...
            data_ = make_copy_on_write<detail::dynamic_message_data>();
        }

        void message_builder::clear() {
            if (data_->unique())
                data_.unshared().clear();
            else
                init();
        }

        size_t message_builder::size() const {
            return data_->size();
        }

        bool message_builder::empty() const {
            return size() == 0;
        }

        message_builder &message_builder::emplace(type_erased_value_ptr x) {
            data_.unshared().append(std::move(x));
            return *this;
        }

        message message_builder::to_message() const {
            return message {data_};
        }

        message message_builder::move_to_message() {
            return message {std::move(data_)};
        }

        optional<message> message_builder::apply(message_handler handler) {
            // Avoid detaching of data_ by moving the data to a message object,
            // calling message::apply and moving the data back.
            auto msg = move_to_message();
            auto res = msg.apply(std::move(handler));
            data_.reset(dynamic_cast<detail::dynamic_message_data *>(msg.vals().detach()), false);
            return res;
        }

    }    // namespace actor
}    // namespace nil
