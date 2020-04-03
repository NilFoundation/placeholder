//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/error.hpp>

#include <nil/actor/spawner_config.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/deserializer.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/serializer.hpp>

namespace nil {
    namespace actor {

        // -- nested classes -----------------------------------------------------------

        struct error::data {
            uint8_t code;
            uint8_t category;
            message context;
        };

        // -- constructors, destructors, and assignment operators ----------------------

        error::error() noexcept : data_(nullptr) {
            // nop
        }

        error::error(none_t) noexcept : data_(nullptr) {
            // nop
        }

        error::error(error &&x) noexcept : data_(x.data_) {
            if (data_ != nullptr)
                x.data_ = nullptr;
        }

        error &error::operator=(error &&x) noexcept {
            if (this != &x)
                std::swap(data_, x.data_);
            return *this;
        }

        error::error(const error &x) : data_(x ? new data(*x.data_) : nullptr) {
            // nop
        }

        error &error::operator=(const error &x) {
            if (this == &x)
                return *this;
            if (x) {
                if (data_ == nullptr)
                    data_ = new data(*x.data_);
                else
                    *data_ = *x.data_;
            } else {
                clear();
            }
            return *this;
        }

        error::error(uint8_t x, uint8_t y) : data_(x != 0 ? new data {x, y, message {}} : nullptr) {
            // nop
        }

        error::error(uint8_t x, uint8_t y, message z) : data_(x != 0 ? new data {x, y, std::move(z)} : nullptr) {
            // nop
        }

        error::~error() {
            delete data_;
        }

        // -- observers ----------------------------------------------------------------

        uint8_t error::code() const noexcept {
            ACTOR_ASSERT(data_ != nullptr);
            return data_->code;
        }

        uint8_t error::category() const noexcept {
            ACTOR_ASSERT(data_ != nullptr);
            return data_->category;
        }

        const message &error::context() const noexcept {
            ACTOR_ASSERT(data_ != nullptr);
            return data_->context;
        }

        int error::compare(const error &x) const noexcept {
            uint8_t x_code;
            uint8_t x_category;
            if (x) {
                x_code = x.data_->code;
                x_category = x.data_->category;
            } else {
                x_code = 0;
                x_category = 0;
            }
            return compare(x_code, x_category);
        }

        int error::compare(uint8_t x, uint8_t y) const noexcept {
            uint8_t mx;
            uint8_t my;
            if (data_ != nullptr) {
                mx = data_->code;
                my = data_->category;
            } else {
                mx = 0;
                my = 0;
            }
            // all errors with default value are considered no error -> equal
            if (mx == x && x == 0)
                return 0;
            if (my < y)
                return -1;
            if (my > y)
                return 1;
            return static_cast<int>(mx) - x;
        }

        // -- modifiers --------------------------------------------------------------

        message &error::context() noexcept {
            ACTOR_ASSERT(data_ != nullptr);
            return data_->context;
        }

        void error::clear() noexcept {
            if (data_ != nullptr) {
                delete data_;
                data_ = nullptr;
            }
        }

        // -- inspection support -----------------------------------------------------

        uint8_t &error::code_ref() noexcept {
            ACTOR_ASSERT(data_ != nullptr);
            return data_->code;
        }

        uint8_t &error::category_ref() noexcept {
            ACTOR_ASSERT(data_ != nullptr);
            return data_->category;
        }

        void error::init() {
            if (data_ == nullptr)
                data_ = new data;
        }

        std::string to_string(const error &x) {
            return spawner_config::render(x);
        }

    }    // namespace actor
}    // namespace nil
