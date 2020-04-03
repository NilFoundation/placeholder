//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/tracing_data.hpp>

#include <cstdint>

#include <nil/actor/spawner.hpp>
#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/deserializer.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/sec.hpp>
#include <nil/actor/serializer.hpp>
#include <nil/actor/tracing_data_factory.hpp>

namespace nil {
    namespace actor {

        tracing_data::~tracing_data() {
            // nop
        }

        namespace {

            template<class Serializer>
            auto inspect_impl(Serializer &sink, const tracing_data_ptr &x) {
                if (x == nullptr) {
                    uint8_t dummy = 0;
                    return sink(dummy);
                }
                uint8_t dummy = 1;
                if (auto err = sink(dummy))
                    return err;
                return x->serialize(sink);
            }

            template<class Deserializer>
            typename Deserializer::result_type inspect_impl(Deserializer &source, tracing_data_ptr &x) {
                uint8_t dummy = 0;
                if (auto err = source(dummy))
                    return err;
                if (dummy == 0) {
                    x.reset();
                    return {};
                }
                auto ctx = source.context();
                if (ctx == nullptr)
                    return sec::no_context;
                auto tc = ctx->system().tracing_context();
                if (tc == nullptr)
                    return sec::no_tracing_context;
                return tc->deserialize(source, x);
            }

        }    // namespace

        error inspect(serializer &sink, const tracing_data_ptr &x) {
            return inspect_impl(sink, x);
        }

        error_code<sec> inspect(binary_serializer &sink, const tracing_data_ptr &x) {
            return inspect_impl(sink, x);
        }

        error inspect(deserializer &source, tracing_data_ptr &x) {
            return inspect_impl(source, x);
        }

        error_code<sec> inspect(binary_deserializer &source, tracing_data_ptr &x) {
            return inspect_impl(source, x);
        }

    }    // namespace actor
}    // namespace nil
