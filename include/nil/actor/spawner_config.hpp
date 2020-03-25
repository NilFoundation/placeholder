//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>
#include <string>
#include <memory>
#include <typeindex>
#include <functional>
#include <type_traits>
#include <unordered_map>

#include <nil/actor/defaults.hpp>
#include <nil/actor/actor_factory.hpp>
#include <nil/actor/config_value.hpp>
#include <nil/actor/dictionary.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/is_typed_actor.hpp>
#include <nil/actor/named_actor_config.hpp>
#include <nil/actor/stream.hpp>
#include <nil/actor/thread_hook.hpp>
#include <nil/actor/type_erased_value.hpp>

#include <nil/actor/detail/safe_equal.hpp>
#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        /// Configures an `spawner` on startup.
        class spawner_config {
        public:
            // -- member types -----------------------------------------------------------

            using hook_factory = std::function<io::hook *(spawner &)>;

            using hook_factory_vector = std::vector<hook_factory>;

            using thread_hooks = std::vector<std::unique_ptr<thread_hook>>;

            using module_factory = std::function<spawner::module *(spawner &)>;

            using module_factory_vector = std::vector<module_factory>;

            using value_factory = std::function<type_erased_value_ptr()>;

            using value_factory_string_map = std::unordered_map<std::string, value_factory>;

            using value_factory_rtti_map = std::unordered_map<std::type_index, value_factory>;

            using actor_factory_map = std::unordered_map<std::string, actor_factory>;

            using portable_name_map = std::unordered_map<std::type_index, std::string>;

            using error_renderer = std::function<std::string(uint8_t, atom_value, const message &)>;

            using error_renderer_map = std::unordered_map<atom_value, error_renderer>;

            using group_module_factory = std::function<group_module *()>;

            using group_module_factory_vector = std::vector<group_module_factory>;

            using string_list = std::vector<std::string>;

            using named_actor_config_map = std::unordered_map<std::string, named_actor_config>;

            // -- constructors, destructors, and assignment operators --------------------

            spawner_config();

            spawner_config(spawner_config &&) = default;

            spawner_config(const spawner_config &) = delete;
            spawner_config &operator=(const spawner_config &) = delete;

            // -- properties -------------------------------------------------------------

            /// @private
            settings content;

            // -- modifiers --------------------------------------------------------------

            /// Allows other nodes to spawn actors created by `fun`
            /// dynamically by using `name` as identifier.
            /// @experimental
            spawner_config &add_actor_factory(std::string name, actor_factory fun);

            /// Allows other nodes to spawn actors of type `T`
            /// dynamically by using `name` as identifier.
            /// @experimental
            template<class T, class... Ts>
            spawner_config &add_actor_type(std::string name) {
                using handle = typename infer_handle_from_class<T>::type;
                if (!std::is_same<handle, actor>::value)
                    add_message_type<handle>(name);
                return add_actor_factory(std::move(name), make_actor_factory<T, Ts...>());
            }

            /// Allows other nodes to spawn actors implemented by function `f`
            /// dynamically by using `name` as identifier.
            /// @experimental
            template<class F>
            spawner_config &add_actor_type(std::string name, F f) {
                using handle = typename infer_handle_from_fun<F>::type;
                if (!std::is_same<handle, actor>::value)
                    add_message_type<handle>(name);
                return add_actor_factory(std::move(name), make_actor_factory(std::move(f)));
            }

            /// Adds message type `T` with runtime type info `name`.
            template<class T>
            spawner_config &add_message_type(std::string name) {
                static_assert(std::is_empty<T>::value || std::is_same<T, actor>::value    // silence add_actor_type err
                                  || is_typed_actor<T>::value ||
                                  (std::is_default_constructible<T>::value && std::is_copy_constructible<T>::value),
                              "T must provide default and copy constructors");
                std::string stream_name = "stream<";
                stream_name += name;
                stream_name += ">";
                add_message_type_impl<stream<T>>(std::move(stream_name));
                std::string vec_name = "std::vector<";
                vec_name += name;
                vec_name += ">";
                add_message_type_impl<std::vector<T>>(std::move(vec_name));
                add_message_type_impl<T>(std::move(name));
                return *this;
            }

            /// Enables the actor system to convert errors of this error category
            /// to human-readable strings via `renderer`.
            spawner_config &add_error_category(atom_value x, error_renderer y);

            /// Enables the actor system to convert errors of this error category
            /// to human-readable strings via `to_string(T)`.
            template<class T>
            spawner_config &add_error_category(atom_value category) {
                auto f = [=](uint8_t val, const std::string &ctx) -> std::string {
                    std::string result;
                    result = to_string(category);
                    result += ": ";
                    result += to_string(static_cast<T>(val));
                    if (!ctx.empty()) {
                        result += " (";
                        result += ctx;
                        result += ")";
                    }
                    return result;
                };
                return add_error_category(category, f);
            }

            /// Loads module `T` with optional template parameters `Ts...`.
            template<class T, class... Ts>
            spawner_config &load() {
                module_factories.push_back([](spawner &sys) -> spawner::module * {
                    return T::make(sys, detail::type_list<Ts...> {});
                });
                return *this;
            }

            /// Adds a factory for a new hook type to the middleman (if loaded).
            template<class Factory>
            spawner_config &add_hook_factory(Factory f) {
                hook_factories.push_back(f);
                return *this;
            }

            /// Adds a hook type to the middleman (if loaded).
            template<class Hook>
            spawner_config &add_hook_type() {
                return add_hook_factory([](spawner &sys) -> Hook * { return new Hook(sys); });
            }

            /// Adds a hook type to the scheduler.
            template<class Hook, class... Ts>
            spawner_config &add_thread_hook(Ts &&... ts) {
                std::unique_ptr<thread_hook> hook {new Hook(std::forward<Ts>(ts)...)};
                thread_hooks_.emplace_back(std::move(hook));
                return *this;
            }

            // -- actor-run parameters -----------------------------------------------------

            /// Stores whether this node was started in slave mode.
            bool slave_mode;

            /// Name of this node when started in slave mode.
            std::string slave_name;

            /// Credentials for connecting to the bootstrap node.
            std::string bootstrap_node;

            // -- stream parameters ------------------------------------------------------

            /// processing time per batch
            timespan stream_desired_batch_complexity = defaults::stream::desired_batch_complexity;

            /// maximum delay for partial batches
            timespan stream_max_batch_delay = defaults::stream::max_batch_delay;

            /// time between emitting credit
            timespan stream_credit_round_interval = defaults::stream::credit_round_interval;

            /// @private
            timespan stream_tick_duration() const noexcept;

            // -- scheduler parameters ------------------------------------------------------

            /// 'stealing' (default) or 'sharing'
            atom_value scheduler_policy = defaults::scheduler::policy;

            /// maximum number of worker threads
            std::size_t scheduler_max_threads = defaults::scheduler::max_threads;

            /// amount of messages actors can consume per run
            std::size_t scheduler_max_throughput = defaults::scheduler::max_throughput;

            /// enables profiler output
            bool scheduler_enable_profiling = false;

            /// data collection rate
            timespan scheduler_profiling_resolution = defaults::scheduler::profiling_resolution;

            /// output file for the profiler
            std::string scheduler_profiling_output_file;

            // -- work stealing parameters ------------------------------------------------------

            /// amount of aggressive steal attempts
            std::size_t work_stealing_aggressive_poll_attempts = defaults::work_stealing::aggressive_poll_attempts;

            /// frequency of aggressive steal attempts
            std::size_t work_stealing_aggressive_steal_interval = defaults::work_stealing::aggressive_steal_interval;

            /// amount of moderate steal attempts
            std::size_t work_stealing_moderate_poll_attempts = defaults::work_stealing::moderate_poll_attempts;

            /// frequency of moderate steal attempts
            std::size_t work_stealing_moderate_steal_interval = defaults::work_stealing::moderate_steal_interval;

            /// sleep duration between moderate steal attempts
            timespan work_stealing_moderate_sleep_duration = defaults::work_stealing::moderate_sleep_duration;

            /// frequency of relaxed steal attempts
            std::size_t work_stealing_relaxed_steal_interval = defaults::work_stealing::relaxed_steal_interval;

            /// sleep duration between relaxed steal attempts
            timespan work_stealing_relaxed_sleep_duration = defaults::work_stealing::relaxed_sleep_duration;

            // -- logger parameters ------------------------------------------------------

            /// default verbosity for file and console
            atom_value logger_verbosity = defaults::logger::console_verbosity;

            /// filesystem path of the log file
            std::string logger_file_name = defaults::logger::file_name;

            /// line format for individual log file entires
            std::string logger_file_format = defaults::logger::file_format;

            /// file output verbosity
            atom_value logger_file_verbosity = defaults::logger::file_verbosity;

            /// std::clog output: none, colored, or uncolored
            atom_value logger_console = defaults::logger::console;

            /// line format for printed log entires
            std::string logger_console_format = defaults::logger::console_format;

            /// console output verbosity
            atom_value logger_console_verbosity = defaults::logger::console_verbosity;

            /// excluded components for logging
            std::vector<atom_value> logger_component_blacklist;

            // -- middleman parameters ------------------------------------------------------

            /// either 'default' or 'asio' (if available)
            atom_value middleman_network_backend = defaults::middleman::network_backend;

            /// valid application identifiers of this node
            std::vector<std::string> middleman_app_identifiers = defaults::middleman::app_identifiers;

            /// enables automatic connection management
            bool middleman_enable_automatic_connections;

            /// max. number of consecutive reads per broker
            std::size_t middleman_max_consecutive_reads = defaults::middleman::max_consecutive_reads;

            /// interval of heartbeat messages
            timespan middleman_heartbeat_interval = timespan(defaults::middleman::heartbeat_interval);

            /// schedule utility actors instead of dedicating threads
            bool middleman_attach_utility_actors;

            /// disables background activity of the multiplexer
            bool middleman_manual_multiplexing;

            /// number of deserialization workers
            std::size_t middleman_workers = defaults::middleman::workers;

            // -- OpenCL parameters ------------------------------------------------------

            /// whitelist for OpenCL devices
            std::string opencl_device_ids;

            // -- OpenSSL parameters -----------------------------------------------------

            /// path to the PEM-formatted certificate file
            std::string openssl_certificate;

            /// path to the private key file for this node
            std::string openssl_key;

            /// passphrase to decrypt the private key
            std::string openssl_passphrase;

            /// path to an OpenSSL-style directory of trusted certificates
            std::string openssl_capath;

            /// path to a file of concatenated PEM-formatted certificates
            std::string openssl_cafile;

            // -- factories --------------------------------------------------------------

            value_factory_string_map value_factories_by_name;
            value_factory_rtti_map value_factories_by_rtti;
            actor_factory_map actor_factories;
            module_factory_vector module_factories;
            hook_factory_vector hook_factories;
            group_module_factory_vector group_module_factories;

            // -- hooks ------------------------------------------------------------------

            thread_hooks thread_hooks_;

            // -- run-time type information ----------------------------------------------

            portable_name_map type_names_by_rtti;

            // -- rendering of user-defined types ----------------------------------------

            error_renderer_map error_renderers;

            // -- utility for actor-run ----------------------------------------------------

            // Config parameter for individual actor types.
            named_actor_config_map named_actor_configs;

            int (*slave_mode_fun)(spawner &, const spawner_config &);

            // -- default error rendering functions --------------------------------------

            static std::string render(const error &err);

            static std::string render_sec(uint8_t, atom_value, const message &);

            static std::string render_exit_reason(uint8_t, atom_value, const message &);

            static std::string render_pec(uint8_t, atom_value, const message &);

            // -- config file parsing ----------------------------------------------------

        private:
            template<class T>
            void add_message_type_impl(std::string name) {
                type_names_by_rtti.emplace(std::type_index(typeid(T)), name);
                value_factories_by_name.emplace(std::move(name), &make_type_erased_value<T>);
                value_factories_by_rtti.emplace(std::type_index(typeid(T)), &make_type_erased_value<T>);
            }
        };

        /// Returns all user-provided configuration parameters.
        const settings &content(const spawner_config &cfg);
    }    // namespace actor
}    // namespace nil