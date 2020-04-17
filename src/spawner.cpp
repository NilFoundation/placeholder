//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <memory>
#include <nil/actor/spawner.hpp>

#include <unordered_set>

#include <nil/actor/actor.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/defaults.hpp>
#include <nil/actor/detail/meta_object.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/policy/work_sharing.hpp>
#include <nil/actor/policy/work_stealing.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/scheduler/abstract_coordinator.hpp>
#include <nil/actor/scheduler/coordinator.hpp>
#include <nil/actor/scheduler/test_coordinator.hpp>
#include <nil/actor/send.hpp>
#include <nil/actor/stateful_actor.hpp>
#include <nil/actor/to_string.hpp>

namespace nil::actor {

    namespace {

        struct kvstate {
            using key_type = std::string;
            using mapped_type = message;
            using subscriber_set = std::unordered_set<strong_actor_ptr>;
            using topic_set = std::unordered_set<std::string>;
            std::unordered_map<key_type, std::pair<mapped_type, subscriber_set>> data;
            std::unordered_map<strong_actor_ptr, topic_set> subscribers;
            static const char *name;
        };

        const char *kvstate::name = "config_server";

        behavior config_serv_impl(stateful_actor<kvstate> *self) {
            ACTOR_LOG_TRACE("");
            std::string wildcard = "*";
            auto unsubscribe_all = [=](actor subscriber) {
                auto &subscribers = self->state.subscribers;
                auto ptr = actor_cast<strong_actor_ptr>(subscriber);
                auto i = subscribers.find(ptr);
                if (i == subscribers.end())
                    return;
                for (const auto &key : i->second)
                    self->state.data[key].second.erase(ptr);
                subscribers.erase(i);
            };
            self->set_down_handler([=](down_msg &dm) {
                ACTOR_LOG_TRACE(ACTOR_ARG(dm));
                auto ptr = actor_cast<strong_actor_ptr>(dm.source);
                if (ptr)
                    unsubscribe_all(actor_cast<actor>(std::move(ptr)));
            });
            return {
                // set a key/value pair
                [=](put_atom, const std::string &key, message &msg) {
                    ACTOR_LOG_TRACE(ACTOR_ARG(key) << ACTOR_ARG(msg));
                    if (key == "*")
                        return;
                    auto &vp = self->state.data[key];
                    vp.first = std::move(msg);
                    for (const auto &subscriber_ptr : vp.second) {
                        // we never put a nullptr in our map
                        auto subscriber = actor_cast<actor>(subscriber_ptr);
                        if (subscriber != self->current_sender())
                            self->send(subscriber, update_atom_v, key, vp.first);
                    }
                    // also iterate all subscribers for '*'
                    for (const auto &subscriber : self->state.data[wildcard].second)
                        if (subscriber != self->current_sender())
                            self->send(actor_cast<actor>(subscriber), update_atom_v, key, vp.first);
                },
                // get a key/value pair
                [=](get_atom, std::string &key) -> message {
                    ACTOR_LOG_TRACE(ACTOR_ARG(key));
                    if (key == wildcard) {
                        std::vector<std::pair<std::string, message>> msgs;
                        for (auto &kvp : self->state.data)
                            if (kvp.first != "*")
                                msgs.emplace_back(kvp.first, kvp.second.first);
                        return make_message(std::move(msgs));
                    }
                    auto i = self->state.data.find(key);
                    return make_message(std::move(key), i != self->state.data.end() ? i->second.first : make_message());
                },
                // subscribe to a key
                [=](subscribe_atom, const std::string &key) {
                    auto subscriber = actor_cast<strong_actor_ptr>(self->current_sender());
                    ACTOR_LOG_TRACE(ACTOR_ARG(key) << ACTOR_ARG(subscriber));
                    if (!subscriber)
                        return;
                    self->state.data[key].second.insert(subscriber);
                    auto &subscribers = self->state.subscribers;
                    auto i = subscribers.find(subscriber);
                    if (i != subscribers.end()) {
                        i->second.insert(key);
                    } else {
                        self->monitor(subscriber);
                        subscribers.emplace(subscriber, kvstate::topic_set {key});
                    }
                },
                // unsubscribe from a key
                [=](unsubscribe_atom, const std::string &key) {
                    auto subscriber = actor_cast<strong_actor_ptr>(self->current_sender());
                    if (!subscriber)
                        return;
                    ACTOR_LOG_TRACE(ACTOR_ARG(key) << ACTOR_ARG(subscriber));
                    if (key == wildcard) {
                        unsubscribe_all(actor_cast<actor>(std::move(subscriber)));
                        return;
                    }
                    self->state.subscribers[subscriber].erase(key);
                    self->state.data[key].second.erase(subscriber);
                },
                // get a 'named' actor from local registry
                [=](get_atom, const std::string &name) { return self->home_system().registry().get(name); },
            };
        }

        // -- spawn server -------------------------------------------------------------

        // A spawn server allows users to spawn actors dynamically with a name and a
        // message containing the data for initialization. By accessing the spawn server
        // on another node, users can spwan actors remotely.

        struct spawn_serv_state {
            static const char *name;
        };

        const char *spawn_serv_state::name = "spawn_server";

        behavior spawn_serv_impl(stateful_actor<spawn_serv_state> *self) {
            ACTOR_LOG_TRACE("");
            return {
                [=](spawn_atom, const std::string &name, message &args,
                    spawner::mpi &xs) -> expected<strong_actor_ptr> {
                    ACTOR_LOG_TRACE(ACTOR_ARG(name) << ACTOR_ARG(args));
                    return self->system().spawn<strong_actor_ptr>(name, std::move(args), self->context(), true, &xs);
                },
            };
        }

        // -- stream server ------------------------------------------------------------

        // The stream server acts as a man-in-the-middle for all streams that cross the
        // network. It manages any number of unrelated streams by placing itself and the
        // stream server on the next remote node into the pipeline.

        // Outgoing messages are buffered in FIFO order to ensure fairness. However, the
        // stream server uses five different FIFO queues: on for each priority level.
        // A high priority grants more network bandwidth.

        // Note that stream servers do not actively take part in the streams they
        // process. Batch messages and ACKs are treated equally. Open, close, and error
        // messages are evaluated to add and remove state as needed.

        class dropping_execution_unit : public execution_unit {
        public:
            dropping_execution_unit(spawner *sys) : execution_unit(sys) {
                // nop
            }

            void exec_later(resumable *) override {
                // should not happen in the first place
                ACTOR_LOG_ERROR("actor registry actor called exec_later during shutdown");
            }
        };

    }    // namespace

    spawner::spawner(spawner_config &cfg) :
        profiler_(cfg.profiler), ids_(0), logger_(new nil::actor::logger(*this), false), registry_(*this),
        groups_(*this), dummy_execution_unit_(this), await_actors_before_shutdown_(true), detached_(0), cfg_(cfg),
        logger_dtor_done_(false), tracing_context_(cfg.tracing_context) {
        ACTOR_SET_LOGGER_SYS(this);
        for (auto &hook : cfg.thread_hooks_)
            hook->init(*this);
        for (auto &f : cfg.module_factories) {
            auto *mod_ptr = f(*this);
            modules_[mod_ptr->id()].reset(mod_ptr);
        }
        // Make sure meta objects are loaded.
        auto gmos = detail::global_meta_objects();
        if (gmos.size() < id_block::core_module::end || gmos[id_block::core_module::begin].type_name == nullptr) {
            ACTOR_CRITICAL(
                "spawner created without calling "
                "nil::actor::init_global_meta_objects<>() before");
        }
        if (modules_[spawner_module::middleman] != nullptr) {
            if (gmos.size() < detail::io_module_end || gmos[detail::io_module_begin].type_name == nullptr) {
                ACTOR_CRITICAL(
                    "I/O module loaded without calling "
                    "nil::actor::io::middleman::init_global_meta_objects() before");
            }
        }
        // Make sure we have a scheduler up and running.
        auto &sched = modules_[spawner_module::scheduler];
        using namespace scheduler;
        using policy::work_sharing;
        using policy::work_stealing;
        using share = coordinator<work_sharing>;
        using steal = coordinator<work_stealing>;
        if (!sched) {
            enum sched_conf {
                stealing = 0x0001,
                sharing = 0x0002,
                testing = 0x0003,
            };
            sched_conf sc = stealing;
            namespace sr = defaults::scheduler;
            auto sr_policy = get_or(cfg, "scheduler.policy", sr::policy);
            if (sr_policy == "sharing")
                sc = sharing;
            else if (sr_policy == "testing")
                sc = testing;
            else if (sr_policy != "stealing")
                std::cerr << "[WARNING] " << deep_to_string(sr_policy)
                          << " is an unrecognized scheduler pollicy, "
                             "falling back to 'stealing' (i.e. work-stealing)"
                          << std::endl;
            switch (sc) {
                default:    // any invalid configuration falls back to work stealing
                    sched = std::make_unique<steal>(*this);
                    break;
                case sharing:
                    sched = std::make_unique<share>(*this);
                    break;
                case testing:
                    sched = std::make_unique<test_coordinator>(*this);
            }
        }
        // Initialize state for each module and give each module the opportunity to
        // adapt the system configuration.
        logger_->init(cfg);
        ACTOR_SET_LOGGER_SYS(this);
        for (auto &mod : modules_)
            if (mod)
                mod->init(cfg);
        groups_.init(cfg);
        // Spawn config and spawn servers (lazily to not access the scheduler yet).
        static constexpr auto Flags = hidden + lazy_init;
        spawn_serv(actor_cast<strong_actor_ptr>(spawn<Flags>(spawn_serv_impl)));
        config_serv(actor_cast<strong_actor_ptr>(spawn<Flags>(config_serv_impl)));
        // Start all modules.
        registry_.start();
        registry_.put("SpawnServ", spawn_serv());
        registry_.put("ConfigServ", config_serv());
        for (auto &mod : modules_)
            if (mod)
                mod->start();
        groups_.start();
        logger_->start();
    }

    spawner::~spawner() {
        {
            ACTOR_LOG_TRACE("");
            ACTOR_LOG_DEBUG("shutdown actor system");
            if (await_actors_before_shutdown_)
                await_all_actors_done();
            // shutdown internal actors
            auto drop = [&](auto &x) {
                anon_send_exit(x, exit_reason::user_shutdown);
                x = nullptr;
            };
            drop(spawn_serv_);
            drop(config_serv_);
            registry_.erase("SpawnServ");
            registry_.erase("ConfigServ");
            // group module is the first one, relies on MM
            groups_.stop();
            // stop modules in reverse order
            for (auto i = modules_.rbegin(); i != modules_.rend(); ++i) {
                auto &ptr = *i;
                if (ptr != nullptr) {
                    ACTOR_LOG_DEBUG("stop module" << ptr->name());
                    ptr->stop();
                }
            }
            await_detached_threads();
            registry_.stop();
        }
        // reset logger and wait until dtor was called
        ACTOR_SET_LOGGER_SYS(nullptr);
        logger_.reset();
        std::unique_lock<std::mutex> guard {logger_dtor_mtx_};
        while (!logger_dtor_done_)
            logger_dtor_cv_.wait(guard);
    }

    /// Returns the host-local identifier for this system.
    const node_id &spawner::node() const {
        return node_;
    }

    /// Returns the scheduler instance.
    scheduler::abstract_coordinator &spawner::scheduler() {
        using ptr = scheduler::abstract_coordinator *;
        return *static_cast<ptr>(modules_[spawner_module::scheduler].get());
    }

    nil::actor::logger &spawner::logger() {
        return *logger_;
    }

    actor_registry &spawner::registry() {
        return registry_;
    }

    std::string spawner::render(const error &x) const {
        if (!x)
            return to_string(x);
        const auto &xs = config().error_renderers;
        auto i = xs.find(x.category());
        if (i != xs.end())
            return i->second(x.code(), x.context());
        return to_string(x);
    }

    group_manager &spawner::groups() {
        return groups_;
    }

    bool spawner::has_middleman() const {
        return modules_[spawner_module::middleman] != nullptr;
    }

    io::middleman &spawner::middleman() {
        auto &clptr = modules_[spawner_module::middleman];
        if (!clptr)
            ACTOR_RAISE_ERROR("cannot access middleman: module not loaded");
        return *reinterpret_cast<io::middleman *>(clptr->subtype_ptr());
    }

    bool spawner::has_openssl_manager() const {
        return modules_[spawner_module::openssl_manager] != nullptr;
    }

    openssl::manager &spawner::openssl_manager() const {
        const auto &clptr = modules_[spawner_module::openssl_manager];
        if (!clptr)
            ACTOR_RAISE_ERROR("cannot access openssl manager: module not loaded");
        return *reinterpret_cast<openssl::manager *>(clptr->subtype_ptr());
    }

    bool spawner::has_network_manager() const noexcept {
        return modules_[spawner_module::network_manager] != nullptr;
    }

    network::middleman &spawner::network_manager() {
        auto &clptr = modules_[spawner_module::network_manager];
        if (!clptr)
            ACTOR_RAISE_ERROR("cannot access openssl manager: module not loaded");
        return *reinterpret_cast<network::middleman *>(clptr->subtype_ptr());
    }

    scoped_execution_unit *spawner::dummy_execution_unit() {
        return &dummy_execution_unit_;
    }

    actor_id spawner::next_actor_id() {
        return ++ids_;
    }

    actor_id spawner::latest_actor_id() const {
        return ids_.load();
    }

    void spawner::await_all_actors_done() const {
        registry_.await_running_count_equal(0);
    }

    void spawner::monitor(const node_id &node, const actor_addr &observer) {
        // TODO: Currently does not work with other modules, in particular caf_net.
        auto *mm = modules_[spawner_module::middleman].get();
        if (mm == nullptr)
            return;
        auto *mm_dptr = static_cast<networking_module *>(mm);
        mm_dptr->monitor(node, observer);
    }

    void spawner::demonitor(const node_id &node, const actor_addr &observer) {
        // TODO: Currently does not work with other modules, in particular caf_net.
        auto *mm = modules_[spawner_module::middleman].get();
        if (mm == nullptr)
            return;
        auto *mm_dptr = static_cast<networking_module *>(mm);
        mm_dptr->demonitor(node, observer);
    }

    actor_clock &spawner::clock() noexcept {
        return scheduler().clock();
    }

    void spawner::inc_detached_threads() {
        ++detached_;
    }

    void spawner::dec_detached_threads() {
        std::unique_lock<std::mutex> guard {detached_mtx_};
        if (--detached_ == 0)
            detached_cv_.notify_all();
    }

    void spawner::await_detached_threads() {
        std::unique_lock<std::mutex> guard {detached_mtx_};
        while (detached_ != 0)
            detached_cv_.wait(guard);
    }

    void spawner::thread_started() {
        for (auto &hook : cfg_.thread_hooks_)
            hook->thread_started();
    }

    void spawner::thread_terminates() {
        for (auto &hook : cfg_.thread_hooks_)
            hook->thread_terminates();
    }

    expected<strong_actor_ptr> spawner::dyn_spawn_impl(const std::string &name, message &args, execution_unit *ctx,
                                                       bool check_interface, optional<const mpi &> expected_ifs) {
        ACTOR_LOG_TRACE(ACTOR_ARG(name) << ACTOR_ARG(args) << ACTOR_ARG(check_interface) << ACTOR_ARG(expected_ifs));
        if (name.empty())
            return sec::invalid_argument;
        auto &fs = cfg_.actor_factories;
        auto i = fs.find(name);
        if (i == fs.end())
            return sec::unknown_type;
        actor_config cfg {ctx != nullptr ? ctx : &dummy_execution_unit_};
        auto res = i->second(cfg, args);
        if (!res.first)
            return sec::cannot_spawn_actor_from_arguments;
        if (check_interface && !assignable(res.second, *expected_ifs))
            return sec::unexpected_actor_messaging_interface;
        return std::move(res.first);
    }

}    // namespace nil::actor
