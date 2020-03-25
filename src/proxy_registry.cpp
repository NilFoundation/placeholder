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

#include <algorithm>
#include <utility>

#include <nil/actor/actor_addr.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/serialization/deserializer.hpp>
#include <nil/actor/node_id.hpp>
#include <nil/actor/proxy_registry.hpp>
#include <nil/actor/serialization/serializer.hpp>

#include <nil/actor/actor_registry.hpp>
#include <nil/actor/logger.hpp>

namespace nil {
    namespace actor {

        proxy_registry::backend::~backend() {
            // nop
        }

        proxy_registry::proxy_registry(spawner &sys, backend &be) : system_(sys), backend_(be) {
            // nop
        }

        proxy_registry::~proxy_registry() {
            clear();
        }

        size_t proxy_registry::count_proxies(const node_id &node) const {
            std::unique_lock<std::mutex> guard {mtx_};
            auto i = proxies_.find(node);
            return i != proxies_.end() ? i->second.size() : 0;
        }

        strong_actor_ptr proxy_registry::get(const node_id &node, actor_id aid) const {
            std::unique_lock<std::mutex> guard {mtx_};
            auto i = proxies_.find(node);
            if (i == proxies_.end())
                return nullptr;
            auto j = i->second.find(aid);
            return j != i->second.end() ? j->second : nullptr;
        }

        strong_actor_ptr proxy_registry::get_or_put(const node_id &nid, actor_id aid) {
            ACTOR_LOG_TRACE(ACTOR_ARG(nid) << ACTOR_ARG(aid));
            std::unique_lock<std::mutex> guard {mtx_};
            auto &result = proxies_[nid][aid];
            if (!result)
                result = backend_.make_proxy(nid, aid);
            return result;
        }

        std::vector<strong_actor_ptr> proxy_registry::get_all(const node_id &node) const {
            // Reserve at least some memory outside of the critical section.
            std::vector<strong_actor_ptr> result;
            result.reserve(128);
            std::unique_lock<std::mutex> guard {mtx_};
            auto i = proxies_.find(node);
            if (i != proxies_.end())
                for (auto &kvp : i->second)
                    result.emplace_back(kvp.second);
            return result;
        }

        bool proxy_registry::empty() const {
            std::unique_lock<std::mutex> guard {mtx_};
            return proxies_.empty();
        }

        void proxy_registry::erase(const node_id &nid) {
            ACTOR_LOG_TRACE(ACTOR_ARG(nid));
            // Move submap for `nid` to a local variable.
            proxy_map tmp;
            {
                using std::swap;
                std::unique_lock<std::mutex> guard {mtx_};
                auto i = proxies_.find(nid);
                if (i == proxies_.end())
                    return;
                swap(i->second, tmp);
                proxies_.erase(i);
            }
            // Call kill_proxy outside the critical section.
            for (auto &kvp : tmp)
                kill_proxy(kvp.second, exit_reason::remote_link_unreachable);
        }

        void proxy_registry::erase(const node_id &nid, actor_id aid, error rsn) {
            ACTOR_LOG_TRACE(ACTOR_ARG(nid) << ACTOR_ARG(aid));
            // Try to find the actor handle in question.
            strong_actor_ptr erased_proxy;
            {
                using std::swap;
                std::unique_lock<std::mutex> guard {mtx_};
                auto i = proxies_.find(nid);
                if (i != proxies_.end()) {
                    auto &submap = i->second;
                    auto j = submap.find(aid);
                    if (j == submap.end())
                        return;
                    swap(j->second, erased_proxy);
                    submap.erase(j);
                    if (submap.empty())
                        proxies_.erase(i);
                }
            }
            // Call kill_proxy outside the critical section.
            if (erased_proxy != nullptr)
                kill_proxy(erased_proxy, std::move(rsn));
        }

        void proxy_registry::clear() {
            ACTOR_LOG_TRACE("");
            // Move the content of proxies_ to a local variable.
            std::unordered_map<node_id, proxy_map> tmp;
            {
                using std::swap;
                std::unique_lock<std::mutex> guard {mtx_};
                swap(proxies_, tmp);
            }
            // Call kill_proxy outside the critical section.
            for (auto &kvp : tmp)
                for (auto &sub_kvp : kvp.second)
                    kill_proxy(sub_kvp.second, exit_reason::remote_link_unreachable);
            proxies_.clear();
        }

        void proxy_registry::kill_proxy(strong_actor_ptr &ptr, error rsn) {
            if (!ptr)
                return;
            auto pptr = static_cast<actor_proxy *>(actor_cast<abstract_actor *>(ptr));
            pptr->kill_proxy(nullptr, std::move(rsn));
        }

    }    // namespace actor
}    // namespace nil
