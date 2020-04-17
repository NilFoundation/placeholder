//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <utility>

#include <boost/preprocessor/stringize.hpp>
#include <boost/preprocessor/facilities/expand.hpp>
#include <boost/preprocessor/facilities/overload.hpp>

#include <nil/actor/config.hpp>

#include <nil/actor/detail/squashed_int.hpp>

#include <nil/actor/meta/type_name.hpp>

#include <nil/actor/fwd.hpp>
#include <nil/actor/timespan.hpp>
#include <nil/actor/timestamp.hpp>

namespace nil {
    namespace actor {

        /// Internal representation of a type ID.
        using type_id_t = uint16_t;

        /// Maps the type `T` to a globally unique ID.
        template<class T>
        struct type_id;

        /// Convenience alias for `type_id<T>::value`.
        /// @relates type_id
        template<class T>
        constexpr type_id_t type_id_v = type_id<detail::squash_if_int_t<T>>::value;

        /// Maps the globally unique ID `V` to a type (inverse to ::type_id).
        /// @relates type_id
        template<type_id_t V>
        struct type_by_id;

        /// Convenience alias for `type_by_id<I>::type`.
        /// @relates type_by_id
        template<type_id_t I>
        using type_by_id_t = typename type_by_id<I>::type;

        /// Maps the globally unique ID `V` to a type name.
        template<type_id_t V>
        struct type_name_by_id;

        /// Convenience alias for `type_name_by_id<I>::value`.
        /// @relates type_name_by_id
        template<type_id_t I>
        constexpr const char *type_name_by_id_v = type_name_by_id<I>::value;

        /// Convenience type that resolves to `type_name_by_id<type_id_v<T>>`.
        template<class T>
        struct type_name;

        /// Convenience specialization that enables generic code to not treat `void`
        /// manually.
        template<>
        struct type_name<void> {
            static constexpr const char *value = "void";
        };

        /// Convenience alias for `type_name<T>::value`.
        /// @relates type_name
        template<class T>
        constexpr const char *type_name_v = type_name<T>::value;

        /// The first type ID not reserved by =nil; Actor and its modules.
        constexpr type_id_t first_custom_type_id = 200;

    }    // namespace actor
}    // namespace nil

/// Starts a code block for registering custom types to =nil; Actor. Stores the first ID
/// for the project as `nil::actor::id_block::${project_name}_first_type_id`. Usually,
/// users should use `nil::actor::first_custom_type_id` as `first_id`. However, this
/// mechanism also enables projects to append IDs to a block of another project.
/// If two projects are developed separately to avoid dependencies, they only
/// need to define sufficiently large offsets to guarantee collision-free IDs.
/// =nil; Actor supports gaps in the ID space.
///
/// @note =nil; Actor reserves all names with the suffix `_module`. For example, core
///       module uses the project name `core_module`.
#define ACTOR_BEGIN_TYPE_ID_BLOCK(project_name, first_id)                        \
    namespace nil::actor::id_block {                                           \
        constexpr type_id_t project_name##_type_id_counter_init = __COUNTER__; \
        constexpr type_id_t project_name##_first_type_id = first_id;           \
    }

#define ACTOR_PP_EXPAND(...) __VA_ARGS__

#ifdef BOOST_MSVC
/// Assigns the next free type ID to `fully_qualified_name`.
#define ACTOR_ADD_TYPE_ID(project_name, fully_qualified_name)                                                  \
    namespace nil {                                                                                            \
        namespace actor {                                                                                      \
            template<>                                                                                         \
            struct type_id<ACTOR_PP_EXPAND fully_qualified_name> {                                             \
                static constexpr type_id_t value =                                                             \
                    id_block::project_name##_first_type_id +                                                   \
                    (BOOST_PP_CAT(BOOST_PP_COUNTER, ()) - id_block::project_name##_type_id_counter_init - 1);  \
            };                                                                                                 \
            template<>                                                                                         \
            struct type_by_id<type_id<ACTOR_PP_EXPAND fully_qualified_name>::value> {                          \
                using type = ACTOR_PP_EXPAND fully_qualified_name;                                             \
            };                                                                                                 \
            template<>                                                                                         \
            struct type_name<ACTOR_PP_EXPAND fully_qualified_name> {                                           \
                static constexpr const char *value = BOOST_PP_STRINGIZE(ACTOR_PP_EXPAND fully_qualified_name); \
            };                                                                                                 \
            template<>                                                                                         \
            struct type_name_by_id<type_id<ACTOR_PP_EXPAND fully_qualified_name>::value>                       \
                : type_name<ACTOR_PP_EXPAND fully_qualified_name> {};                                          \
        }
#else
#define ACTOR_ADD_TYPE_ID(project_name, fully_qualified_name)                                                         \
    namespace nil {                                                                                                   \
        namespace actor {                                                                                             \
            template<>                                                                                                \
            struct type_id<ACTOR_PP_EXPAND fully_qualified_name> {                                                    \
                static constexpr type_id_t value = id_block::project_name##_first_type_id +                           \
                                                   (__COUNTER__ - id_block::project_name##_type_id_counter_init - 1); \
            };                                                                                                        \
            template<>                                                                                                \
            struct type_by_id<type_id<ACTOR_PP_EXPAND fully_qualified_name>::value> {                                 \
                using type = ACTOR_PP_EXPAND fully_qualified_name;                                                    \
            };                                                                                                        \
            template<>                                                                                                \
            struct type_name<ACTOR_PP_EXPAND fully_qualified_name> {                                                  \
                static constexpr const char *value = BOOST_PP_STRINGIZE(ACTOR_PP_EXPAND fully_qualified_name);        \
            };                                                                                                        \
            template<>                                                                                                \
            struct type_name_by_id<type_id<ACTOR_PP_EXPAND fully_qualified_name>::value>                              \
                : type_name<ACTOR_PP_EXPAND fully_qualified_name> {};                                                 \
        }                                                                                                             \
    }
#endif

/// Creates a new tag type (atom) in the global namespace and assigns the next
/// free type ID to it.
#define ACTOR_ADD_ATOM_2(project_name, atom_name)                      \
    struct atom_name {};                                               \
    static constexpr atom_name atom_name##_v = atom_name {};           \
    [[maybe_unused]] constexpr bool operator==(atom_name, atom_name) { \
        return true;                                                   \
    }                                                                  \
    [[maybe_unused]] constexpr bool operator!=(atom_name, atom_name) { \
        return false;                                                  \
    }                                                                  \
    template<class Inspector>                                          \
    auto inspect(Inspector &f, atom_name &) {                          \
        return f(nil::actor::meta::type_name(#atom_name));             \
    }                                                                  \
    ACTOR_ADD_TYPE_ID(project_name, (atom_name))

/// Creates a new tag type (atom) and assigns the next free type ID to it.
#define ACTOR_ADD_ATOM_3(project_name, atom_namespace, atom_name)                   \
    namespace atom_namespace {                                                      \
        struct atom_name {};                                                        \
        static constexpr atom_name atom_name##_v = atom_name {};                    \
        [[maybe_unused]] constexpr bool operator==(atom_name, atom_name) {          \
            return true;                                                            \
        }                                                                           \
        [[maybe_unused]] constexpr bool operator!=(atom_name, atom_name) {          \
            return false;                                                           \
        }                                                                           \
        template<class Inspector>                                                   \
        auto inspect(Inspector &f, atom_name &) {                                   \
            return f(nil::actor::meta::type_name(#atom_namespace "::" #atom_name)); \
        }                                                                           \
    }                                                                               \
    ACTOR_ADD_TYPE_ID(project_name, (atom_namespace::atom_name))

#ifdef ACTOR_MSVC
#define ACTOR_ADD_ATOM(...) BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_ADD_ATOM_, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())
#else
#define ACTOR_ADD_ATOM(...) BOOST_PP_OVERLOAD(ACTOR_ADD_ATOM_, __VA_ARGS__)(__VA_ARGS__)
#endif

/// Finalizes a code block for registering custom types to =nil; Actor. Defines a struct
/// `nil::actor::type_id::${project_name}` with two static members `begin` and `end`.
/// The former stores the first assigned type ID. The latter stores the last
/// assigned type ID + 1.
#define ACTOR_END_TYPE_ID_BLOCK(project_name)                                                         \
    namespace nil::actor::id_block {                                                                \
        constexpr type_id_t project_name##_last_type_id =                                           \
            project_name##_first_type_id + (__COUNTER__ - project_name##_type_id_counter_init - 2); \
        struct project_name {                                                                       \
            static constexpr type_id_t begin = project_name##_first_type_id;                        \
            static constexpr type_id_t end = project_name##_last_type_id + 1;                       \
        };                                                                                          \
    }

ACTOR_BEGIN_TYPE_ID_BLOCK(core_module, 0)

// -- C types

ACTOR_ADD_TYPE_ID(core_module, (bool))
ACTOR_ADD_TYPE_ID(core_module, (double))
ACTOR_ADD_TYPE_ID(core_module, (float))
ACTOR_ADD_TYPE_ID(core_module, (int16_t))
ACTOR_ADD_TYPE_ID(core_module, (int32_t))
ACTOR_ADD_TYPE_ID(core_module, (int64_t))
ACTOR_ADD_TYPE_ID(core_module, (int8_t))
ACTOR_ADD_TYPE_ID(core_module, (long double))
ACTOR_ADD_TYPE_ID(core_module, (uint16_t))
ACTOR_ADD_TYPE_ID(core_module, (uint32_t))
ACTOR_ADD_TYPE_ID(core_module, (uint64_t))
ACTOR_ADD_TYPE_ID(core_module, (uint8_t))

// -- STL types

ACTOR_ADD_TYPE_ID(core_module, (std::string))
ACTOR_ADD_TYPE_ID(core_module, (std::u16string))
ACTOR_ADD_TYPE_ID(core_module, (std::u32string))
ACTOR_ADD_TYPE_ID(core_module, (std::set<std::string>))

// -- =nil; Actor types

ACTOR_ADD_TYPE_ID(core_module, (nil::actor::actor))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::actor_addr))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::byte_buffer))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::config_value))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::dictionary<nil::actor::config_value>))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::down_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::downstream_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::error))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::exit_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::group))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::group_down_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::message))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::message_id))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::node_down_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::node_id))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::open_stream_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::strong_actor_ptr))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::timeout_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::timespan))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::timestamp))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::unit_t))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::upstream_msg))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::uri))
ACTOR_ADD_TYPE_ID(core_module, (nil::actor::weak_actor_ptr))
ACTOR_ADD_TYPE_ID(core_module, (std::vector<nil::actor::actor>))
ACTOR_ADD_TYPE_ID(core_module, (std::vector<nil::actor::actor_addr>))
ACTOR_ADD_TYPE_ID(core_module, (std::vector<nil::actor::config_value>))
ACTOR_ADD_TYPE_ID(core_module, (std::vector<nil::actor::strong_actor_ptr>))
ACTOR_ADD_TYPE_ID(core_module, (std::vector<nil::actor::weak_actor_ptr>))
ACTOR_ADD_TYPE_ID(core_module, (std::vector<std::pair<std::string, message>>))

// -- predefined atoms

ACTOR_ADD_ATOM(core_module, nil::actor, add_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, close_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, connect_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, contact_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, delete_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, demonitor_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, div_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, flush_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, forward_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, get_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, idle_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, join_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, leave_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, link_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, migrate_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, monitor_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, mul_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, ok_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, open_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, pending_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, ping_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, pong_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, publish_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, publish_udp_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, put_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, receive_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, redirect_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, reset_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, resolve_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, spawn_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, stream_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, sub_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, subscribe_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, sys_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, tick_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, timeout_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, unlink_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, unpublish_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, unpublish_udp_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, unsubscribe_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, update_atom)
ACTOR_ADD_ATOM(core_module, nil::actor, wait_for_atom)

ACTOR_END_TYPE_ID_BLOCK(core_module)

namespace nil::actor::detail {

    static constexpr type_id_t io_module_begin = id_block::core_module::end;

    static constexpr type_id_t io_module_end = io_module_begin + 19;

}    // namespace nil::actor::detail
