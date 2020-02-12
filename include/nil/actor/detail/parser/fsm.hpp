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

// This header intentionally has no `#pragma once`. Any parser that uses this
// DSL is supposed to clean up all defines made in this header via
// `include "actor/detail/parser/fsm_undef.hpp"` at the end.

#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/variadic/size.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/facilities/overload.hpp>

#define ACTOR_FSM_EVAL_MISMATCH_EC                                                \
    if (mismatch_ec == nil::actor::pec::unexpected_character)                     \
        ps.code = ch != '\n' ? mismatch_ec : nil::actor::pec::unexpected_newline; \
    else                                                                        \
        ps.code = mismatch_ec;                                                  \
    return;

/// Starts the definition of an FSM.
#define start()                              \
    char ch = ps.current();                  \
    goto s_init;                             \
    s_unexpected_eof:                        \
    ps.code = nil::actor::pec::unexpected_eof; \
    return;                                  \
    {                                        \
        static_cast<void>(0);    // dummy; init state closes parentheses

/// Defines a non-terminal state in the FSM.
#define state(name)                                                                                     \
    }                                                                                                   \
    for (;;) {                                                                                          \
        /* jumps back up here if no transition matches */                                               \
        ps.code = ch != '\n' ? nil::actor::pec::unexpected_character : nil::actor::pec::unexpected_newline; \
        return;                                                                                         \
        s_##name : if (ch == '\0') goto s_unexpected_eof;                                               \
        e_##name:

/// Defines a state in the FSM that doesn't check for end-of-input. Unstable
/// states must make a transition and cause undefined behavior otherwise.
#define unstable_state(name) \
    }                        \
    {                        \
        s_##name : e_##name:

/// Ends the definition of an FSM.
#define fin()                         \
    }                                 \
    s_fin:                            \
    ps.code = nil::actor::pec::success; \
    return;

/// Defines a terminal state in the FSM.
#define ACTOR_TERM_STATE_IMPL1(name)                        \
    }                                                     \
    for (;;) {                                            \
        /* jumps back up here if no transition matches */ \
        ps.code = nil::actor::pec::trailing_character;      \
        return;                                           \
        s_##name : if (ch == '\0') goto s_fin;            \
        e_##name:

/// Defines a terminal state in the FSM that runs `exit_statement` when leaving
/// the state with code `pec::success` or `pec::trailing_character`.
#define ACTOR_TERM_STATE_IMPL2(name, exit_statement)        \
    }                                                     \
    for (;;) {                                            \
        /* jumps back up here if no transition matches */ \
        ps.code = nil::actor::pec::trailing_character;      \
        exit_statement;                                   \
        return;                                           \
        s_##name : if (ch == '\0') {                      \
            exit_statement;                               \
            goto s_fin;                                   \
        }                                                 \
        e_##name:

#define ACTOR_TRANSITION_IMPL1(target) \
    ch = ps.next();                  \
    goto s_##target;

#define ACTOR_TRANSITION_IMPL2(target, whitelist)                    \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        ACTOR_TRANSITION_IMPL1(target)                               \
    }

#define ACTOR_TRANSITION_IMPL3(target, whitelist, action)            \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        action;                                                    \
        ACTOR_TRANSITION_IMPL1(target)                               \
    }

#define ACTOR_TRANSITION_IMPL4(target, whitelist, action, error_code) \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) {  \
        if (!action) {                                              \
            ps.code = error_code;                                   \
            return;                                                 \
        }                                                           \
        ACTOR_TRANSITION_IMPL1(target)                                \
    }

#define ACTOR_ERROR_TRANSITION_IMPL2(error_code, whitelist)          \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        ps.code = error_code;                                      \
        return;                                                    \
    }

#define ACTOR_ERROR_TRANSITION_IMPL1(error_code) \
    ps.code = error_code;                      \
    return;

#define ACTOR_EPSILON_IMPL1(target) goto s_##target;

#define ACTOR_EPSILON_IMPL2(target, whitelist)                       \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        ACTOR_EPSILON_IMPL1(target)                                  \
    }

#define ACTOR_EPSILON_IMPL3(target, whitelist, action)               \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        action;                                                    \
        ACTOR_EPSILON_IMPL1(target)                                  \
    }

#define ACTOR_EPSILON_IMPL4(target, whitelist, action, error_code)   \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        if (!action) {                                             \
            ps.code = error_code;                                  \
            return;                                                \
        }                                                          \
        ACTOR_EPSILON_IMPL1(target)                                  \
    }

#define ACTOR_FSM_TRANSITION_IMPL2(fsm_call, target)   \
    ps.next();                                       \
    fsm_call;                                        \
    if (ps.code > nil::actor::pec::trailing_character) \
        return;                                      \
    ch = ps.current();                               \
    goto s_##target;

#define ACTOR_FSM_TRANSITION_IMPL3(fsm_call, target, whitelist)      \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        ACTOR_FSM_TRANSITION_IMPL2(fsm_call, target)                 \
    }

#define ACTOR_FSM_TRANSITION_IMPL4(fsm_call, target, whitelist, action) \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) {    \
        action;                                                       \
        ACTOR_FSM_TRANSITION_IMPL2(fsm_call, target)                    \
    }

#define ACTOR_FSM_TRANSITION_IMPL5(fsm_call, target, whitelist, action, error_code) \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) {                \
        if (!action) {                                                            \
            ps.code = error_code;                                                 \
            return;                                                               \
        }                                                                         \
        ACTOR_FSM_TRANSITION_IMPL2(fsm_call, target)                                \
    }

#define ACTOR_FSM_EPSILON_IMPL2(fsm_call, target)      \
    fsm_call;                                        \
    if (ps.code > nil::actor::pec::trailing_character) \
        return;                                      \
    ch = ps.current();                               \
    goto s_##target;

#define ACTOR_FSM_EPSILON_IMPL3(fsm_call, target, whitelist)         \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        ACTOR_FSM_EPSILON_IMPL2(fsm_call, target)                    \
    }

#define ACTOR_FSM_EPSILON_IMPL4(fsm_call, target, whitelist, action) \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) { \
        action;                                                    \
        ACTOR_FSM_EPSILON_IMPL2(fsm_call, target)                    \
    }

#define ACTOR_FSM_EPSILON_IMPL5(fsm_call, target, whitelist, action, error_code) \
    if (::nil::actor::detail::parser::in_whitelist(whitelist, ch)) {             \
        if (!action) {                                                         \
            ps.code = error_code;                                              \
            return;                                                            \
        }                                                                      \
        ACTOR_FSM_EPSILON_IMPL2(fsm_call, target)                                \
    }

#ifdef ACTOR_MSVC

/// Defines a terminal state in the FSM.
#define term_state(...) BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_TERM_STATE_IMPL, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

/// Transitions to target state if a predicate (optional argument 1) holds for
/// the current token and executes an action (optional argument 2) before
/// entering the new state.
#define transition(...) BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_TRANSITION_IMPL, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

/// Stops the FSM with reason `error_code` if `predicate` holds for the current
/// token.
#define error_transition(...) \
    BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_ERROR_TRANSITION_IMPL, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

// Makes an epsilon transition into another state.
#define epsilon(...) BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_EPSILON_IMPL, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

/// Makes an transition transition into another FSM, resuming at state `target`.
#define fsm_transition(...) \
    BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_FSM_TRANSITION_IMPL, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

/// Makes an epsilon transition into another FSM, resuming at state `target`.
#define fsm_epsilon(...) \
    BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_FSM_EPSILON_IMPL, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

#else    // ACTOR_MSVC

/// Defines a terminal state in the FSM.
#define term_state(...) BOOST_PP_OVERLOAD(ACTOR_TERM_STATE_IMPL, __VA_ARGS__)(__VA_ARGS__)

/// Transitions to target state if a predicate (optional argument 1) holds for
/// the current token and executes an action (optional argument 2) before
/// entering the new state.
#define transition(...) BOOST_PP_OVERLOAD(ACTOR_TRANSITION_IMPL, __VA_ARGS__)(__VA_ARGS__)

/// Stops the FSM with reason `error_code` if `predicate` holds for the current
/// token.
#define error_transition(...) BOOST_PP_OVERLOAD(ACTOR_ERROR_TRANSITION_IMPL, __VA_ARGS__)(__VA_ARGS__)

// Makes an epsilon transition into another state.
#define epsilon(...) BOOST_PP_OVERLOAD(ACTOR_EPSILON_IMPL, __VA_ARGS__)(__VA_ARGS__)

/// Makes an transition transition into another FSM, resuming at state `target`.
#define fsm_transition(...) BOOST_PP_OVERLOAD(ACTOR_FSM_TRANSITION_IMPL, __VA_ARGS__)(__VA_ARGS__)

/// Makes an epsilon transition into another FSM, resuming at state `target`.
#define fsm_epsilon(...) BOOST_PP_OVERLOAD(ACTOR_FSM_EPSILON_IMPL, __VA_ARGS__)(__VA_ARGS__)

#endif    // ACTOR_MSVC

/// Makes a transition into another state if the `statement` is true.
#define transition_if(statement, ...) \
    if (statement) {                  \
        transition(__VA_ARGS__)       \
    }

/// Makes an epsiolon transition into another state if the `statement` is true.
#define epsilon_if(statement, ...) \
    if (statement) {               \
        epsilon(__VA_ARGS__)       \
    }

/// Makes an transition transition into another FSM if `statement` is true,
/// resuming at state `target`.
#define fsm_transition_if(statement, ...) \
    if (statement) {                      \
        fsm_transition(__VA_ARGS__)       \
    }

/// Makes an epsilon transition into another FSM if `statement` is true,
/// resuming at state `target`.
#define fsm_epsilon_if(statement, ...) \
    if (statement) {                   \
        fsm_epsilon(__VA_ARGS__)       \
    }
