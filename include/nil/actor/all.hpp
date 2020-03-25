//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/config.hpp>

#include <nil/actor/sec.hpp>
#include <nil/actor/atom.hpp>
#include <nil/actor/send.hpp>
#include <nil/actor/skip.hpp>
#include <nil/actor/unit.hpp>
#include <nil/actor/term.hpp>
#include <nil/actor/actor.hpp>
#include <nil/actor/after.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/group.hpp>
#include <nil/actor/extend.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/others.hpp>
#include <nil/actor/result.hpp>
#include <nil/actor/stream.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/node_id.hpp>
#include <nil/actor/behavior.hpp>
#include <nil/actor/defaults.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/expected.hpp>
#include <nil/actor/exec_main.hpp>
#include <nil/actor/resumable.hpp>
#include <nil/actor/to_string.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/actor_pool.hpp>
#include <nil/actor/attachable.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/replies_to.hpp>
#include <nil/actor/serialization/serializer.hpp>
#include <nil/actor/actor_clock.hpp>
#include <nil/actor/actor_proxy.hpp>
#include <nil/actor/exit_reason.hpp>
#include <nil/actor/local_actor.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/stream_slot.hpp>
#include <nil/actor/thread_hook.hpp>
#include <nil/actor/typed_actor.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/config_value.hpp>
#include <nil/actor/serialization/deserializer.hpp>
#include <nil/actor/scoped_actor.hpp>
#include <nil/actor/upstream_msg.hpp>
#include <nil/actor/actor_ostream.hpp>
#include <nil/actor/function_view.hpp>
#include <nil/actor/index_mapping.hpp>
#include <nil/actor/spawn_options.hpp>
#include <nil/actor/abstract_actor.hpp>
#include <nil/actor/abstract_group.hpp>
#include <nil/actor/blocking_actor.hpp>
#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/execution_unit.hpp>
#include <nil/actor/memory_managed.hpp>
#include <nil/actor/stateful_actor.hpp>
#include <nil/actor/typed_behavior.hpp>
#include <nil/actor/proxy_registry.hpp>
#include <nil/actor/downstream_msg.hpp>
#include <nil/actor/behavior_policy.hpp>
#include <nil/actor/message_builder.hpp>
#include <nil/actor/message_handler.hpp>
#include <nil/actor/response_handle.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/abstract_channel.hpp>
#include <nil/actor/may_have_timeout.hpp>
#include <nil/actor/message_priority.hpp>
#include <nil/actor/typed_actor_view.hpp>
#include <nil/actor/serialization/binary_serializer.hpp>
#include <nil/actor/composed_behavior.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/primitive_variant.hpp>
#include <nil/actor/timeout_definition.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/serialization/binary_deserializer.hpp>
#include <nil/actor/composable_behavior.hpp>
#include <nil/actor/typed_actor_pointer.hpp>
#include <nil/actor/scoped_execution_unit.hpp>
#include <nil/actor/typed_response_promise.hpp>
#include <nil/actor/typed_event_based_actor.hpp>
#include <nil/actor/fused_downstream_manager.hpp>
#include <nil/actor/abstract_composable_behavior.hpp>

#include <nil/actor/decorator/sequencer.hpp>

#include <nil/actor/meta/type_name.hpp>
#include <nil/actor/meta/annotation.hpp>
#include <nil/actor/meta/save_callback.hpp>
#include <nil/actor/meta/load_callback.hpp>
#include <nil/actor/meta/omittable_if_empty.hpp>

#include <nil/actor/scheduler/test_coordinator.hpp>
#include <nil/actor/scheduler/abstract_coordinator.hpp>

///
/// @mainpage ACTOR
///
/// @section Intro Introduction
///
/// This library provides an implementation of the actor model for C++.
/// It uses a network transparent messaging system to ease development
/// of both concurrent and distributed software.
///
/// `ACTOR` uses a thread pool to schedule actors by default.
/// A scheduled actor should not call blocking functions.
/// Individual actors can be spawned (created) with a special flag to run in
/// an own thread if one needs to make use of blocking APIs.
///
/// Writing applications in `ACTOR` requires a minimum of gluecode and
/// each context <i>is</i> an actor. Scoped actors allow actor interaction
/// from the context of threads such as main.
///
/// @section GettingStarted Getting Started
///
/// To build `ACTOR,` you need `GCC >= 4.8 or <tt>Clang >= 3.2</tt>,
/// and `CMake`.
///
/// The usual build steps on Linux and macOS are:
///
///- `./configure
///- `make
///- `make install (as root, optionally)
///
/// Please run the unit tests as well to verify that `libmtl`
/// works properly.
///
///- `make test
///
/// Please submit a bug report that includes (a) your compiler version,
/// (b) your OS, and (c) the output of the unit tests if an error occurs:
/// https://github.com/nilfoundation/actor/issues
///
/// Please read the <b>Manual</b> for an introduction to `ACTOR`.
/// It is available online at https://actor.nil.foundation
///
/// @section IntroHelloWorld Hello World Example
///
/// @include hello_world.cpp
///
/// @section IntroMoreExamples More Examples
///
/// The {@link math_actor.cpp Math Actor Example} shows the usage
/// of {@link receive_loop} and {@link nil::actor::arg_match arg_match}.
/// The {@link dining_philosophers.cpp Dining Philosophers Example}
/// introduces event-based actors covers various features of ACTOR.
///
/// @namespace nil
/// Root namespace of all the Nil Foundation projects
///
/// @namespace actor
/// Root namespace of ACTOR.
///
/// @namespace nil::actor::mixin
/// Contains mixin classes implementing several actor traits.
///
/// @namespace nil::actor::exit_reason
/// Contains all predefined exit reasons.
///
/// @namespace nil::actor::policy
/// Contains policies encapsulating characteristics or algorithms.
///
/// @namespace nil::actor::io
/// Contains all IO-related classes and functions.
///
/// @namespace nil::actor::io::network
/// Contains classes and functions used for network abstraction.
///
/// @namespace nil::actor::io::basp
/// Contains all classes and functions for the Binary Actor Sytem Protocol.
///
/// @defgroup MessageHandling Message Handling
///
/// This is the beating heart of ACTOR, since actor programming is
/// a message oriented programming paradigm.
///
/// A message in ACTOR is a n-tuple of values (with size >= 1).
/// You can use almost every type in a messages as long as it is announced,
/// i.e., known by the type system of ACTOR.
///
/// @defgroup BlockingAPI Blocking API
///
/// Blocking functions to receive messages.
///
/// The blocking API of ACTOR is intended to be used for migrating
/// previously threaded applications. When writing new code, you should
/// consider the nonblocking API based on `become` and `unbecome` first.
///
/// @section Send Sending Messages
///
/// The function `send` can be used to send a message to an actor.
/// The first argument is the receiver of the message followed by any number
/// of values:
///
/// ~~
/// // spawn some actors
/// spawner_config cfg;
/// spawner system{cfg};
/// auto a1 = system.spawn(...);
/// auto a2 = system.spawn(...);
/// auto a3 = system.spawn(...);
///
/// // an actor executed in the current thread
/// scoped_actor self{system};
///
/// // define an atom for message annotation
/// using hello_atom = atom_constant<atom("hello")>;
/// using compute_atom = atom_constant<atom("compute")>;
/// using result_atom = atom_constant<atom("result")>;
///
/// // send a message to a1
/// self->send(a1, hello_atom::value, "hello a1!");
///
/// // send a message to a1, a2, and a3
/// auto msg = make_message(compute_atom::value, 1, 2, 3);
/// self->send(a1, msg);
/// self->send(a2, msg);
/// self->send(a3, msg);
/// ~~
///
/// @section Receive Receive messages
///
/// The function `receive` takes a `behavior` as argument. The behavior
/// is a list of { callback } rules where the callback argument types
/// define a pattern for matching messages.
///
/// ~~
/// {
///   [](hello_atom, const std::string& msg) {
///     cout << "received hello message: " << msg << endl;
///   },
///   [](compute_atom, int i0, int i1, int i2) {
///     // send our result back to the sender of this messages
///     return make_message(result_atom::value, i0 + i1 + i2);
///   }
/// }
/// ~~
///
/// Blocking actors such as the scoped actor can call their receive member
/// to handle incoming messages.
///
/// ~~
/// self->receive(
///  [](result_atom, int i) {
///    cout << "result is: " << i << endl;
///  }
/// );
/// ~~
///
/// Please read the manual for further details about pattern matching.
///
/// @section Atoms Atoms
///
/// Atoms are a nice way to add semantic informations to a message.
/// Assuming an actor wants to provide a "math sevice" for integers. It
/// could provide operations such as addition, subtraction, etc.
/// This operations all have two operands. Thus, the actor does not know
/// what operation the sender of a message wanted by receiving just two integers.
///
/// Example actor:
/// ~~
/// using plus_atom = atom_constant<atom("plus")>;
/// using minus_atom = atom_constant<atom("minus")>;
/// behavior math_actor() {
///   return {
///     [](plus_atom, int a, int b) {
///       return make_message(atom("result"), a + b);
///     },
///     [](minus_atom, int a, int b) {
///       return make_message(atom("result"), a - b);
///     }
///   };
/// }
/// ~~
///
/// @section ReceiveLoops Receive Loops
///
/// The previous examples used `receive` to create a behavior on-the-fly.
/// This is inefficient in a loop since the argument passed to receive
/// is created in each iteration again. It's possible to store the behavior
/// in a variable and pass that variable to receive. This fixes the issue
/// of re-creation each iteration but rips apart definition and usage.
///
/// There are three convenience functions implementing receive loops to
/// declare behavior where it belongs without unnecessary
/// copies: `receive_while,` `receive_for` and `do_receive`.
///
/// `receive_while` creates a functor evaluating a lambda expression.
/// The loop continues until the given lambda returns `false`. A simple example:
///
/// ~~
/// size_t received = 0;
/// receive_while([&] { return received < 10; }) (
///   [&](int) {
///     ++received;
///   }
/// );
/// // ...
/// ~~
///
/// `receive_for` is a simple ranged-based loop:
///
/// ~~
/// std::vector<int> results;
/// size_t i = 0;
/// receive_for(i, 10) (
///   [&](int value) {
///     results.push_back(value);
///   }
/// );
/// ~~
///
/// `do_receive` returns a functor providing the function `until` that
/// takes a lambda expression. The loop continues until the given lambda
/// returns true. Example:
///
/// ~~
/// size_t received = 0;
/// do_receive (
///   [&](int) {
///     ++received;
///   }
/// ).until([&] { return received >= 10; });
/// // ...
/// ~~
///
/// @section FutureSend Sending Delayed Messages
///
/// The function `delayed_send` provides a simple way to delay a message.
/// This is particularly useful for recurring events, e.g., periodical polling.
/// Usage example:
///
/// ~~
/// scoped_actor self{...};
///
/// self->delayed_send(self, std::chrono::seconds(1), poll_atom::value);
/// bool running = true;
/// self->receive_while([&](){ return running; }) (
///   // ...
///   [&](poll_atom) {
///     // ... poll something ...
///     // and do it again after 1sec
///     self->delayed_send(self, std::chrono::seconds(1), poll_atom::value);
///   }
/// );
/// ~~
///
/// See also the {@link dancing_kirby.cpp dancing kirby example}.
///
/// @defgroup ImplicitConversion Implicit Type Conversions
///
/// The message passing of `libmtl` prohibits pointers in messages because
/// it enforces network transparent messaging.
/// Unfortunately, string literals in `C++` have the type `const char*,
/// resp. `const char[]. Since `libmtl` is a user-friendly library,
/// it silently converts string literals and C-strings to `std::string` objects.
/// It also converts unicode literals to the corresponding STL container.
///
/// A few examples:
/// ~~
/// // sends an std::string containing "hello actor!" to itself
/// send(self, "hello actor!");
///
/// const char* cstring = "cstring";
/// // sends an std::string containing "cstring" to itself
/// send(self, cstring);
///
/// // sends an std::u16string containing the UTF16 string "hello unicode world!"
/// send(self, u"hello unicode world!");
///
/// // x has the type nil::actor::tuple<std::string, std::string>
/// auto x = make_message("hello", "tuple");
/// ~~
///
/// @defgroup ActorCreation Creating Actors

// examples

/// A trivial example program.
/// @example hello_world.cpp

/// A simple example for a delayed_send based application.
/// @example dancing_kirby.cpp

/// An event-based "Dining Philosophers" implementation.
/// @example dining_philosophers.cpp
