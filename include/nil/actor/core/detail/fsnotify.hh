//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#pragma once

#include <memory>

#include <libfswatch/c++/path_utils.hpp>
#include <libfswatch/c++/event.hpp>
#include <libfswatch/c++/monitor.hpp>
#include <libfswatch/c++/monitor_factory.hpp>
#include <libfswatch/c/error.h>
#include <libfswatch/c/libfswatch.h>
#include <libfswatch/c/libfswatch_log.h>
#include <libfswatch/c++/libfswatch_exception.hpp>

#include <nil/actor/core/future.hh>
#include <nil/actor/core/sstring.hh>
#include <nil/actor/core/shared_ptr.hh>

namespace nil {
    namespace actor {

        /**
         * Thin wrapper around inotify. (See http://man7.org/linux/man-pages/man7/inotify.7.html)
         * De-facto light-weight filesystem modification watch interface.
         * Allows adding watches to files or directories for various modification
         * events (see fsnotifier::flags).
         *
         * Presents a c++ wrapped buffered read of events, and
         * raii-handling of watches themselves.
         *
         * All definition are bit-matched with inotify,
         * but watch points are raii guarded.
         *
         * Note that this impl does not (yet) handle
         * re-writing watches (adding to mask).
         *
         */
        class fsnotifier {
            class impl;
            shared_ptr<impl> _impl;

        public:
            class watch;
            friend class watch;

            enum class flags : uint32_t {
                access = IN_ACCESS,    // File was accessed (e.g., read(2), execve(2)).
                attrib = IN_ATTRIB,    // Metadata changed—for example, permissions, timestamps, extended attributes
                close_write = IN_CLOSE_WRITE,        // File opened for writing was closed.
                close_nowrite = IN_CLOSE_NOWRITE,    // File or directory not opened for writing was closed.
                create_child = IN_CREATE,            // File/directory created in watched directory
                delete_child = IN_DELETE,            // File/directory deleted from watched directory.
                delete_self = IN_DELETE_SELF,        // Watched file/directory was itself deleted.  (This event
                                                     // also occurs if an object is moved to another filesystem)
                modify = IN_MODIFY,                  // File was modified (e.g., write(2), truncate(2)).
                move_self = IN_MOVE_SELF,            // Watched file/directory was itself moved.
                move_from = IN_MOVED_FROM,           // Generated for the directory containing the old filename
                                                     // when a file is renamed.
                move_to = IN_MOVED_TO,               // Generated for the directory containing the new filename
                                                     // when a file is renamed.
                open = IN_OPEN,                      // File was opened
                close = IN_CLOSE,                    // close_write|close_nowrite
                move = IN_MOVE,                      // move_from|move_to
                oneshot = IN_ONESHOT,                // listen for only a single notification, after which the
                                                     // token will be invalid
                ignored = IN_IGNORED,                // generated when a token or the file being watched is deleted
                onlydir = IN_ONLYDIR,                // Watch pathname only if it is a directory; the error ENOT‐
                                                     // DIR results if pathname is not a directory.  Using this
                                                     // flag provides an application with a race-free way of
                                                     // ensuring that the monitored object is a directory.
            };

            using watch_token = int32_t;
            using sequence_no = uint32_t;

            /**
             * Simple raii-wrapper around a watch token
             * - i.e. watch identifier
             */
            class watch {
            public:
                ~watch();
                watch(watch &&) noexcept;
                watch &operator=(watch &&) noexcept;

                watch_token release();
                operator watch_token() const {
                    return _token;
                }
                watch_token token() const {
                    return _token;
                }

            private:
                friend class fsnotifier;
                watch(shared_ptr<impl>, watch_token);
                watch_token _token;
                shared_ptr<impl> _impl;
            };

            fsnotifier();
            ~fsnotifier();

            fsnotifier(fsnotifier &&);
            fsnotifier &operator=(fsnotifier &&);

            // create a watch point for given path, checking/producing
            // events specified in mask
            future<watch> create_watch(const sstring &path, flags mask);

            // a watch event.
            struct event {
                // matches source watch
                watch_token id;
                // event(s) generated
                flags mask;
                sequence_no seq;    // event correlation -> move_from+move_to
                sstring name;       // optional file name, in case of move_from/to
            };

            // wait for events
            future<std::vector<event>> wait() const;

            // shutdown notifier and abort any event wait.
            // all watches are invalidated, and no new ones can be
            // created.
            void shutdown();

            bool active() const;

            operator bool() const {
                return active();
            }
        };

        inline fsnotifier::flags operator|(fsnotifier::flags a, fsnotifier::flags b) {
            return fsnotifier::flags(std::underlying_type_t<fsnotifier::flags>(a) |
                                     std::underlying_type_t<fsnotifier::flags>(b));
        }

        inline void operator|=(fsnotifier::flags &a, fsnotifier::flags b) {
            a = (a | b);
        }

        inline fsnotifier::flags operator&(fsnotifier::flags a, fsnotifier::flags b) {
            return fsnotifier::flags(std::underlying_type_t<fsnotifier::flags>(a) &
                                     std::underlying_type_t<fsnotifier::flags>(b));
        }

        inline void operator&=(fsnotifier::flags &a, fsnotifier::flags b) {
            a = (a & b);
        }

    }    // namespace actor
}    // namespace nil
