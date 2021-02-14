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

#include <random>
#include <algorithm>

#include <nil/actor/testing/thread_test_case.hh>
#include <nil/actor/core/fstream.hh>
#include <nil/actor/core/file.hh>
#include <nil/actor/core/core.hh>
#include <nil/actor/detail/std-compat.hh>

#include "../../src/core/fsnotify.hh"
#include "tmpdir.hh"

namespace fs = std::filesystem;
using namespace nil::actor;

static bool find_event(const std::vector<fsnotifier::event> &events, const fsnotifier::watch &w, fsnotifier::flags mask,
                       std::optional<sstring> path = {}) {
    auto i = std::find_if(events.begin(), events.end(), [&](const fsnotifier::event &e) {
        return (e.mask & mask) != fsnotifier::flags {} && e.id == w && (!path || *path == e.name);
    });
    return i != events.end();
}

ACTOR_THREAD_TEST_CASE(test_notify_modify_close_delete) {
    tmpdir tmp;
    fsnotifier fsn;

    auto p = tmp.path() / "kossa.dat";
    auto f = open_file_dma(p.native(), open_flags::create | open_flags::rw).get0();
    auto w = fsn.create_watch(p.native(),
                              fsnotifier::flags::delete_self | fsnotifier::flags::modify | fsnotifier::flags::close)
                 .get0();

    auto os = api_v3::and_newer::make_file_output_stream(f).get0();
    os.write("kossa").get();
    os.flush().get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::modify));
    }

    os.close().get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::close_write));
    }

    remove_file(p.native()).get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::delete_self));
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::ignored));
    }
}

ACTOR_THREAD_TEST_CASE(test_notify_overwrite) {
    tmpdir tmp;
    fsnotifier fsn;

    auto p = tmp.path() / "kossa.dat";

    auto write_file = [](fs::path &p, sstring content) {
        auto f = open_file_dma(p.native(), open_flags::create | open_flags::rw).get0();
        auto os = api_v3::and_newer::make_file_output_stream(f).get0();
        os.write(content).get();
        os.flush().get();
        os.close().get();
    };

    write_file(p, "kossa");

    auto w = fsn.create_watch(p.native(),
                              fsnotifier::flags::delete_self | fsnotifier::flags::modify | fsnotifier::flags::close)
                 .get0();

    write_file(p, "kossabello");

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::modify));
    }

    write_file(p, "kossaruffalobill");

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::modify));
    }

    auto p2 = tmp.path() / "tmp.apa";
    write_file(p2, "le apa");

    auto w2 = fsn.create_watch(tmp.path().native(), fsnotifier::flags::move_to).get0();

    rename_file(p2.native(), p.native()).get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::delete_self));
        BOOST_REQUIRE(find_event(events, w2, fsnotifier::flags::move_to, p.filename().native()));
    }
}

ACTOR_THREAD_TEST_CASE(test_notify_create_delete_child) {
    tmpdir tmp;
    fsnotifier fsn;

    auto p = tmp.path() / "kossa.dat";
    auto w =
        fsn.create_watch(tmp.path().native(), fsnotifier::flags::create_child | fsnotifier::flags::delete_child).get0();

    auto f = open_file_dma(p.native(), open_flags::create | open_flags::rw).get0();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::create_child));
    }

    f.close().get();
    remove_file(p.native()).get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::delete_child));
        BOOST_REQUIRE(!find_event(events, w, fsnotifier::flags::ignored));
    }
}

ACTOR_THREAD_TEST_CASE(test_notify_open) {
    tmpdir tmp;
    fsnotifier fsn;

    auto p = tmp.path() / "kossa.dat";
    auto f = open_file_dma(p.native(), open_flags::create | open_flags::rw).get0();
    f.close().get();

    auto w = fsn.create_watch(p.native(), fsnotifier::flags::open).get0();

    auto f2 = open_file_dma(p.native(), open_flags::ro).get0();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::open));
    }

    f2.close().get();
}

ACTOR_THREAD_TEST_CASE(test_notify_move) {
    tmpdir tmp;
    fsnotifier fsn;

    auto p = tmp.path() / "kossa.dat";
    auto f = open_file_dma(p.native(), open_flags::create | open_flags::rw).get0();

    f.close().get();

    auto w = fsn.create_watch(tmp.path().native(), fsnotifier::flags::move).get0();
    auto p2 = tmp.path() / "kossa.mu";

    rename_file(p.native(), p2.native()).get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::move_from, p.filename().native()));
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::move_to, p2.filename().native()));
    }

    tmpdir tmp2;
    auto p3 = tmp2.path() / "ninja.mission";
    auto w2 = fsn.create_watch(tmp2.path().native(), fsnotifier::flags::move).get0();

    rename_file(p2.native(), p3.native()).get();

    {
        auto events = fsn.wait().get0();
        BOOST_REQUIRE(find_event(events, w, fsnotifier::flags::move_from, p2.filename().native()));
        BOOST_REQUIRE(find_event(events, w2, fsnotifier::flags::move_to, p3.filename().native()));
    }
}

ACTOR_THREAD_TEST_CASE(test_shutdown_notifier) {
    tmpdir tmp;
    fsnotifier fsn;

    auto p = tmp.path() / "kossa.dat";
    auto f = open_file_dma(p.native(), open_flags::create | open_flags::rw).get0();

    f.close().get();

    auto w = fsn.create_watch(tmp.path().native(), fsnotifier::flags::delete_child).get0();
    auto fut = fsn.wait();

    fsn.shutdown();

    auto events = fut.get0();
    BOOST_REQUIRE(events.empty());
}
