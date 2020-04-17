//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/actor_ostream.hpp>

#include <nil/actor/abstract_actor.hpp>
#include <nil/actor/default_attachable.hpp>
#include <nil/actor/scoped_actor.hpp>
#include <nil/actor/send.hpp>

#include <nil/actor/scheduler/abstract_coordinator.hpp>

namespace nil::actor {

    actor_ostream::actor_ostream(local_actor *self) :
        self_(self->id()), printer_(self->home_system().scheduler().printer()) {
        init(self);
    }

    actor_ostream::actor_ostream(scoped_actor &self) :
        self_(self->id()), printer_(self->home_system().scheduler().printer()) {
        init(actor_cast<abstract_actor *>(self));
    }

    actor_ostream &actor_ostream::write(std::string arg) {
        printer_->enqueue(make_mailbox_element(nullptr, make_message_id(), {}, add_atom_v, self_, std::move(arg)),
                          nullptr);
        return *this;
    }

    actor_ostream &actor_ostream::flush() {
        printer_->enqueue(make_mailbox_element(nullptr, make_message_id(), {}, flush_atom_v, self_), nullptr);
        return *this;
    }

    void actor_ostream::redirect(abstract_actor *self, std::string fn, int flags) {
        if (self == nullptr)
            return;
        auto pr = self->home_system().scheduler().printer();
        pr->enqueue(
            make_mailbox_element(nullptr, make_message_id(), {}, redirect_atom_v, self->id(), std::move(fn), flags),
            nullptr);
    }

    void actor_ostream::redirect_all(spawner &sys, std::string fn, int flags) {
        auto pr = sys.scheduler().printer();
        pr->enqueue(make_mailbox_element(nullptr, make_message_id(), {}, redirect_atom_v, std::move(fn), flags),
                    nullptr);
    }

    void actor_ostream::init(abstract_actor *self) {
        if (!self->getf(abstract_actor::has_used_aout_flag))
            self->setf(abstract_actor::has_used_aout_flag);
    }

    actor_ostream aout(local_actor *self) {
        return actor_ostream {self};
    }

    actor_ostream aout(scoped_actor &self) {
        return actor_ostream {self};
    }

}    // namespace nil::actor

namespace std {

    nil::actor::actor_ostream &endl(nil::actor::actor_ostream &o) {
        return o.write("\n");
    }

    nil::actor::actor_ostream &flush(nil::actor::actor_ostream &o) {
        return o.flush();
    }

}    // namespace std
