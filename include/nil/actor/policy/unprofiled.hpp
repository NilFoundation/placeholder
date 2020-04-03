//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/scheduler/abstract_coordinator.hpp>

namespace nil::actor::policy {

    /// This class is intended to be used as a base class for actual polices.
    /// It provides a default empty implementation for the customization points.
    /// By deriving from it, actual policy classes only need to implement/override
    /// the customization points they need. This class also serves as a place to
    /// factor common utilities for implementing actual policies.
    class BOOST_SYMBOL_VISIBLE unprofiled {
    public:
        virtual ~unprofiled();

        /// Performs cleanup action before a shutdown takes place.
        template<class Worker>
        void before_shutdown(Worker *) {
            // nop
        }

        /// Called immediately before resuming an actor.
        template<class Worker>
        void before_resume(Worker *, resumable *) {
            // nop
        }

        /// Called whenever an actor has been resumed. This function can
        /// prepare some fields before the next resume operation takes place
        /// or perform cleanup actions between to actor runs.
        template<class Worker>
        void after_resume(Worker *, resumable *) {
            // nop
        }

        /// Called whenever an actor has completed a job.
        template<class Worker>
        void after_completion(Worker *, resumable *) {
            // nop
        }

    protected:
        // Convenience function to access the data field.
        template<class WorkerOrCoordinator>
        static auto d(WorkerOrCoordinator *self) -> decltype(self->data()) {
            return self->data();
        }
    };

}    // namespace nil::actor::policy