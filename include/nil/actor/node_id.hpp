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

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include <nil/actor/detail/comparable.hpp>

#include <nil/actor/fwd.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/none.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/uri.hpp>

namespace nil {
    namespace actor {

        /// A node ID is an opaque value for representing spawner instances in the network.
        class BOOST_SYMBOL_VISIBLE node_id {
        public:
            // -- member types -----------------------------------------------------------

            // A reference counted, implementation-specific implementation of a node ID.
            class BOOST_SYMBOL_VISIBLE data : public ref_counted {
            public:
                ~data() override;

                virtual bool valid() const noexcept = 0;

                virtual size_t hash_code() const noexcept = 0;

                virtual uint8_t implementation_id() const noexcept = 0;

                virtual int compare(const data &other) const noexcept = 0;

                virtual void print(std::string &dst) const = 0;

                virtual error serialize(serializer &sink) const = 0;

                virtual error deserialize(deserializer &source) = 0;

                virtual error_code<sec> serialize(binary_serializer &sink) const = 0;

                virtual error_code<sec> deserialize(binary_deserializer &source) = 0;
            };

            // A technology-agnostic node identifier with process ID and hash value.
            class BOOST_SYMBOL_VISIBLE default_data final : public data {
            public:
                // -- constants ------------------------------------------------------------

                /// A 160 bit hash (20 bytes).
                static constexpr size_t host_id_size = 20;

                /// Identifies this data implementation type.
                static constexpr uint8_t class_id = 1;

                // -- member types ---------------------------------------------------------

                /// Represents a 160 bit hash.
                using host_id_type = std::array<uint8_t, host_id_size>;

                // -- constructors, destructors, and assignment operators ------------------

                default_data();

                default_data(uint32_t pid, const host_id_type &host);

                // -- factory functions ----------------------------------------------------

                /// Returns an ID for this node.
                static node_id local(const spawner_config &cfg);

                // -- properties -----------------------------------------------------------

                uint32_t process_id() const noexcept {
                    return pid_;
                }

                const host_id_type host_id() const noexcept {
                    return host_;
                }

                // -- utility functions ----------------------------------------------------

                static bool valid(const host_id_type &x) noexcept;

                static bool can_parse(string_view str) noexcept;

                // -- interface implementation ---------------------------------------------

                bool valid() const noexcept override;

                size_t hash_code() const noexcept override;

                uint8_t implementation_id() const noexcept override;

                int compare(const data &other) const noexcept override;

                void print(std::string &dst) const override;

                error serialize(serializer &sink) const override;

                error deserialize(deserializer &source) override;

                error_code<sec> serialize(binary_serializer &sink) const override;

                error_code<sec> deserialize(binary_deserializer &source) override;

            private:
                // -- member variables -----------------------------------------------------

                uint32_t pid_;

                host_id_type host_;
            };

            // A technology-agnostic node identifier using an URI.
            class BOOST_SYMBOL_VISIBLE uri_data final : public data {
            public:
                // -- constants ------------------------------------------------------------

                /// Identifies this data implementation type.
                static constexpr uint8_t class_id = 2;

                // -- constructors, destructors, and assignment operators ------------------

                uri_data() = default;

                explicit uri_data(uri value);

                // -- properties -----------------------------------------------------------

                const uri &value() const noexcept {
                    return value_;
                }

                // -- interface implementation ---------------------------------------------

                bool valid() const noexcept override;

                size_t hash_code() const noexcept override;

                uint8_t implementation_id() const noexcept override;

                int compare(const data &other) const noexcept override;

                void print(std::string &dst) const override;

                error serialize(serializer &sink) const override;

                error deserialize(deserializer &source) override;

                error_code<sec> serialize(binary_serializer &sink) const override;

                error_code<sec> deserialize(binary_deserializer &source) override;

            private:
                // -- member variables -----------------------------------------------------

                uri value_;
            };

            // -- constructors, destructors, and assignment operators --------------------

            constexpr node_id() noexcept {
                // nop
            }

            explicit node_id(intrusive_ptr<data> dataptr);

            node_id &operator=(const none_t &);

            node_id(node_id &&) = default;

            node_id(const node_id &) = default;

            node_id &operator=(node_id &&) = default;

            node_id &operator=(const node_id &) = default;

            ~node_id();

            // -- properties -------------------------------------------------------------

            /// Queries whether this node is not default-constructed.
            explicit operator bool() const;

            /// Compares this instance to `other`.
            /// @returns -1 if `*this < other`, 0 if `*this == other`, and 1 otherwise.
            int compare(const node_id &other) const noexcept;

            /// Exchanges the value of this object with `other`.
            void swap(node_id &other);

            /// @cond PRIVATE

            data *operator->() noexcept {
                return data_.get();
            }

            const data *operator->() const noexcept {
                return data_.get();
            }

            data &operator*() noexcept {
                return *data_;
            }

            const data &operator*() const noexcept {
                return *data_;
            }

            /// @endcond

            /// Returns whether `parse` would produce a valid node ID.
            static bool can_parse(string_view str) noexcept;

            /// @relates node_id
            friend BOOST_SYMBOL_VISIBLE error inspect(serializer &sink, node_id &x);

            /// @relates node_id
            friend BOOST_SYMBOL_VISIBLE error_code<sec> inspect(binary_serializer &sink, node_id &x);

            /// @relates node_id
            friend BOOST_SYMBOL_VISIBLE error inspect(deserializer &source, node_id &x);

            /// @relates node_id
            friend BOOST_SYMBOL_VISIBLE error_code<sec> inspect(binary_deserializer &source, node_id &x);

        private:
            intrusive_ptr<data> data_;
        };

        /// Returns whether `x` contains an URI.
        /// @relates node_id
        inline bool wraps_uri(const node_id &x) noexcept {
            return x && x->implementation_id() == node_id::uri_data::class_id;
        }

        /// @relates node_id
        inline bool operator==(const node_id &x, const node_id &y) noexcept {
            return x.compare(y) == 0;
        }

        /// @relates node_id
        inline bool operator!=(const node_id &x, const node_id &y) noexcept {
            return x.compare(y) != 0;
        }

        /// @relates node_id
        inline bool operator<(const node_id &x, const node_id &y) noexcept {
            return x.compare(y) < 0;
        }

        /// @relates node_id
        inline bool operator<=(const node_id &x, const node_id &y) noexcept {
            return x.compare(y) <= 0;
        }

        /// @relates node_id
        inline bool operator>(const node_id &x, const node_id &y) noexcept {
            return x.compare(y) > 0;
        }

        /// @relates node_id
        inline bool operator>=(const node_id &x, const node_id &y) noexcept {
            return x.compare(y) >= 0;
        }

        /// @relates node_id
        inline bool operator==(const node_id &x, const none_t &) noexcept {
            return !x;
        }

        /// @relates node_id
        inline bool operator==(const none_t &, const node_id &x) noexcept {
            return !x;
        }

        /// @relates node_id
        inline bool operator!=(const node_id &x, const none_t &) noexcept {
            return static_cast<bool>(x);
        }

        /// @relates node_id
        inline bool operator!=(const none_t &, const node_id &x) noexcept {
            return static_cast<bool>(x);
        }

        /// Appends `x` in human-readable string representation to `str`.
        /// @relates node_id
        BOOST_SYMBOL_VISIBLE void append_to_string(std::string &str, const node_id &x);

        /// Converts `x` into a human-readable string representation.
        /// @relates node_id
        BOOST_SYMBOL_VISIBLE std::string to_string(const node_id &x);

        /// Creates a node ID from the URI `from`.
        /// @relates node_id
        BOOST_SYMBOL_VISIBLE node_id make_node_id(uri from);

        /// Creates a node ID from `process_id` and `host_id`.
        /// @param process_id System-wide unique process identifier.
        /// @param host_id Unique hash value representing a single =nil; Actor node.
        /// @relates node_id
        BOOST_SYMBOL_VISIBLE node_id make_node_id(uint32_t process_id,
                                                  const node_id::default_data::host_id_type &host_id);

        /// Creates a node ID from `process_id` and `host_hash`.
        /// @param process_id System-wide unique process identifier.
        /// @param host_hash Unique node ID as hexadecimal string representation.
        /// @relates node_id
        BOOST_SYMBOL_VISIBLE optional<node_id> make_node_id(uint32_t process_id, string_view host_hash);

        /// @relates node_id
        BOOST_SYMBOL_VISIBLE error parse(string_view str, node_id &dest);

    }    // namespace actor
}    // namespace nil

namespace std {

    template<>
    struct hash<nil::actor::node_id> {
        size_t operator()(const nil::actor::node_id &x) const noexcept {
            return x ? x->hash_code() : 0;
        }
    };

}    // namespace std
