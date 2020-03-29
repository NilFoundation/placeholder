//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/uri.hpp>

#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/deserializer.hpp>
#include <nil/actor/detail/append_percent_encoded.hpp>
#include <nil/actor/detail/fnv_hash.hpp>
#include <nil/actor/detail/overload.hpp>
#include <nil/actor/detail/parse.hpp>
#include <nil/actor/detail/parser/read_uri.hpp>
#include <nil/actor/detail/uri_impl.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/expected.hpp>
#include <nil/actor/make_counted.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/serializer.hpp>

namespace nil {
    namespace actor {

        uri::uri() : impl_(&detail::uri_impl::default_instance) {
            // nop
        }

        uri::uri(impl_ptr ptr) : impl_(std::move(ptr)) {
            ACTOR_ASSERT(impl_ != nullptr);
        }

        bool uri::empty() const noexcept {
            return str().empty();
        }

        string_view uri::str() const noexcept {
            return impl_->str;
        }

        string_view uri::scheme() const noexcept {
            return impl_->scheme;
        }

        const uri::authority_type &uri::authority() const noexcept {
            return impl_->authority;
        }

        string_view uri::path() const noexcept {
            return impl_->path;
        }

        const uri::query_map &uri::query() const noexcept {
            return impl_->query;
        }

        string_view uri::fragment() const noexcept {
            return impl_->fragment;
        }

        size_t uri::hash_code() const noexcept {
            return detail::fnv_hash(str());
        }

        optional<uri> uri::authority_only() const {
            if (empty() || authority().empty())
                return none;
            auto result = make_counted<detail::uri_impl>();
            result->scheme = impl_->scheme;
            result->authority = impl_->authority;
            auto &str = result->str;
            str = impl_->scheme;
            str += "://";
            str += to_string(impl_->authority);
            return uri {std::move(result)};
        }

        // -- comparison ---------------------------------------------------------------

        int uri::compare(const uri &other) const noexcept {
            return str().compare(other.str());
        }

        int uri::compare(string_view x) const noexcept {
            return string_view {str()}.compare(x);
        }

        // -- parsing ------------------------------------------------------------------

        namespace {

            class nop_builder {
            public:
                template<class T>
                nop_builder &scheme(T &&) {
                    return *this;
                }

                template<class T>
                nop_builder &userinfo(T &&) {
                    return *this;
                }

                template<class T>
                nop_builder &host(T &&) {
                    return *this;
                }

                template<class T>
                nop_builder &port(T &&) {
                    return *this;
                }

                template<class T>
                nop_builder &path(T &&) {
                    return *this;
                }

                template<class T>
                nop_builder &query(T &&) {
                    return *this;
                }

                template<class T>
                nop_builder &fragment(T &&) {
                    return *this;
                }
            };

        }    // namespace

        bool uri::can_parse(string_view str) noexcept {
            string_parser_state ps {str.begin(), str.end()};
            nop_builder builder;
            if (ps.consume('<')) {
                detail::parser::read_uri(ps, builder);
                if (ps.code > pec::trailing_character)
                    return false;
                if (!ps.consume('>'))
                    return false;
            } else {
                detail::parser::read_uri(ps, builder);
            }
            return ps.code == pec::success;
        }

        // -- friend functions ---------------------------------------------------------

        error inspect(nil::actor::serializer &dst, uri &x) {
            return inspect(dst, const_cast<detail::uri_impl &>(*x.impl_));
        }

        error inspect(nil::actor::deserializer &src, uri &x) {
            auto impl = make_counted<detail::uri_impl>();
            auto err = inspect(src, *impl);
            if (err == none)
                x = uri {std::move(impl)};
            return err;
        }

        error_code<sec> inspect(nil::actor::binary_serializer &dst, uri &x) {
            return inspect(dst, const_cast<detail::uri_impl &>(*x.impl_));
        }

        error_code<sec> inspect(nil::actor::binary_deserializer &src, uri &x) {
            auto impl = make_counted<detail::uri_impl>();
            auto err = inspect(src, *impl);
            if (err == none)
                x = uri {std::move(impl)};
            return err;
        }

        // -- related free functions ---------------------------------------------------

        std::string to_string(const uri &x) {
            auto x_str = x.str();
            std::string result {x_str.begin(), x_str.end()};
            return result;
        }

        std::string to_string(const uri::authority_type &x) {
            std::string str;
            if (!x.userinfo.empty()) {
                detail::append_percent_encoded(str, x.userinfo);
                str += '@';
            }
            auto f = nil::actor::detail::make_overload(
                [&](const ip_address &addr) {
                    if (addr.embeds_v4()) {
                        str += to_string(addr);
                    } else {
                        str += '[';
                        str += to_string(addr);
                        str += ']';
                    }
                },
                [&](const std::string &host) { detail::append_percent_encoded(str, host); });
            visit(f, x.host);
            if (x.port != 0) {
                str += ':';
                str += std::to_string(x.port);
            }
            return str;
        }

        error parse(string_view str, uri &dest) {
            string_parser_state ps {str.begin(), str.end()};
            parse(ps, dest);
            if (ps.code == pec::success)
                return none;
            return make_error(ps);
        }

        expected<uri> make_uri(string_view str) {
            uri result;
            if (auto err = parse(str, result))
                return err;
            return result;
        }

    }    // namespace actor
}    // namespace nil
