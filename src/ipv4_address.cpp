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

#include <nil/actor/ipv4_address.hpp>

#include <nil/actor/detail/network_order.hpp>
#include <nil/actor/detail/parser/read_ipv4_address.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/pec.hpp>
#include <nil/actor/string_view.hpp>

namespace nil {
    namespace actor {

        namespace {

            inline uint32_t net_order(uint32_t value) {
                return detail::to_network_order(value);
            }

            struct ipv4_address_consumer {
                ipv4_address &dest;

                ipv4_address_consumer(ipv4_address &ref) : dest(ref) {
                    // nop
                }

                void value(ipv4_address val) {
                    dest = val;
                }
            };

        }    // namespace

        // -- constructors, destructors, and assignment operators ----------------------

        ipv4_address::ipv4_address() {
            bits_ = 0u;
        }

        ipv4_address::ipv4_address(array_type bytes) {
            memcpy(bytes_.data(), bytes.data(), bytes.size());
        }

        // -- properties ---------------------------------------------------------------

        bool ipv4_address::is_loopback() const noexcept {
            // All addresses in 127.0.0.0/8 are considered loopback addresses.
            return (bits_ & net_order(0xFF000000)) == net_order(0x7F000000);
        }

        bool ipv4_address::is_multicast() const noexcept {
            // All addresses in 224.0.0.0/4 are considered multicast addresses.
            return (bits_ & net_order(0xF0000000)) == net_order(0xE0000000);
        }

        // -- related free functions ---------------------------------------------------

        ipv4_address make_ipv4_address(uint8_t oct1, uint8_t oct2, uint8_t oct3, uint8_t oct4) {
            ipv4_address::array_type bytes {{oct1, oct2, oct3, oct4}};
            return ipv4_address {bytes};
        }

        std::string to_string(const ipv4_address &x) {
            using std::to_string;
            std::string result;
            result += to_string(x[0]);
            for (size_t i = 1; i < x.data().size(); ++i) {
                result += '.';
                result += to_string(x[i]);
            }
            return result;
        }

        error parse(string_view str, ipv4_address &dest) {
            using namespace detail;
            parser::state<string_view::iterator> res {str.begin(), str.end()};
            ipv4_address_consumer f {dest};
            parser::read_ipv4_address(res, f);
            if (res.code == pec::success)
                return none;
            return make_error(res.code, static_cast<size_t>(res.line), static_cast<size_t>(res.column));
        }

    }    // namespace actor
}    // namespace nil
