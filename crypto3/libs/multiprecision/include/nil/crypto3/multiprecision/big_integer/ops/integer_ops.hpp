//---------------------------------------------------------------------------//
//  Copyright 2024 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// We need to include this file after modular adaptor, in order for these functions to 'see'
//---------------------------------------------------------------------------//

#pragma once

#include <boost/multiprecision/number.hpp>

namespace nil::crypto3::multiprecision {
    // TODO

    // // Only for our modular numbers function powm takes 2 arguments,
    // // so we need to add this specialization.
    // template<class Backend, class modular_params_type, class U>
    // inline constexpr
    //     typename std::enable_if<detail::is_backend<Backend>::value && is_integral<U>::value,
    //                             number<boost::multiprecision::backends::modular_adaptor<
    //                                 Backend, modular_params_type>>>::type
    //     powm(const number<
    //              boost::multiprecision::backends::modular_adaptor<Backend, modular_params_type>>&
    //              b,
    //          const U& p) {
    //     // We will directly call eval_powm here, that's what a call through a
    //     // default_ops::powm_func would do if expression tempaltes are off. We don't want to
    //     // change that structure.
    //     boost::multiprecision::backends::modular_adaptor<Backend, modular_params_type> result;
    //     result.set_modular_params(b.backend().mod_data());
    //     boost::multiprecision::backends::eval_powm(result, b.backend(), p);
    //     return result;
    // }

    // template<class Backend, class modular_params_type, class U>
    // inline constexpr
    //     typename std::enable_if<(detail::is_backend<Backend>::value &&
    //                              (is_number<U>::value || is_number_expression<U>::value)),
    //                             number<boost::multiprecision::backends::modular_adaptor<
    //                                 Backend, modular_params_type>>>::type
    //     powm(const number<
    //              boost::multiprecision::backends::modular_adaptor<Backend, modular_params_type>>&
    //              b,
    //          const U& p) {
    //     // We will directly call eval_powm here, that's what a call through a
    //     // default_ops::powm_func would do if expression tempaltes are off. We don't want to
    //     // change that structure.
    //     boost::multiprecision::backends::modular_adaptor<Backend, modular_params_type> result;
    //     result.set_modular_params(b.backend().mod_data());
    //     boost::multiprecision::backends::eval_powm(result, b.backend(), p.backend());
    //     return result;
    // }
}  // namespace nil::crypto3::multiprecision
