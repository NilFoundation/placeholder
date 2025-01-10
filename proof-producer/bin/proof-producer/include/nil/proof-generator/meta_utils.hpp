//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#ifndef PROOF_GENERATOR_META_UTILS_HPP
#define PROOF_GENERATOR_META_UTILS_HPP

#include <type_traits>
#include <variant>

namespace nil {
    namespace proof_generator {

        // C++20 has it inside std::
        template<typename T>
        struct type_identity {
            using type = T;
        };

        template<typename T>
        struct to_type_identity {
            using type = type_identity<T>;
        };

        template<typename Tuple, template<typename> class MetaFun>
        struct transform_tuple;

        template<typename... Ts, template<typename> class MetaFun>
        struct transform_tuple<std::tuple<Ts...>, MetaFun> {
            using type = std::tuple<typename MetaFun<Ts>::type...>;
        };

        template<typename Tuple>
        struct tuple_to_variant;

        template<typename... Ts>
        struct tuple_to_variant<std::tuple<Ts...>> {
            using type = std::variant<Ts...>;
        };

        template<typename T>
        struct variant_to_tuple;

        template<typename... Ts>
        struct variant_to_tuple<std::variant<Ts...>> {
            using type = std::tuple<Ts...>;
        };


        // Takes variant value and forward its inner type to function template.
        // Example:
        //     using Variant = std::variant<int, double>;
        //     Variant var;
        //     var = 69;
        //     auto func = []<typename template_type>() {
        //         std::cout << typeid(template_type).name();
        //     };
        //     pass_variant_type_to_template_func<Variant>(var, func);
        template<typename Variant, typename Func>
        void pass_variant_type_to_template_func(const Variant& variant, Func&& func) {
            std::visit(
                [&func](auto&& arg) {
                    using CurrentType = std::decay_t<decltype(arg)>;
                    func.template operator()<CurrentType>();
                },
                variant
            );
        }

    } // namespace proof_generator
} // namespace nil

#endif // PROOF_GENERATOR_META_UTILS_HPP
