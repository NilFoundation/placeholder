#ifndef PARALLEL_CRYPTO3_ZK_KIMCHI_FUNCTIONS
#define PARALLEL_CRYPTO3_ZK_KIMCHI_FUNCTIONS

#ifdef CRYPTO3_ZK_KIMCHI_FUNCTIONS
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct kimchi_functions {
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;

                    static typename scalar_field_type::value_type
                    shift_scalar(const typename scalar_field_type::value_type &x) {
                        typename scalar_field_type::value_type two = typename scalar_field_type::value_type(2);
                        typename scalar_field_type::value_type two_pow = two.pow(scalar_field_type::modulus_bits);
                        if (scalar_field_type::modulus < base_field_type::modulus) {
                            return (x - (two_pow + scalar_field_type::value_type::one())) / two;
                        } else {
                            return x - two_pow;
                        }
                    }
                };
            }
        }
    }
}

#endif
