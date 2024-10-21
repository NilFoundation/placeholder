#include <cstdint>
#include <iostream>
#include <type_traits>
#include <boost/tti/tti.hpp>


struct base_field {
    using value_type = uint64_t;
    static constexpr value_type p = 0xFFFFFFFF00000001;
};

struct scalar_field {
    using value_type = uint64_t;
    static constexpr value_type p = 0xFFFFFFFF00000001;
};

struct g1_element {
    using field_type = base_field;
    using field_value_type = typename field_type::value_type;

    field_value_type X, Y;

    static g1_element one() {
        return {42, 17};
    }

    g1_element operator+(const g1_element& other) {
        return {X+other.X, Y+other.Y};
    }

    g1_element operator*(typename scalar_field::value_type a) {
        return {X*a, Y*a};
    }

    friend std::ostream& operator<<(std::ostream& s, g1_element const& a) {
        s << "X:" << a.X << ", Y:" << a.Y;
        return s;
    }
};

struct mnt4;

struct mnt4_g1_group {
    using curve_type = mnt4;
    using field_type = base_field;
    using value_type = g1_element;
};

struct mnt4 {
    using base_field_type = base_field;
    using scalar_field_type = scalar_field;
    using g1_type = mnt4_g1_group;
};

BOOST_TTI_HAS_STATIC_MEMBER_DATA(p)
BOOST_TTI_HAS_TYPE(value_type)
BOOST_TTI_HAS_TYPE(field_type)
BOOST_TTI_HAS_TYPE(curve_type)

template<typename T>
struct is_field {
    static constexpr bool value =
        has_static_member_data_p<T, typename T::value_type const>::value &&
        has_type_value_type<T>::value;
};

template<typename T>
struct is_curve_group {
    static constexpr bool value =
        has_type_curve_type<T>::value &&
        has_type_field_type<T>::value &&
        has_type_value_type<T>::value;
};



template<typename T>
std::enable_if_t<is_field<T>::value, typename T::value_type>
my_random_element()
{
    return 42;
}

template<typename T>
std::enable_if_t<is_curve_group<T>::value, typename T::value_type>
my_random_element()
{
    using scalar_type = typename T::curve_type::scalar_field_type;

    typename scalar_type::value_type scalar = my_random_element<scalar_type>();
    return T::value_type::one() * scalar;
}

int main()
{
    using curve = mnt4;

    auto x = my_random_element<curve::g1_type>();
    std::cout << "My random point: " << x << std::endl;

    return 0;
}
