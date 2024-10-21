#include <iostream>
#include <stdint.h>
#include <boost/tti/tti.hpp>


struct base_field {
    static const uint64_t p = 0xffffffff00000001;
    base_field(uint64_t data): data(data) {};
    base_field operator+(base_field const& a) const {
        return (data+a.data)%p;
    }
    base_field operator*(base_field const& a) const {
        return (data*a.data)%p;
    }
    uint64_t data;
};

struct scalar_field {
    static const uint64_t p = 0xffffffff00000001;
    scalar_field(uint64_t data): data(data) {};
    scalar_field operator+(scalar_field const& a) const {
        return (data+a.data)%p;
    }
    scalar_field operator*(scalar_field const& a) const {
        return (data*a.data)%p;
    }
    uint64_t data;
};

struct ext_field {
    base_field x,y;
    static const base_field r;
    ext_field(base_field const& x, base_field const&y) : x(x), y(y) {};
    ext_field operator+(ext_field const& a) const {
        return { (x+a.x), (y+a.y) };
    }
    ext_field operator*(ext_field const& a) const {
        return { x*a.x+ r*y*a.y, x*a.y+y*a.x };
    }
};

const base_field ext_field::r = base_field::p-1;

struct curve_g1_type {
    base_field x,y;
    curve_g1_type add(const curve_g1_type& a) const {
        return a;
    }
    curve_g1_type dbl() const {
        return *this;
    }
};

struct curve_g2_type {
    ext_field x,y;
    curve_g1_type add(const curve_g1_type& a) const {
        return a;
    }
    curve_g2_type dbl() const {
        return *this;
    }
};

struct curve {
    using g1_type = curve_g1_type;
    using g2_type = curve_g2_type;
};


template <typename, typename = std::void_t<>>
struct has_plus_operator : std::false_type {};
template <typename T>
struct has_plus_operator<T, std::void_t<decltype(std::declval<T>() + std::declval<T>())>> : std::true_type {};

template <typename, typename = std::void_t<>>
struct has_mul_operator : std::false_type {};
template <typename T>
struct has_mul_operator<T, std::void_t<decltype(std::declval<T>() * std::declval<T>())>> : std::true_type {};

BOOST_TTI_HAS_FUNCTION(add)
BOOST_TTI_HAS_FUNCTION(dbl)

template<typename T>
struct is_curve_element {
    static const bool value =
        has_function_add<const T, T>::value &&
        has_function_dbl<const T, T>::value ;
};



int main()
{

    std::cout << has_function_dbl<const typename curve::g1_type, typename curve::g1_type>::value << std::endl;
    std::cout << has_function_add<const typename curve::g1_type, typename curve::g1_type>::value << std::endl;

    std::cout << is_curve_element<typename curve::g1_type>::value << std::endl;
    std::cout << is_curve_element<typename curve::g2_type>::value << std::endl;
    
    std::cout << is_curve_element<base_field>::value << std::endl;
    std::cout << is_curve_element<scalar_field>::value << std::endl;
    std::cout << is_curve_element<ext_field>::value << std::endl;
    return 0;
}
