#include <iostream>
#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>

struct coordinates_affine;
struct coordinates_projective;
struct coordinates_extended;

struct form_short_weierstrass;
struct form_twisted_edwards;

namespace detail {

    /* general */
    template<typename form, typename coordinates>
    struct elliptic_curve_g1;

    template<typename form, typename coordinates>
    struct other_elliptic_curve_g1;

    /* specializations */
    template<>
    struct elliptic_curve_g1<form_short_weierstrass, coordinates_projective> {
        static void printme() { std::cout << "projective coordinates for short weierstrass form ec1" << std::endl; }
    };

    template<>
    struct elliptic_curve_g1<form_short_weierstrass, coordinates_affine> {
        static void printme() { std::cout << "affine coordinates for short weierstrass form ec1" << std::endl; }
    };

    template<>
    struct other_elliptic_curve_g1<form_twisted_edwards, coordinates_extended> {
        static void printme() { std::cout << "extended coordinates for twisted edwards form ec2" << std::endl; }
    };

    template<>
    struct other_elliptic_curve_g1<form_twisted_edwards, coordinates_affine> {
        static void printme() { std::cout << "affine coordinates for twisted edwards form ec2" << std::endl; }
    };
};

struct elliptic_curve_1 {
    template<typename coordinates = coordinates_projective, typename form = form_short_weierstrass>
    using g1_type = typename detail::elliptic_curve_g1<form, coordinates>;
};

struct elliptic_curve_2 {
    template<typename coordinates = coordinates_extended, typename form = form_twisted_edwards>
    using g1_type = typename detail::other_elliptic_curve_g1<form, coordinates>;
};


//BOOST_TTI_HAS_TYPE(g1_type) // has_type_g1_type = false on template types
BOOST_TTI_HAS_TEMPLATE(g1_type) // ?? call to 'has_template_g1_type_detail_mpl_test' is ambiguous

int main()
{
    typename elliptic_curve_1::g1_type<> g1_default;
    typename elliptic_curve_1::g1_type<coordinates_affine> g1_affine;

    g1_default.printme();
    g1_affine.printme();

    typename elliptic_curve_2::g1_type<> other_g1_default;
    typename elliptic_curve_2::g1_type<coordinates_affine> other_g1_affine;
    other_g1_default.printme();
    other_g1_affine.printme();

//    std::cout << "ec1 has g1_type:" << has_type_g1_type<elliptic_curve_1>::value << std::endl; // FALSE
//    std::cout << "ec2 has g1_type:" << has_type_g1_type<elliptic_curve_2>::value << std::endl; // FALSE

    std::cout << "ec1 has template g1_type:" << has_template_g1_type<elliptic_curve_1>::value << std::endl;
    std::cout << "ec2 has template g1_type:" << has_template_g1_type<elliptic_curve_2>::value << std::endl;

    return 0;
}
