
#ifndef NIL__TEST__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_TEST_HPP
#define NIL__TEST__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_TEST_HPP

#include <sstream>

#include "../../unit_test/include.hpp"

#include "../../multiprecision/binary_modular_integer_over_array.hpp"

namespace nil {
namespace test {
namespace multiprecision {


/// Runs addition and subtraction unit tests on provided modular 
/// integer type 'IntT', as (mod 17).
template< typename IntT >
inline void test_modular_integer_add_sub_mod_17()
{
	{
		IntT a, b, c;

		a = 10, b = 9, c = 2;
		NIL_CHECK_EQUAL( a + b, c );
		NIL_CHECK_EQUAL( b + a, c );
		NIL_CHECK_EQUAL( c - a, b );
		NIL_CHECK_EQUAL( c - b, a );

		a = 16, b = 1, c = 0;
		NIL_CHECK_EQUAL( a + b, c );
		NIL_CHECK_EQUAL( b + a, c );
		NIL_CHECK_EQUAL( c - a, b );
		NIL_CHECK_EQUAL( c - b, a );

		a = 16, b = 16, c = 15;
		NIL_CHECK_EQUAL( a + b, c );
		NIL_CHECK_EQUAL( b + a, c );
		NIL_CHECK_EQUAL( c - a, b );
		NIL_CHECK_EQUAL( c - b, a );

		a = 9, b = 5, c = 14;
		NIL_CHECK_EQUAL( a + b, c );
		NIL_CHECK_EQUAL( b + a, c );
		NIL_CHECK_EQUAL( c - a, b );
		NIL_CHECK_EQUAL( c - b, a );

		a = 8, b = 0, c = 8;
		NIL_CHECK_EQUAL( a + b, c );
		NIL_CHECK_EQUAL( b + a, c );
		NIL_CHECK_EQUAL( c - a, b );
		NIL_CHECK_EQUAL( c - b, a );
	}
}


/// Runs multiplication unit tests on provided modular integer type 
/// 'IntT', as (mod 17).
template< typename IntT >
inline void test_modular_integer_mul_mod_17()
{
	{
		IntT a, b, c;

		a = 10, b = 7, c = 2;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 5, b = 5, c = 8;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 10, b = 4, c = 6;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 4, b = 4, c = 16;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 7, b = 2, c = 14;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 12, b = 0, c = 0;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 1, b = 14, c = 14;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 16, b = 16, c = 1;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );

		a = 15, b = 15, c = 4;
		NIL_CHECK_EQUAL( a * b, c );
		NIL_CHECK_EQUAL( b * a, c );
	}
}


/// Runs inversion unit tests on provided modular integer type 
/// 'IntT', as (mod 17).
template< typename IntT >
inline void test_modular_integer_inv_mod_17()
{
	{
		IntT a, b;

		a = 10, b = 12;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 2, b = 9;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 3, b = 6;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 4, b = 13;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 5, b = 7;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 1, b = 1;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 15, b = 8;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

		a = 16, b = 16;
		NIL_CHECK_EQUAL( a.inversed(), b );
		NIL_CHECK_EQUAL( b.inversed(), a );

	}
}


/// This class represents a module with value of '17'.
template< typename RawIntT >
struct modulo_17_t
{
	typedef RawIntT type;
	static constexpr type _value = type( 17 );
};


/// Runs tests on "binary_modular_integer_over_array<>" template.
inline void test_binary_modular_integer_over_array()
{
	using nil::multiprecision::binary_modular_integer_over_array;
	using nil::multiprecision::binary_integer_over_array;

	{
		typedef binary_integer_over_array< unsigned char, 4, unsigned short > 
				raw_int_t;
		typedef binary_modular_integer_over_array< raw_int_t, modulo_17_t< raw_int_t > >
				int_t;

		test_modular_integer_add_sub_mod_17< int_t >();
		test_modular_integer_mul_mod_17< int_t >();
		test_modular_integer_inv_mod_17< int_t >();




	}

	{
		typedef binary_integer_over_array< unsigned short, 4, unsigned int > 
				raw_int_t;
		typedef binary_modular_integer_over_array< raw_int_t, modulo_17_t< raw_int_t > >
				int_t;

		test_modular_integer_add_sub_mod_17< int_t >();
		test_modular_integer_mul_mod_17< int_t >();
		test_modular_integer_inv_mod_17< int_t >();



	}
}



}
}
}

#endif // NIL__TEST__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_TEST_HPP
