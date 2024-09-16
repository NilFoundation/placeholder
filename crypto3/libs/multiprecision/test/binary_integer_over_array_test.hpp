
#ifndef NIL__TEST__MULTIPRECISION__BINARY_INTEGER_OVER_ARRAY_TEST_HPP
#define NIL__TEST__MULTIPRECISION__BINARY_INTEGER_OVER_ARRAY_TEST_HPP

#include <sstream>

#include "../../unit_test/include.hpp"

#include "../../multiprecision/binary_integer_over_array.hpp"

namespace nil {
namespace test {
namespace multiprecision {


/// Runs addition and subtraction unit tests on provided type 'IntT'.
template< typename IntT >
inline void test_big_integer_add_sub()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// Regular addition and subtraction
	{
		IntT a( (dbl_limb_type)1'000 ), b( (dbl_limb_type)2'000 );
		IntT c( (dbl_limb_type)3'000 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a( (dbl_limb_type)527 ), b( (dbl_limb_type)179 );
		IntT c( (dbl_limb_type)706 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a( (dbl_limb_type)321 ), b( (dbl_limb_type)123 );
		IntT c( (dbl_limb_type)444 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a( (dbl_limb_type)998 ), b( (dbl_limb_type)997 );
		IntT c( (dbl_limb_type)1995 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}

	// Duplicating values
	{
		IntT a( (dbl_limb_type)144 );
		IntT b( a );
		IntT c( (dbl_limb_type)288 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a( (dbl_limb_type)2'018 );
		IntT b( a );
		IntT c( (dbl_limb_type)4'036 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}

	// Adding zero
	{
		IntT a( (dbl_limb_type)384 ), b( (dbl_limb_type)0 );
		IntT c( (dbl_limb_type)384 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a( (dbl_limb_type)0 ), b( (dbl_limb_type)0 );
		IntT c( (dbl_limb_type)0 );

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
}


/// Runs addition and subtraction unit tests on provided type 'IntT'.
/// The provided type is expected to hold integer data by limbs, 
/// each of 8 bits.
template< typename IntT >
inline void test_8_bit_big_integer_add_sub()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// "Digit"-based operations
	{
		IntT a({ 255, 255 }), b({ 255, 255 });
		IntT c({ 1, 255, 254 });

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a({ 5, 187, 203 }), b({ 167, 219, 42 });
		IntT c({ 173, 150, 245 });

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a({ 255, 255, 255 }), b({ 1 });
		IntT c({ 1, 0, 0, 0 });

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
	{
		IntT a({ 204, 10, 203 }), b({ 20, 198, 35 });
		IntT c({ 224, 208, 238 });

		NIL_CHECK_EQUAL( a+b, c );
		NIL_CHECK_EQUAL( b+a, c );
		NIL_CHECK_EQUAL( c-a, b );
		NIL_CHECK_EQUAL( c-b, a );
	}
}


/// Runs multiplication, division, modulo unit tests on provided type 'IntT'.
template< typename IntT >
inline void test_big_integer_mul_div_mod()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// Regular mult, div (without remainder)
	{
		dbl_limb_type a, b;
		unsigned long long c;

		a = 503;
		b = 72;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 82;
		b = 14;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 128;
		b = 127;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 17'006;
		b = 12;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 39;
		b = 3'459;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 17'006;
		b = 3'459;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 1;
		b = 6'083;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );

		a = 7'094;
		b = 0;
		c = (unsigned long long)a * b;

		NIL_CHECK_EQUAL( IntT(a) * IntT(b), IntT(c) );
		NIL_CHECK_EQUAL( IntT(b) * IntT(a), IntT(c) );
		NIL_CHECK_EQUAL( IntT(c) / IntT(a), IntT(b) );
		//NIL_CHECK_EQUAL( IntT(c) / IntT(b), IntT(a) );  // can't divide over 0
		NIL_CHECK_EQUAL( IntT(c) % IntT(a), IntT() );
		//NIL_CHECK_EQUAL( IntT(c) % IntT(b), IntT() );  // can't divide over 0
	}

	// Regular division, modulo and mult.
	{
		dbl_limb_type a, b, quot, mod;

		a = 12'053;
		b = 706;
		quot = a / b;
		mod = a % b;

		NIL_CHECK_EQUAL( IntT(a) / IntT(b), IntT(quot) );
		NIL_CHECK_EQUAL( IntT(a) % IntT(b), IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a), IntT(b) * IntT(quot) + IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a) - IntT(mod), IntT(quot) * IntT(b) );
		NIL_CHECK_EQUAL( (IntT(a) - IntT(mod)) / IntT(quot), IntT(b) );

		a = 50'003;
		b = 15'034;
		quot = a / b;
		mod = a % b;

		NIL_CHECK_EQUAL( IntT(a) / IntT(b), IntT(quot) );
		NIL_CHECK_EQUAL( IntT(a) % IntT(b), IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a), IntT(b) * IntT(quot) + IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a) - IntT(mod), IntT(quot) * IntT(b) );
		NIL_CHECK_EQUAL( (IntT(a) - IntT(mod)) / IntT(quot), IntT(b) );
		NIL_CHECK_EQUAL( IntT(a) - IntT(mod), IntT(quot) * IntT(b) );
		NIL_CHECK_EQUAL( (IntT(a) - IntT(mod)) / IntT(quot), IntT(b) );

		a = 48'006;
		b = 1;
		quot = a / b;
		mod = a % b;

		NIL_CHECK_EQUAL( IntT(a) / IntT(b), IntT(quot) );
		NIL_CHECK_EQUAL( IntT(a) % IntT(b), IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a), IntT(b) * IntT(quot) + IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a) - IntT(mod), IntT(quot) * IntT(b) );
		NIL_CHECK_EQUAL( (IntT(a) - IntT(mod)) / IntT(quot), IntT(b) );

		a = 48'005;
		b = 2;
		quot = a / b;
		mod = a % b;

		NIL_CHECK_EQUAL( IntT(a) / IntT(b), IntT(quot) );
		NIL_CHECK_EQUAL( IntT(a) % IntT(b), IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a), IntT(b) * IntT(quot) + IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a) - IntT(mod), IntT(quot) * IntT(b) );
		NIL_CHECK_EQUAL( (IntT(a) - IntT(mod)) / IntT(quot), IntT(b) );

		a = 839;
		b = 839;
		quot = a / b;
		mod = a % b;

		NIL_CHECK_EQUAL( IntT(a) / IntT(b), IntT(quot) );
		NIL_CHECK_EQUAL( IntT(a) % IntT(b), IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a), IntT(b) * IntT(quot) + IntT(mod) );

		a = 1'056;
		b = 2'008;
		quot = a / b;
		mod = a % b;

		NIL_CHECK_EQUAL( IntT(a) / IntT(b), IntT(quot) );
		NIL_CHECK_EQUAL( IntT(a) % IntT(b), IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a), IntT(b) * IntT(quot) + IntT(mod) );
		NIL_CHECK_EQUAL( IntT(a) - IntT(mod), IntT(quot) * IntT(b) );
		//NIL_CHECK_EQUAL( (IntT(a) - IntT(mod)) / IntT(quot), IntT(b) );
				// This check is skipped here
	}

	// Test chains of multiplication / division
	{
		dbl_limb_type a;

		a = 12'053;

		NIL_CHECK_EQUAL( IntT(a) * IntT(2) / IntT(2) * IntT(3) / IntT(3), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(2) * IntT(3) / IntT(6), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(5) * IntT(17) / IntT(5) / IntT(17), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(42) * IntT(98) / IntT(42) / IntT(49) / IntT(2), IntT(a) );

		a = 5'026;

		NIL_CHECK_EQUAL( IntT(a) * IntT(2) / IntT(2) * IntT(3) / IntT(3), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(2) * IntT(3) / IntT(6), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(5) * IntT(17) / IntT(5) / IntT(17), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(42) * IntT(98) / IntT(42) / IntT(49) / IntT(2), IntT(a) );

		a = 9;

		NIL_CHECK_EQUAL( IntT(a) * IntT(2) / IntT(2) * IntT(3) / IntT(3), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(2) * IntT(3) / IntT(6), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(5) * IntT(17) / IntT(5) / IntT(17), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(42) * IntT(98) / IntT(42) / IntT(49) / IntT(2), IntT(a) );

		a = 0;

		NIL_CHECK_EQUAL( IntT(a) * IntT(2) / IntT(2) * IntT(3) / IntT(3), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(2) * IntT(3) / IntT(6), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(5) * IntT(17) / IntT(5) / IntT(17), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(42) * IntT(98) / IntT(42) / IntT(49) / IntT(2), IntT(a) );

		a = 1;

		NIL_CHECK_EQUAL( IntT(a) * IntT(2) / IntT(2) * IntT(3) / IntT(3), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(2) * IntT(3) / IntT(6), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(5) * IntT(17) / IntT(5) / IntT(17), IntT(a) );
		NIL_CHECK_EQUAL( IntT(a) * IntT(42) * IntT(98) / IntT(42) / IntT(49) / IntT(2), IntT(a) );
	}

}


/// Runs increment and decrement unit tests on provided integer type 'IntT'.
template< typename IntT >
inline void test_big_integer_inc_dec()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// Regular increments and decrements
	{
		dbl_limb_type a_raw;
		IntT a;

		a_raw = 5'046;
		a = a_raw;

		++a;
		++a;
		a_raw += 2;
		NIL_CHECK_EQUAL( a, IntT(a_raw) );
		++a;
		++a;
		a_raw += 2;
		NIL_CHECK_EQUAL( a, IntT(a_raw) );
		--a;
		--a_raw;
		NIL_CHECK_EQUAL( a, IntT(a_raw) );
		--a;
		--a;
		a_raw -= 2;
		NIL_CHECK_EQUAL( a, IntT(a_raw) );
	}

	// Inc, dec near zero
	{
		dbl_limb_type a_raw;
		IntT a;

		a_raw = 0;
		a = a_raw;

		++a;
		a++;
		a--;
		--a;
		NIL_CHECK_EQUAL( a, IntT() );

		a++;
		++a;
		a_raw += 2;
		NIL_CHECK_EQUAL( a, IntT(a_raw) );

		a--;
		--a_raw;
		NIL_CHECK_EQUAL( a, IntT(a_raw) );
	}
}


/// Runs increment and decrement unit tests on provided integer type 'IntT', 
/// which is expected to habe 8-bit limb.
template< typename IntT >
inline void test_8_bit_big_integer_inc_dec()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// Inc, dec with carries
	{
		IntT a({ 255, 254 }), b({ 255, 255 }), c({ 1, 0, 0 });

		++a;
		NIL_CHECK_EQUAL( a, b );
		++a;
		NIL_CHECK_EQUAL( a, c );

		++a;
		NIL_CHECK_NOT_EQUAL( a, c );
		--a;
		NIL_CHECK_EQUAL( a, c );

		a--;
		a--;

		--b;
		NIL_CHECK_EQUAL( a, b );
		--b;
		NIL_CHECK_NOT_EQUAL( a, b );
	}
}


/// Runs various bit shifts on provided integer type 'IntT'.
template< typename IntT >
inline void test_big_integer_bit_shifts()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// Regular bit shifts
	{
		//dbl_limb_type a_raw;
		IntT a;

		a = (dbl_limb_type)5;
		a <<= 1;
		NIL_CHECK_EQUAL( a, IntT(10) );

		a <<= 4;
		NIL_CHECK_EQUAL( a, IntT(10 * 16) );

		a <<= 5;
		NIL_CHECK_EQUAL( a, IntT(10 * 16 * 32) );

		a >>= 2;
		NIL_CHECK_EQUAL( a, IntT(10 * 16 * 8) );

		a >>= 4;
		NIL_CHECK_EQUAL( a, IntT(10 * 8) );

		a >>= 2;
		NIL_CHECK_EQUAL( a, IntT(10 * 2) );

		a >>= 4;
		NIL_CHECK_EQUAL( a, IntT(1) );

		a >>= 1;
		NIL_CHECK_EQUAL( a, IntT(0) );

		a <<= 3;
		NIL_CHECK_EQUAL( a, IntT(0) );
	}

	// Random checks
	{
		IntT a = 51'056;
		NIL_CHECK_NOT_EQUAL( a >> 1, a );
		NIL_CHECK_EQUAL( a >> 1 << 1, a );
		NIL_CHECK_EQUAL( a << 1 >> 1, a );

		a = 512 + 64;
		NIL_CHECK_EQUAL( a >> 1 >> 1, a >> 2 );
		NIL_CHECK_EQUAL( a << 2, a << 1 << 1 );
		NIL_CHECK_NOT_EQUAL( a << 4, a << 2 << 1 );
		NIL_CHECK_EQUAL( a << 3, a << 2 << 1 );
	}

	// ToDo: This unit test must be continued
	//
	//

}


/// Runs various bit operations on provided integer type 'IntT'.
template< typename IntT >
inline void test_big_integer_bit_operations()
{
	typedef typename IntT::limb_type limb_type;
	typedef typename IntT::dbl_limb_type dbl_limb_type;

	// Regular bit checks
	{
		//dbl_limb_type a_raw;
		IntT a;

		a = (dbl_limb_type)5;
		NIL_CHECK( a.test_bit( 2 ) );
		NIL_CHECK( ! a.test_bit( 1 ) );
		NIL_CHECK( a.test_bit( 0 ) );

		a *= (dbl_limb_type)2;
		NIL_CHECK( a.test_bit( 3 ) );
		NIL_CHECK( ! a.test_bit( 2 ) );

		a.set_bit( 0 );
		NIL_CHECK_EQUAL( a, IntT((dbl_limb_type)11) );

		a.unset_bit( 1 );
		NIL_CHECK_EQUAL( a, IntT((dbl_limb_type)9) );

		a.set_bit( 10 );
		NIL_CHECK_EQUAL( a, IntT((dbl_limb_type)(9 + 1024)) );

		a.unset_bit( 10 );
		a.unset_bit( 0 );
		NIL_CHECK_EQUAL( a, IntT((dbl_limb_type)8) );

	}

	// ToDo: This unit test must be continued
	//
	//
}


/// Runs various decimal output operations on provided 
/// integer type 'IntT'.
template< typename IntT >
void test_big_integer_output()
{
	IntT a;
	std::ostringstream ostr;

	// Regular tests
	{
		a = 87;
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "87" );

		a = 1045;
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "1045" );

		a = 58'314;
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "58314" );

		a = 156'001;
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "156001" );

		a = 58'508'124;
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL(ostr.str(), "58508124" );

		a = 1'078'998'004;
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL(ostr.str(), "1078998004" );
	}

	// Specific tests
	{
		a = 8;  // 1-digit
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "8" );

		a = 0;  // zero value
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "0" );

		a = 10'000'000;  // an exponent
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "10000000" );

		a = 9'999;  // one less than an exponent
		ostr.str("");
		ostr << a;
		NIL_CHECK_EQUAL( ostr.str(), "9999" );
	}
}


/// Runs various decimal output operations on provided 
/// integer type 'IntT'.
template< typename IntT >
void test_big_integer_input()
{
	IntT a;
	std::istringstream istr;

	// Regular tests
	{
		istr.seekg( 0 );
		istr.str( "86" );
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(86) );

		istr.seekg( 0 );
		istr.str( "1045" );
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(1'045) );

		istr.seekg( 0 );
		istr.str( "324006" );
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(324'006) );

		istr.seekg( 0 );
		istr.str( "2056345" );
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(2'056'345) );

		istr.seekg( 0 );
		istr.str( "1824500012" );
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(1'824'500'012) );
	}

	// Corner cases
	{
		istr.seekg( 0 );
		istr.str( "5" );  // 1-digit
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(5) );

		istr.seekg( 0 );
		istr.str( "0" );  // zero
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(0) );

		istr.seekg( 0 );
		istr.str( "100000000" );  // an exponent
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(100'000'000) );

		istr.seekg( 0 );
		istr.str( "99999" );  // one less than an exponent
		istr >> a;
		NIL_CHECK_EQUAL( a, IntT(99'999) );
	}

}


/// Runs tests on "binary_integer_over_array<>" template.
inline void test_binary_integer_over_array()
{
	using nil::multiprecision::binary_integer_over_array;

	{
		typedef binary_integer_over_array< unsigned char, 4, unsigned short > 
				int_t;

		test_big_integer_add_sub< int_t >();
		test_8_bit_big_integer_add_sub< int_t >();
		test_big_integer_mul_div_mod< int_t >();
		test_big_integer_inc_dec< int_t >();
		test_8_bit_big_integer_inc_dec< int_t >();
		test_big_integer_bit_shifts< int_t >();
		test_big_integer_bit_operations< int_t >();
		test_big_integer_output< int_t >();
		test_big_integer_input< int_t >();
	}

	{
		typedef binary_integer_over_array< unsigned short, 4, unsigned int > 
				int_t;

		test_big_integer_add_sub< int_t >();
		//test_8_bit_big_integer_add_sub< int_t >();
				// Commented out because this test suite it 
				// intended for 8-bit limbs.
		test_big_integer_mul_div_mod< int_t >();
		test_big_integer_inc_dec< int_t >();
		//test_8_bit_big_integer_inc_dec< int_t >();
				// Commented out for the same reason.
		test_big_integer_bit_shifts< int_t >();
		test_big_integer_bit_operations< int_t >();
		test_big_integer_output< int_t >();
		test_big_integer_input< int_t >();
	}
}


}
}
}

#endif // NIL__TEST__MULTIPRECISION__BINARY_INTEGER_OVER_ARRAY_TEST_HPP
