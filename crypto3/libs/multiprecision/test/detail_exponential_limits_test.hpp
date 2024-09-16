
#ifndef NIL__TEST__MULTIPRECISION__DETAIL_EXPONENTIAL_LIMITS_TEST_HPP
#define NIL__TEST__MULTIPRECISION__DETAIL_EXPONENTIAL_LIMITS_TEST_HPP

#include "../../unit_test/include.hpp"

#include "../../multiprecision/detail/exponential_limits.hpp"

namespace nil {
namespace test {
namespace multiprecision {


	
/// Runs tests on "detail::exponential_limits<>" template.
inline void test_detail_exponential_limits()
{
	using nil::multiprecision::detail::exponential_limits;

	// Testing for "unsigned char"
	{
		exponential_limits< unsigned char, 10 > limits;

		// Checking precision of the primitive type
		NIL_CHECK_EQUAL( sizeof(unsigned char) * CHAR_BIT, 8 );

		NIL_CHECK_EQUAL( limits.max_power, 100 );
		NIL_CHECK_EQUAL( limits.max_exponent, 2 );
	}

	// Testing for "unsigned short"
	{
		exponential_limits< unsigned short, 10 > limits;

		// Checking precision of the primitive type
		NIL_CHECK_EQUAL( sizeof(unsigned short) * CHAR_BIT, 16 );

		NIL_CHECK_EQUAL( limits.max_power, 10'000 );
		NIL_CHECK_EQUAL( limits.max_exponent, 4 );
	}

	// Testing for "unsigned int"
	{
		exponential_limits< unsigned int, 10 > limits;

		// Checking precision of the primitive type
		NIL_CHECK_EQUAL( sizeof(unsigned int) * CHAR_BIT, 32 );

		NIL_CHECK_EQUAL( limits.max_power, 1'000'000'000 );
		NIL_CHECK_EQUAL( limits.max_exponent, 9 );
	}

}


}
}
}

#endif // NIL__TEST__MULTIPRECISION__DETAIL_EXPONENTIAL_LIMITS_TEST_HPP
