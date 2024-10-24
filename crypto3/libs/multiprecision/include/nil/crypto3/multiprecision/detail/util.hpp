
#ifndef NIL__MULTIPRECISION__DETAIL__UTIL_HPP
#define NIL__MULTIPRECISION__DETAIL__UTIL_HPP

#include <bitset>
#include <cstdlib>
#include <cassert>

namespace nil {
namespace multiprecision {
namespace detail {


/// This class contains utility functions, for working with multiprecision 
/// objects.
class util
{
public:
	/// Given the 'value', represented as sequence of binary limbs, calculates 
	/// and returns the required minimal amount of bits, to represent such 
	/// 'value'. Generally, this is overall number of bits in 'value', subtracted 
	/// by the number of leading 0 bits.
	template< typename BigIntegerType >
	static constexpr size_t obtain_bits_count( const BigIntegerType& value ) {
		// Some typedefs & constants
		typedef typename BigIntegerType::limb_type limb_type;
		constexpr auto _limbs_count = BigIntegerType::_limbs_count;
		constexpr auto _limb_bits = BigIntegerType::_limb_bits;
		// Process
		size_t result = _limbs_count * _limb_bits;
		for ( int limb_index = _limbs_count - 1; limb_index >= 0; --limb_index ) {
			const limb_type& limb = value[ limb_index ];
			for ( int limb_bit = _limb_bits - 1; limb_bit >= 0; --limb_bit ) {
				if ( ! (limb & (((limb_type)1) << limb_bit)) )
					--result;
				else
					return result;
			}
		}
		assert( ! "The previous return statement should be invoked, if at least"
				" one bit of 'value' is set." );
		assert( result == 0 );
		return result;
	}

	/// Calculates and returns pure binary representation of 'value'.
	/// Generally, 'value' is already stored in binary format, but in different limbs.
	/// This function converts the sequence of limbs into sequence of bits, 
	/// and returns as 'std::bitset<>'.
	/// 0-th bit of the result corresponds to least significant bit of 'value', 
	/// while the last bit of the result corresponds to most significant bit of 'value'.
	template< size_t Bits, typename BigIntegerType >
	static constexpr std::bitset< Bits > obtain_bits( const BigIntegerType& value ) {
		// Some typedefs & constants
		typedef typename BigIntegerType::limb_type limb_type;
		constexpr auto _limbs_count = BigIntegerType::_limbs_count;
		constexpr auto _limb_bits = BigIntegerType::_limb_bits;
		// Process
		std::bitset< Bits > result;
		int result_bit_index = 0;  // Index over bits of 'result'
		for ( int limb_index = 0; limb_index < _limbs_count; ++limb_index ) {
			const limb_type& limb = value[ limb_index ];
			for ( int bit_index = 0; bit_index < _limb_bits; ++bit_index ) {
				if ( limb & (((limb_type)1) << bit_index) )
					result.set( result_bit_index );
				++result_bit_index;
			}
		}
		assert( result_bit_index == _limbs_count * _limb_bits );
		return result;
	}

	/// Calculates and returns 'a' powered to such exponent, which bits are 
	/// represented in 'bits' argument.
	/// "bits[0]" corresponds to least significant binary digit of the exponent, 
	///   while "bits[bits.size() - 1]" corresponds to its most significant bit.
	template< typename BigIntegerType, size_t Bits >
	static constexpr BigIntegerType power(
			const BigIntegerType& a,
			const std::bitset< Bits >& bits ) {
		BigIntegerType result( 1 );
		for ( int i = (int)bits.size() - 1; i >= 0; --i ) {
			result *= result;
			if ( bits[ i ] )
				result *= a;
		}
		return result;
	}

};


}
}
}

#endif // NIL__MULTIPRECISION__DETAIL__UTIL_HPP
