
#ifndef NIL__MULTIPRECISION__BINARY_INTEGER_OVER_ARRAY_HPP
#define NIL__MULTIPRECISION__BINARY_INTEGER_OVER_ARRAY_HPP

#include <array>
#include <algorithm>
#include <initializer_list>
#include <ostream>
#include <istream>
#include <cassert>

#include "detail/exponential_limits.hpp"

namespace nil {
namespace multiprecision {


// Turns out, no need for this forward declaration

// Forward declaration of the class.
//template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
//class binary_integer_over_array;


// Forward declarations of some global functions.

// Turns out, no need for this forward declarations.

/// Regular multiplication of big integers with different limbs count.
/// Caller is able to control number of the least significant limbs 
/// of result of multiplication.
//template< unsigned int R, 
//		typename LimbType, unsigned int U1, unsigned int U2, typename DblLimbType >
//binary_integer_over_array< LimbType, R, DblLimbType >
//		multiply_by_limbs( 
//				const binary_integer_over_array< LimbType, U1, DblLimbType >& a,
//				const binary_integer_over_array< LimbType, U2, DblLimbType >& b );

/// Regular multiplication of big integer on a primitive value.
/// Caller is able to control number of the least significant limbs 
/// of result of multiplication.
//template< unsigned int R, 
//		typename LimbType, unsigned int U1, typename DblLimbType >
//binary_integer_over_array< LimbType, R, DblLimbType >
//		multiply_by_limbs( 
//				const binary_integer_over_array< LimbType, U1, DblLimbType >& a,
//				const LimbType b );


/// This class represents a big integer, which stores data as binary 
/// digits in an 'std::array<>' class. This way, the data is sotred in 
/// the stack memory.
template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
class binary_integer_over_array
{
public:
	typedef LimbType limb_type;
	static constexpr unsigned int _limbs_count = LimbsCount;
	typedef DblLimbType dbl_limb_type;

	typedef binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
			this_type;  // Synonym for this class

	/// How many bits there are in a single limb.
	static constexpr unsigned int _limb_bits = sizeof(limb_type) * CHAR_BIT;

protected:
	typedef std::array< limb_type, _limbs_count > limbs_type;

	/// The array, which stores all limbs of the integer.
	/// '_limbs[0]' corresponds to the least significant limb.
	limbs_type _limbs;

protected:
	/// Increments by one the most-significant limbs, starting from 'limb_index'.
	/// This is the same as adding "2^(limb_index * _limb_bits)" to the 
	/// entire number.
	constexpr this_type& increment_from_limb( unsigned int limb_index ) {
		limb_type* ptr = _limbs.data() + limb_index;
		limb_type* const ptr_end = _limbs.data() + _limbs_count;
		for ( ; ptr < ptr_end; ++ptr ) {
			++(*ptr);
			if ( *ptr != 0 )
				break;  // No longer carry
		}
		return *this;
	}

	/// Decrements by one the most-significant limbs, starting from 'limb_index'.
	/// This is the same as subtracting "2^(limb_index * _limb_bits)" from the 
	/// entire number.
	constexpr this_type& decrement_from_limb( unsigned int limb_index ) {
		limb_type* ptr = _limbs.data() + limb_index;
		limb_type* const ptr_end = _limbs.data() + _limbs_count;
		for ( ; ptr < ptr_end; ++ptr ) {
			if ( *ptr > 0 ) {
				--(*ptr);
				break;  // No longer carry
			}
			--(*ptr);
		}
		return *this;
	}

	/// Constructs value of this object from given 'value', which can 
	/// have any size (in bytes)
	template< typename RawT >
	constexpr this_type& construct_from_raw( RawT value ) {
		constexpr unsigned int value_bits = sizeof(value) * CHAR_BIT;
				// Count of bits in 'value'.
		std::fill_n( _limbs.data(), _limbs_count, (limb_type)0 );
				// At first, reset the number to 0.
		// Check different cases
		if constexpr ( value_bits <= _limb_bits )
			_limbs[ 0 ] = value;
		else if constexpr ( value_bits <= _limb_bits * 2 ) {
			// We must fill 2 limbs
			_limbs[ 0 ] = (limb_type)value;
			_limbs[ 1 ] = (limb_type)(value >> _limb_bits);
		}
		else if constexpr ( value_bits <= _limb_bits * 4 ) {
			// We must fill 4 limbs
			_limbs[ 0 ] = (limb_type)value;
			_limbs[ 1 ] = (limb_type)(value >>= _limb_bits);
			_limbs[ 2 ] = (limb_type)(value >>= _limb_bits);
			_limbs[ 3 ] = (limb_type)(value >>= _limb_bits);
		}
		else {
			// The general case, we iterate over limbs
			limb_type* limb_ptr = _limbs.data();
			*(limb_ptr++) = (limb_type)value;
			while ( value != 0 && limb_ptr < _limbs.data() + _limbs_count )
				*(limb_ptr++) = (limb_type)(value >>= _limb_bits);
		}
		return *this;
	}

	/// Converts value of this number into raw type 'RawT', which can 
	/// have arbitrary number of bits.
	template< typename RawT >
	constexpr RawT convert_to_raw() const {
		constexpr unsigned int raw_bits = sizeof(RawT) * CHAR_BIT;
				// Count of bits in 'value'.
		// Check different cases
		if constexpr ( raw_bits <= _limb_bits )
			return _limbs[ 0 ];
		else if constexpr ( raw_bits <= _limb_bits * 2 )
			return (RawT(_limbs[ 1 ]) << _limb_bits) 
					| RawT(_limbs[ 0 ]);
		else if constexpr ( raw_bits <= _limb_bits * 4 )
			return (RawT(_limbs[ 3 ]) << (_limb_bits*3) ) 
					| (RawT(_limbs[ 2 ]) << (_limb_bits*2) )
					| (RawT(_limbs[ 1 ]) << _limb_bits)
					| RawT(_limbs[ 0 ]);
		else {
			RawT result( 0 );
			for ( const limb_type* ptr = _limbs.data() + _limbs_count - 1; 
					ptr >= _limbs.data();
					--ptr ) {
				//result *= (dbl_limb_type)(1 << _limb_bits);
				result <<= _limb_bits;  // This line should work faster
				result += *ptr;
			}
			return result;
		}
	}

public:
	/// Default constructor
	/// Initializes to 0.
	constexpr binary_integer_over_array() {
		std::fill_n( _limbs.data(), _limbs_count, (limb_type)0 );
	}

	/// Conversion constructors
	constexpr binary_integer_over_array( unsigned char value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( char value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( unsigned short value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( short value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( unsigned int value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( int value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( unsigned long long value )
		{ construct_from_raw( value ); }
	constexpr binary_integer_over_array( long long value )
		{ construct_from_raw( value ); }

	/// Constructor
	/// Creates the big integer equal to 'value'.
//	binary_integer_over_array( limb_type value ) {
//		std::fill_n( _limbs.data(), _limbs_count, 0 );
//		_limbs[ 0 ] = value;  // Place to the last limb
//	}

	/// Constructor
	/// Creates the big integer equal to 'value'.
	// Note: We declare this constructor as explicit, because otherwise 
	// it causes a lot of ambiguity with constructor from "limb_type".
//	explicit binary_integer_over_array( dbl_limb_type value ) {
//		std::fill_n( _limbs.data(), _limbs_count, 0 );
//		_limbs[ 1 ] = (limb_type)(value >> _limb_bits);
//		_limbs[ 0 ] = (limb_type)value;
//	}

	/// Constructor
	/// Allows to specify value of every limb separately.
	/// The unspecified most significant limbs are filled with 0.
	constexpr binary_integer_over_array( std::initializer_list< limb_type > digits ) {
		// Place the specified limbs, in reverse order
		std::reverse_copy( digits.begin(), digits.end(), _limbs.data() );
		// Fill upper limbs with '0'
		std::fill( _limbs.data() + digits.size(), _limbs.data() + _limbs_count, 0 );
	}

	/// Convertion constructor
	/// Narrows or widens provided other big integer object.
	template< unsigned int OtherLimbsCount >
	constexpr binary_integer_over_array( 
			const binary_integer_over_array< LimbType, OtherLimbsCount, DblLimbType >& other ) {
		if constexpr ( _limbs_count < other._limbs_count ) {
			// Narrowing
			std::copy_n( other.data(), _limbs_count, _limbs.data() );
		}
		else {
			// Widening
			std::copy_n( other.data(), other._limbs_count, _limbs.data() );
			std::fill( _limbs.data() + other._limbs_count, _limbs.data() + _limbs_count, 0 );
		}
	}

	/// Assignment operators
	this_type& operator=( unsigned char value )
		{ return construct_from_raw( value ); }
	this_type& operator=( char value )
		{ return construct_from_raw( value ); }
	this_type& operator=( unsigned short value )
		{ return construct_from_raw( value ); }
	this_type& operator=( short value )
		{ return construct_from_raw( value ); }
	this_type& operator=( unsigned int value )
		{ return construct_from_raw( value ); }
	this_type& operator=( int value )
		{ return construct_from_raw( value ); }
	this_type& operator=( unsigned long long value )
		{ return construct_from_raw( value ); }
	this_type& operator=( long long value )
		{ return construct_from_raw( value ); }

	/// Assignment operators
//	this_type& operator=( limb_type value ) {
//		std::fill_n( _limbs.data(), _limbs_count, 0 );
//		_limbs[ 0 ] = value;  // Place into the last limb
//		return *this;
//	}
//	this_type& operator=( dbl_limb_type value ) {
//		std::fill_n( _limbs.data(), _limbs_count, 0 );
//		_limbs[ 1 ] = (limb_type)(value >> _limb_bits);
//		_limbs[ 0 ] = (limb_type)value;
//		return *this;
//	}

	/// Access to underlying array.
	constexpr limb_type* data() {
		return _limbs.data();
	}
	constexpr const limb_type* data() const {
		return _limbs.data();
	}

	/// Access to separate limbs, by index.
	constexpr limb_type& operator[]( unsigned int index ) {
		return _limbs[ index ];
	}
	constexpr limb_type operator[]( unsigned int index ) const {
		return _limbs[ index ];
	}

	/// Access to count of limbs.
	size_t size() const {
		return _limbs.size();
	}

	/// Fills all limbs with 'arg' value.
	void fill( limb_type arg ) {
		_limbs.fill( arg );
	}

	// Addition
	constexpr this_type& operator+=( const this_type& rhs ) {
		limb_type carry( 0 );
		limb_type* this_ptr = _limbs.data();
		limb_type* const this_ptr_end = _limbs.data() + _limbs_count;
		const limb_type* rhs_ptr = rhs._limbs.data();
		for ( ; this_ptr < this_ptr_end; 
				++this_ptr, ++rhs_ptr ) {
			if ( carry ) {
				(*this_ptr) += (*rhs_ptr);
				if ( *this_ptr < *rhs_ptr ) {  // there is a carry
					++(*this_ptr);  // Use previous carry
					// Keep it as current carry
				}
				else {
					++(*this_ptr);
					if ( *this_ptr != 0 )
						carry = 0;  // Reset previous carry
				}
			}
			else {
				(*this_ptr) += (*rhs_ptr);
				if ( *this_ptr < *rhs_ptr )  // there is a carry
					carry = 1;
			}
		}
		return *this;
	}

	// Subtraction
	constexpr this_type& operator-=( const this_type& rhs ) {
		limb_type carry( 0 );
		limb_type* this_ptr = _limbs.data();
		limb_type* const this_ptr_end = _limbs.data() + _limbs_count;
		const limb_type* rhs_ptr = rhs._limbs.data();
		for ( ; this_ptr < this_ptr_end; 
				++this_ptr, ++rhs_ptr ) {
			if ( carry ) {
				if ( *this_ptr < *rhs_ptr ) {  // there will be a carry
					(*this_ptr) -= (*rhs_ptr);
					--(*this_ptr);  // Use previous carry
					// Keep it as current carry
				}
				else {
					(*this_ptr) -= (*rhs_ptr);
					if ( *this_ptr != 0 )
						carry = 0;  // Reset previous carry
					--(*this_ptr);
				}
			}
			else {
				if ( *this_ptr < *rhs_ptr )  // there will be a carry
					carry = 1;
				(*this_ptr) -= (*rhs_ptr);
			}
		}
		return *this;
	}

	/// Addition by regular number
	constexpr this_type& operator+=( limb_type rhs ) {
		limb_type* ptr = _limbs.data();
		(*ptr) += rhs;
		if ( *ptr < rhs )  // There was a carry
			increment_from_limb( 1 );
		return *this;
	}

	/// Prefix increment
	constexpr this_type& operator++() {
		return increment_from_limb( 0 );
	}

	/// Postfix increment
	constexpr this_type operator++( int ) {
		this_type result( *this );
		++(*this);
		return result;
	}

	/// Prefix decrement
	constexpr this_type& operator--() {
		return decrement_from_limb( 0 );
	}

	/// Postfix decrement
	constexpr this_type operator--( int ) {
		this_type result( *this );
		--(*this);
		return result;
	}

	/// Subtraction by regular number
	constexpr this_type& operator-=( limb_type rhs ) {
		limb_type* ptr = _limbs.data();
		if ( *ptr < rhs ) {  // There will be a carry
			(*ptr) -= rhs;
			decrement_from_limb( 1 );
		}
		else
			(*ptr) -= rhs;
		return *this;
	}

	// Declaration as 'friend' function, so function with some value of 'R' 
	// will be able to access the class with another value of 'R'.
	template< unsigned int R_, 
			typename LimbType_, unsigned int U1_, unsigned int U2_, typename DblLimbType_ >
	friend binary_integer_over_array< LimbType_, R_, DblLimbType_ >
			multiply_by_limbs( 
					const binary_integer_over_array< LimbType_, U1_, DblLimbType_ >& a,
					const binary_integer_over_array< LimbType_, U2_, DblLimbType_ >& b );

	// Declaration as 'friend' function, so function with some value of 'R' 
	// will be able to access the class with another value of 'R'.
	template< unsigned int R_, 
			typename LimbType_, unsigned int U1_, typename DblLimbType_ >
	friend binary_integer_over_array< LimbType_, R_, DblLimbType_ >
			multiply_by_limbs( 
					const binary_integer_over_array< LimbType_, U1_, DblLimbType_ >& a,
					const LimbType_ b );

	/// Multiplication
	this_type& operator*=( const this_type& rhs ) {
		// We can't multiply inplace, so write in a temporary
		this_type result 
				= multiply_by_limbs< _limbs_count >( *this, rhs );
		(*this) = result;
		return *this;
	}

	/// Multiplication over a primitive
	this_type& operator*=( limb_type rhs ) {
		// We can't multiply inplace, so write in a temporary
		this_type result 
				= multiply_by_limbs< _limbs_count >( *this, rhs );
		(*this) = result;
		return *this;
	}

	/// Divides this number over 'b'.
	/// Result is returned via the return value
	/// Modulo of the division is stored in *this.
	/// Note, this is not a constant-method.
	this_type div_mod( const this_type& b ) {
		auto b_mult( b );  // Multiple "b*(2^power)"
		unsigned int power( 0 );
		// Find the smallest multiple of 'b', which is greater than 'a'
		while ( b_mult <= (*this) ) {
			b_mult <<= 1;
			++power;
		}
		// Subtract the multiples of 'b' in reverse order from 'a'
		binary_integer_over_array< LimbType, LimbsCount, DblLimbType > quot;
		while ( power > 0 ) {
			b_mult >>= 1;
			--power;
			if ( *this >= b_mult ) {
				(*this) -= b_mult;
				quot.set_bit( power );
			}
		}
		return quot;
	}

	/// Remainder calculation operator
	this_type& operator%=( const this_type& b ) {
		this_type b_mult( b );  // Multiple "b*(2^power)"
		unsigned int power( 0 );
		// Find the smallest multiple of 'b', which is greater than '*this'
		while ( b_mult <= *this ) {
			b_mult <<= 1;
			++power;
		}
		// Subtract the multiples of 'b' in reverse order from '*this'
		while ( power > 0 ) {
			b_mult >>= 1;
			--power;
			if ( *this >= b_mult )
				*this -= b_mult;
		}
		return *this;
	}

	/// Division calculation operator
	this_type& operator/=( const this_type& b ) {
		return *this = div_mod( b );
	}

	/// Bit shift to right
	constexpr this_type& operator>>=( unsigned int bits ) {
		assert( bits < _limb_bits );
				// We are not going to shift too long.
		const unsigned int bits_complement = _limb_bits - bits;
		limb_type *ptr = _limbs.data(), 
				*next_ptr = _limbs.data() + 1;
		limb_type* const ptr_end = _limbs.data() + _limbs_count;
		for ( ; next_ptr < ptr_end; 
				++ptr, ++next_ptr ) {
			(*ptr) >>= bits;
			(*ptr) |= (*next_ptr) << bits_complement;
		}
		(*ptr) >>= bits;  // The most-significant limb
		return *this;
	}

	/// Bit shift to left
	constexpr this_type& operator<<=( unsigned int bits ) {
		assert( bits < _limb_bits );
				// We are not going to shift too long.
		const unsigned int bits_complement = _limb_bits - bits;
		limb_type *ptr = _limbs.data() + _limbs_count - 1, 
				*next_ptr = _limbs.data() + _limbs_count - 2;
		limb_type* const ptr_end = _limbs.data();
		for ( ; next_ptr >= ptr_end; 
				--ptr, --next_ptr ) {
			(*ptr) <<= bits;
			(*ptr) |= (*next_ptr) >> bits_complement;
		}
		(*ptr) <<= bits;  // The least-significant limb
		return *this;
	}

	/// Sets bit at 'index' to 1.
	constexpr this_type& set_bit( unsigned int index ) {
		// Obtain parts of 'index'
		unsigned int limb_index = index / _limb_bits;
		assert( limb_index < _limbs_count );
		unsigned int index_in_limb = index - (limb_index * _limb_bits);
		assert( index_in_limb < _limb_bits );
		// Set
		_limbs[ limb_index ] |= limb_type( 1 ) << index_in_limb;
		return *this;
	}

	/// Unsets bit at 'index' to 0.
	constexpr this_type& unset_bit( unsigned int index ) {
		// Obtain parts of 'index'
		unsigned int limb_index = index / _limb_bits;
		assert( limb_index < _limbs_count );
		unsigned int index_in_limb = index - (limb_index * _limb_bits);
		assert( index_in_limb < _limb_bits );
		// Unset
		_limbs[ limb_index ] &= ~( limb_type( 1 ) << index_in_limb );
		return *this;
	}

	/// Checks if bit at 'index' is 1.
	constexpr bool test_bit( unsigned int index ) const {
		// Obtain parts of 'index'
		unsigned int limb_index = index / _limb_bits;
		assert( limb_index < _limbs_count );
		unsigned int index_in_limb = index - (limb_index * _limb_bits);
		assert( index_in_limb < _limb_bits );
		// Check
		return _limbs[ limb_index ] & (limb_type( 1 ) << index_in_limb);
	}

	/// Conversion operators
	explicit operator char() const
		{ return convert_to_raw< char >(); }
	explicit operator unsigned char() const
		{ return convert_to_raw< unsigned char >(); }
	explicit operator short() const
		{ return convert_to_raw< short >(); }
	explicit operator unsigned short() const
		{ return convert_to_raw< unsigned short >(); }
	explicit operator int() const
		{ return convert_to_raw< int >(); }
	explicit operator unsigned int() const
		{ return convert_to_raw< unsigned int >(); }
	explicit operator long long() const
		{ return convert_to_raw< long long >(); }
	explicit operator unsigned long long() const
		{ return convert_to_raw< unsigned long long >(); }

	/// Convertion operator into 'limb_type'
//	operator limb_type() const {
//		return _limbs[ 0 ];  // Take only the last limb
//	}

	/// Convertion operator into 'dbl_limb_type'
	// Note: We declare this conversion operator as explciit, because otherwise 
	// it causes a lot of ambiguity with the conversion operator to "limb_type".
//	explicit operator dbl_limb_type() const {
//		dbl_limb_type result( _limbs[ 1 ] );  // Take one before last limb
//		result <<= _limb_bits;
//		result |= _limbs[ 0 ];  // and the last one.
//		return result;
//	}

	/// Conversion to boolean type.
	explicit operator bool() const {
		return std::find( _limbs.cbegin(), _limbs.cend(), (limb_type)0 ) 
				!= _limbs.end();
	}

};


// Definition of some global functions


/// Regular multiplication of big integers with different limbs count.
/// Caller is able to control number of the least significant limbs 
/// of result of multiplication.
template< unsigned int R, 
		typename LimbType, unsigned int U1, unsigned int U2, typename DblLimbType >
inline binary_integer_over_array< LimbType, R, DblLimbType >
		multiply_by_limbs( 
				const binary_integer_over_array< LimbType, U1, DblLimbType >& a,
				const binary_integer_over_array< LimbType, U2, DblLimbType >& b ) {
	// Some typdefs and constants
	typedef LimbType limb_type;
	constexpr auto _limb_bits 
			= binary_integer_over_array< LimbType, R, DblLimbType >::_limb_bits;
	typedef DblLimbType dbl_limb_type;
	// Prepare the result variable
	binary_integer_over_array< limb_type, R, dbl_limb_type > r;
	limb_type *r_low_ptr = r.data(), 
			*r_high_ptr = r.data() + 1;
	for ( int r_index = 0; 
			r_index < R; 
			++r_index, ++r_low_ptr, ++r_high_ptr ) {
		// Now we are calculating "r[ r_index ]"
		int a_index = r_index;
		int b_index = 0;
		if ( a_index >= U1 ) {  // 'a' hasn't that many limbs
			b_index = a_index - (U1 - 1);
			a_index = U1 - 1;
		}
		if ( b_index >= U2 )  // 'b' hasn't that many limbs too
			break;  // All necessary limbs of result are calculated
		const int a_last_index = 0;
		const int b_last_index = U2 - 1;
		// Iterate in parallel over a in [a_index -> a_last_index], 
		//    and over 'b' in [b_index -> b_last_index].
		for ( ; a_index >= a_last_index && b_index <= b_last_index; 
				--a_index, ++b_index ) {
			// Now we need to multiply 'a[ a_index ]' over 'b[ b_index ]', 
			// and add the result to (*r_high_ptr, *r_low_ptr).
			dbl_limb_type tmp( a[ a_index ] );
			tmp *= b[ b_index ];
			// Add to '*r_low_ptr'
			assert( r_low_ptr < r.data() + R );
			*r_low_ptr += (limb_type)tmp;
			if ( *r_low_ptr < (limb_type)tmp )  // There was an overflow
				r.increment_from_limb( r_index + 1 );
			// Add to '*r_high_ptr'
			if ( r_high_ptr < r.data() + R ) {  // Check that the result
						// can fit also the high bits of multiplication
				tmp >>= _limb_bits;
				*r_high_ptr += (limb_type)tmp;
				if ( *r_high_ptr < (limb_type)tmp )  // There was an overflow
					r.increment_from_limb( r_index + 2 );
			}
		}
	}
	return r;
}

/// Regular multiplication of big integer on a primitive value.
/// Caller is able to control number of the least significant limbs 
/// of result of multiplication.
template< unsigned int R, 
		typename LimbType, unsigned int U1, typename DblLimbType >
inline binary_integer_over_array< LimbType, R, DblLimbType >
		multiply_by_limbs( 
				const binary_integer_over_array< LimbType, U1, DblLimbType >& a,
				const LimbType b ) {
	// Some typdefs and constants
	typedef LimbType limb_type;
	constexpr auto _limb_bits
		= binary_integer_over_array< LimbType, R, DblLimbType >::_limb_bits;
	typedef DblLimbType dbl_limb_type;
	// Prepare the result variable
	binary_integer_over_array< limb_type, R, dbl_limb_type > r;
	limb_type *r_low_ptr = r._limbs.data(), 
			*r_high_ptr = r._limbs.data() + 1;
	for ( unsigned int r_index = 0; 
			r_index < R; 
			++r_index, ++r_low_ptr, ++r_high_ptr ) {
		if ( r_index >= U1 )  // 'a' hasn't that many limbs
			break;  // All necessary limbs of result are calculated
		// Now we need to multiply 'a[ r_index ]' over 'b', 
		// and add the result to (*r_high_ptr, *r_low_ptr).
		dbl_limb_type tmp( a[ r_index ] );
		tmp *= b;
		// Add to '*r_low_ptr'
		assert( r_low_ptr < r._limbs.data() + R );
		*r_low_ptr += (limb_type)tmp;
		if ( *r_low_ptr < (limb_type)tmp )  // There was an overflow
			r.increment_from_limb( r_index + 1 );
		// Add to '*r_high_ptr'
		if ( r_high_ptr < r._limbs.data() + R ) {  // Check that the result
					// can fit also the high bits of multiplication
			tmp >>= _limb_bits;
			*r_high_ptr += (limb_type)tmp;
			if ( *r_high_ptr < (limb_type)tmp )  // There was an overflow
				r.increment_from_limb( r_index + 2 );
		}
	}
	return r;
}


// Global operators


template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline constexpr binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator+(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	auto result( lhs );
	result += rhs;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline constexpr binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator+(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		LimbType rhs )
{
	auto result( lhs );
	result += rhs;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline constexpr binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator+(
		LimbType lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	auto result( rhs );
	result += lhs;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline constexpr binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator-(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	auto result( lhs );
	result -= rhs;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline constexpr binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator-(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		LimbType rhs )
{
	auto result( lhs );
	result -= rhs;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator*(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return multiply_by_limbs< LimbsCount >( lhs, rhs );
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator*(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		LimbType rhs )
{
	return multiply_by_limbs< LimbsCount >( lhs, rhs );
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator*( 
		LimbType lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return multiply_by_limbs< LimbsCount >( rhs, lhs );
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator%(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& a, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& b )
{
	auto result( a );
	result %= b;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator/(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& a, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& b )
{
	auto a_copy( a );
	return a_copy.div_mod( b );
}


// Comparison


template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline bool operator==(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return std::equal(
			lhs.data(), lhs.data() + lhs._limbs_count,
			rhs.data() );
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline bool operator!=(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return ! (lhs == rhs);
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline bool operator<(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	const LimbType* lhs_ptr = lhs.data() + lhs._limbs_count - 1;
	const LimbType* rhs_ptr = rhs.data() + rhs._limbs_count - 1;
	const LimbType* lhs_ptr_end = lhs.data();
	for ( ; lhs_ptr >= lhs_ptr_end; 
			--lhs_ptr, --rhs_ptr ) {
		if ( *lhs_ptr != *rhs_ptr )
			return *lhs_ptr < *rhs_ptr;
	}
	return false;  // Values are equal
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline bool operator<=(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return ! (rhs < lhs);
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline bool operator>(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return rhs < lhs;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline bool operator>=(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return ! (lhs < rhs);
}


// Bit operators


template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator<<(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		unsigned int offset ) {
	auto result( lhs );
	result <<= offset;
	return result;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator>>(
		const binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		unsigned int offset ) {
	auto result( lhs );
	result >>= offset;
	return result;
}


// Stream operators


template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline std::ostream& operator<<( 
		std::ostream& ostr, 
		binary_integer_over_array< LimbType, LimbsCount, DblLimbType > a )
{
	typedef binary_integer_over_array< LimbType, LimbsCount, DblLimbType > 
			number_type;  // Type of the number being printed
	// Handle case of "0" separately.
	if ( a == number_type(0) ) {
		ostr << '0';
		return ostr;
	}
	// The general case
	static constexpr LimbType max_power_of_10
			= detail::exponential_limits< LimbType, 10 >::max_power;
			// The maximal power of 10, that can fit in one limb.
	static constexpr unsigned int max_exponent 
			= detail::exponential_limits< LimbType, 10 >::max_exponent;
			// Exponent of that maximal power.
	std::array< LimbType, LimbsCount * 2 + 2 > decimals;
			// Sequence of portions of the number, each representing
			// some substring of its decimal representation.
	int L = 0;  // Index over "decimals" array
	// Obtain sequence of decimal portions
	binary_integer_over_array< LimbType, LimbsCount, DblLimbType > a_next;
	while ( a != number_type(0) ) {
		a_next = a.div_mod( max_power_of_10 );
		decimals[ L++ ] = a[ 0 ];
		a = a_next;
	}
	// Print them
	assert( L > 0 );
	ostr << (unsigned int)decimals[ --L ];  // The first portion goes without leading 0s.
	for ( --L; L >= 0; --L ) {
		ostr.width( max_exponent );  // The others go with leading 0s.
		ostr.fill( '0' );
		ostr << (unsigned int)decimals[ L ];
	}
	return ostr;
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline std::istream& operator>>( 
		std::istream& istr, 
		binary_integer_over_array< LimbType, LimbsCount, DblLimbType >& a )
{
	static constexpr LimbType max_power_of_10
			= detail::exponential_limits< LimbType, 10 >::max_power;
			// The maximal power of 10, that can fit in one limb.
	static constexpr unsigned int max_exponent 
			= detail::exponential_limits< LimbType, 10 >::max_exponent;
			// Exponent of that maximal power.
	// Read all the digits into string
	static std::string number_dec;
			// Decimal string of the number being parsed
	istr >> number_dec;
	assert( ! number_dec.empty() );
	// Divide the string into portions
	std::array< LimbType, LimbsCount * 2 + 2 > decimals;
			// Sequence of portions of the number, each representing
			// some substring of its decimal representation.
	int L = 0;  // Index over "decimals" array
	//   we can read one more "full" portions
	static std::istringstream is_stream;  // Stream, used to read a portion
	unsigned int limb_value;
	while ( number_dec.length() >= max_exponent ) {
		is_stream.str( number_dec.substr( 
				number_dec.length() - max_exponent ) );
		is_stream.seekg( 0 );
		number_dec.erase( 
				number_dec.length() - max_exponent, max_exponent );
		is_stream >> limb_value;
		decimals[ L++ ] = limb_value;
		L %= decimals.size();  // Reset index to 0, on overflow
	}
	//   read the last (possibly partial) portion
	if ( ! number_dec.empty() ) {
		is_stream.str( number_dec );
		is_stream.seekg( 0 );
		number_dec.clear();
		is_stream >> limb_value;
		decimals[ L++ ] = limb_value;
		L %= decimals.size();  // Reset index to 0, on overflow
	}
	// Accumulate portions in the number
	if ( L == 0 ) {
		// There definitely was an overflow
		a = (LimbType)0;
	}
	else {
		// The regular case
		a = decimals[ --L ];
		for ( --L; L >= 0; --L ) {
			a *= max_power_of_10;
			a += decimals[ L ];
		}
	}
	return istr;

	// ToDo: Later this functionality can be optimized, to not used 
	//    internal 'std::istringstream' object. Just read raw characters 
	//    instead.
}


/**
 * ToDo:
 * 
 * Add faster comparison functions, when one of operands is 'limb_type'
 *     ... don't force its conversion to 'BigInteger', followed by
 *     comparison of 2 BigIntegers.
 * 
 */

}
}

#endif // NIL__MULTIPRECISION__BINARY_INTEGER_OVER_ARRAY_HPP
