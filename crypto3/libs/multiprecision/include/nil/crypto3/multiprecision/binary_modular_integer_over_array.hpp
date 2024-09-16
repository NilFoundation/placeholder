
#ifndef NIL__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_HPP
#define NIL__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_HPP

#include <algorithm>
#include <vector>
#include <cassert>

#include "binary_integer_over_array.hpp"

namespace nil {
namespace multiprecision {


/// Names of the integers, which are used as modules, in modular arithmetic.
enum class modules_names : unsigned int
{
	MODULE_A, 
	MODULE_B, 
	MODULE_C
};

/// Values of the integers, which are used as modules, in modular arithmetic.
template< typename BigIntegerType >
class modules_values
{
public:
	/// Value of modules
	static constexpr BigIntegerType values[] = {
			
	}
};


/// This class is ordinary implementation of modular big number.
/// It derives a regular 'BigIntegerType', and adds modular behavior.
template< typename BigIntegerType, unsigned int ModuleIndex >
class binary_modular_integer_over_array : public BigIntegerType
{
public:
	typedef BigIntegerType big_integer_type;
	typedef BigIntegerType base_type;
	static constexpr unsigned int _module_index = ModuleIndex;
	typedef binary_modular_integer_over_array< 
			BigIntegerType, ModuleIndex > this_type;

	typedef typename base_type::limb_type limb_type;
	static constexpr unsigned int _limbs_count = base_type::limbs_count;
	typedef typename base_type::dbl_limb_type dbl_limb_type;

	/// The module of this big integer
	static constexpr big_integer_type _module 
			= modules_values< big_integer_type >.values[ _module_index ];

	// Check that keeping double module will not overflow the regular
	// big integer.
	static_assert( 
			_module * 2 > _module, 
			"Implementation of this class requires that a value twice larger than the module"
			" can still fit in the underlying big integer." );

protected:
	/// Normalizes this modular number (brings it into range [0, module) ), 
	/// assuming that currently it might be at most twice larger than the module.
	void normalize_once_down() {
		if ( _module <= *this )
			base_type::operator-=( _module );
		// Check that this normalization was enough
		assert( *this < _module );
	}

	/// Normalizes this modular number (brings it into range [0, module) ), 
	/// assuming that currently it might be "negative", in range (-module, 0).
	void normalize_once_up() {
		if ( _module <= *this )
			base_type::operator+=( _module );
		// Check that this normalization was enough
		assert( *this < _module );
	}

	/// Normalizes this modular number (brings it into range [0, module) ), 
	/// assuming that currently it might be many times larger than the module.
/*	void normalize_multiple() {
		static std::vector< base_type > modules_multiples( 
				1, _module );
				// Multiples of the module, where every next value 
				// is twice larger from previous one.
		// Find the smallest multiple, larger than current value
		int i = 0;
		while ( i < (int)modules_multiples.size() 
				&& modules_multiples[ i ] <= *this )
			++i;
		// ... append new multiples, if necessary
		if ( i == (int)modules_multiples.size() ) {
			do {
				modules_multiples.push_back( 
						modules_multiples.back() + modules_multiples.back() );
			} while ( modules_multiples.back() <= *this );
			i = (int)modules_multiples.size() - 1;
		}
		// ... check that in any case we are on a greater multiple
		assert( modules_multiples[ i ] > *this );
		// Start reducing
		for ( --i; i >= 0; --i )
			if ( modules_multiples[ i ] <= *this )
				(*this) -= modules_multiples[ i ];
	}*/

	/// Normalizes 'value' (brings it into range [0, module) ), 
	/// assuming that currently it might be many times larger than the module.
	/// For example, if a raw multiplication was performed on 2 modular numbers.
	static void reduce( binary_integer_over_array< 
			limb_type, 
			_limbs_count * 2, 
			dbl_limb_type >& value ) {
		static std::vector< base_type > modules_multiples( 
				1, _module );
				// Multiples of the module, where every next value 
				// is twice larger from previous one.
		// Find the smallest multiple, larger than current value
		int i = 0;
		while ( i < (int)modules_multiples.size() 
				&& modules_multiples[ i ] <= value )
			++i;
		// ... append new multiples, if necessary
		if ( i == (int)modules_multiples.size() ) {
			do {
				modules_multiples.push_back( 
						modules_multiples.back() + modules_multiples.back() );
			} while ( modules_multiples.back() <= value );
			i = (int)modules_multiples.size() - 1;
		}
		// ... check that in any case we are on a greater multiple
		assert( modules_multiples[ i ] > value );
		// Start reducing
		for ( --i; i >= 0; --i )
			if ( modules_multiples[ i ] <= value )
				value -= modules_multiples[ i ];
	}

	/// Constructs value of this object from given 'value', which can 
	/// have any size (in bytes)
	template< typename RawT >
	this_type& construct_from_raw( RawT value ) {
		base_type::construct_from_raw( value );
		normalize_once_down();
		return *this;
	}

public:
	/// Default constructor
	/// Initializes to 0.
	this_type() {
		std::fill_n( _limbs.data(), _limbs_count, (limb_type)0 );
	}

	/// Conversion constructors
	this_type( unsigned char value )
		{ construct_from_raw( value ); }
	this_type( char value )
		{ construct_from_raw( value ); }
	this_type( unsigned short value )
		{ construct_from_raw( value ); }
	this_type( short value )
		{ construct_from_raw( value ); }
	this_type( unsigned int value )
		{ construct_from_raw( value ); }
	this_type( int value )
		{ construct_from_raw( value ); }
	this_type( unsigned long long value )
		{ construct_from_raw( value ); }
	this_type( long long value )
		{ construct_from_raw( value ); }

	/// Constructor
	/// Allows to specify value of every limb separately.
	/// The unspecified most significant limbs are filled with 0.
	this_type( std::initializer_list< limb_type > digits ) 
			: base_type( digits ) {
		// Normalize
		reduce( static_cast< base_type& >( *this ) );
	}

	// We assume that no need will arise for calling conversion constructor
	// with same limb types but different limbs count.
	template< unsigned int OtherLimbsCount >
	this_type( const binary_modular_integer_over_array< 
			LimbType, 
			OtherLimbsCount, 
			DblLimbType >& );

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

	/// Addition
	this_type& operator+=( const this_type& rhs ) {
		base_type::operator+=( rhs );
		normalize_once_down();
		return *this;
	}

	// Addition by regular number
	this_type& operator+=( limb_type rhs ) {
		base_type::operator+=( rhs );
		normalize_once_down();
		return *this;
	}

	/// Subtraction
	this_type& operator-=( const this_type& rhs ) {
		base_type::operator-=( rhs );
		normalize_once_up();
		return *this;
	}

	// Subtraction by regular number
	this_type& operator-=( limb_type rhs ) {
		base_type::operator-=( rhs );
		normalize_once_up();
		return *this;
	}

	/// Increment
	this_type& operator++() {
		base_type::operator++();
		if ( *this == _module )  // Possible reset
			*this = (limb_type)0;
		return *this;
	}

	// ... postfix version
	this_type operator++( int ) {
		this_type result( *this );
		++(*this);
		return result;
	}

	/// Decrement
	this_type& operator--() {
		if ( *this == 0 )  // Prepare for possible reset
			*this = _module;
		base_type::operator--();
		return *this;
	}

	// ... postfix version
	this_type operator--(int) {
		this_type result(*this);
		--(*this);
		return result;
	}

	/// Multiplication
	this_type& operator*=( const this_type& rhs ) {
		auto result = (*this) * rhs;
		return (*this) = result;
	}

	// ... over a primitive type
	this_type& operator*=( limb_type rhs ) {
		auto result = (*this) * rhs;
		return (*this) = result;
	}

};


// Global operators


template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator*(
		const binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		const binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >
			this_type;
	typedef typename this_type::base_type base_type;
	// Perform regular multiplication
	binary_integer_over_array< LimbType, LimbsCount * 2, DblLimbType > result_raw 
			= base_type::multiply_by_limbs< LimbsCount * 2 >( lhs, rhs );
	// Reduce it
	this_type::reduce( result_raw );
	assert( result_raw < this_type::_module );
	return this_type( result_raw );
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator*(
		const binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >& lhs, 
		LimbType rhs )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >
			this_type;
	typedef typename this_type::base_type base_type;
	// Perform regular multiplication
	binary_integer_over_array< LimbType, LimbsCount * 2, DblLimbType > result_raw 
			= base_type::multiply_by_limbs< LimbsCount * 2 >( lhs, rhs );
	// Reduce it
	this_type::reduce( result_raw );
	assert( result_raw < this_type::_module );
	return this_type( result_raw );
}

template< typename LimbType, unsigned int LimbsCount, typename DblLimbType >
inline binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >
operator*(
		LimbType lhs, 
		const binary_modular_integer_over_array< LimbType, LimbsCount, DblLimbType >& rhs )
{
	return rhs * lhs;
}


/**
 * ToDo:
 * 
 * Add global addition / subtraction operators
 * 
 * In base class, add casting to twice more limbs count and twice less limbs count
 * 
 * Decide about changing template arguments of this class to:
 *   LimbType, 
 *   LimbsCount,
 *   DblLimbType,
 * instead of relying on BigIntegerType.
 * 
 * Check that conversion from 'base_type' to 'this_type' can work.
 *     ... perhaps make it explicit.
 * 
 * Check that comparison between 'modular' and 'regular' works as expected.
 * 
 * 
 * 
 */

}
}

#endif // NIL__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_HPP
