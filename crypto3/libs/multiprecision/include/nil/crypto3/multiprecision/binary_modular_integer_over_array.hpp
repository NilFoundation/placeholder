
#ifndef NIL__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_HPP
#define NIL__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_HPP

#include <algorithm>
#include <vector>
#include <bitset>
#include <istream>
#include <cassert>

#include "binary_integer_over_array.hpp"

#include "detail/util.hpp"

namespace nil {
namespace multiprecision {

/*
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
};*/


/// This class is ordinary implementation of modular big integer.
/// It derives a regular 'BigIntegerType', and adds modular behavior.
/// The module is specified with help of 'ModuleCarrierType' class, which is 
/// expected to have:
///   ---
///   typedef ... type;
///   static constexpr type _value = ...;
///   ---
template< typename BigIntegerType, typename ModuleCarrierType >
class binary_modular_integer_over_array : public BigIntegerType
{
public:
	typedef BigIntegerType base_type;
	typedef ModuleCarrierType module_carrier_type;
	typedef binary_modular_integer_over_array< 
			BigIntegerType, 
			ModuleCarrierType > this_type;

	using typename base_type::limb_type;
	using base_type::_limbs_count;
	using typename base_type::dbl_limb_type;

	using base_type::_limb_bits;

	/// Type of underlying regular number, which has doubled precision.
	/// Such integer will be used during intermediate calculations.
//	typedef binary_integer_over_array< 
//			limb_type, 
//			2 * _limbs_count, 
//			dbl_limb_type > extended_base_type;

	/// The module of this big integer.
	static constexpr base_type _module = module_carrier_type::_value;

	// Check that keeping double module will not overflow the regular
	// big integer.
	static_assert( 
			detail::util::obtain_bits_count( _module ) < _limbs_count * _limb_bits, 
			"Implementation of this class requires that a value twice larger"
			" than the module can still fit in the underlying big integer." );

protected:
	/// Normalizes this modular number (brings it into range [0, module) ), 
	/// assuming that currently it might be at most twice larger than the module.
	constexpr void normalize_once_down() {
		if ( *this >= _module )
			base_type::operator-=( _module );
		// Check that this normalization was enough
		assert( *this < _module );
	}

	/// Normalizes this modular number (brings it into range [0, module) ), 
	/// assuming that currently it might be "negative", in range (-module, 0).
	constexpr void normalize_once_up() {
		if ( *this >= _module )
			base_type::operator+=( _module );
		// Check that this normalization was enough
		assert( *this < _module );
	}

	/// Normalizes 'value' (brings it into range [0, module) ), 
	/// assuming that currently it might be much larger than the module.
	/// For example, after a raw multiplication was performed on two 
	/// modular numbers.
	template< typename ValueType >
	constexpr static void reduce( ValueType& value ) {
		static std::vector< ValueType > modules_multiples(
				1, 
				static_cast< ValueType >( _module ) );
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
	constexpr this_type& construct_from_raw( RawT value ) {
		base_type::construct_from_raw( value );
		normalize_once_down();
		return *this;
	}

public:
	/// Default constructor
	/// Initializes to 0.
	constexpr binary_modular_integer_over_array()
		: base_type()
		{}

	/// Conversion constructors
	constexpr binary_modular_integer_over_array( unsigned char value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( char value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( unsigned short value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( short value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( unsigned int value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( int value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( unsigned long long value )
		{ construct_from_raw( value ); }
	constexpr binary_modular_integer_over_array( long long value )
		{ construct_from_raw( value ); }

	/// Constructor from base type
	constexpr explicit binary_modular_integer_over_array( 
					const base_type& rhs )
			: base_type( rhs ) {
		// Normalize
		reduce( static_cast< base_type& >( *this ) );
	}

	/// Constructor
	/// Allows to specify value of every limb separately.
	/// The unspecified most significant limbs are filled with 0.
	constexpr binary_modular_integer_over_array( 
					std::initializer_list< limb_type > digits )
			: base_type( digits ) {
		// Normalize
		reduce( static_cast< base_type& >( *this ) );
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
			base_type::operator=( _module );
		base_type::operator--();
		return *this;
	}

	// ... postfix version
	this_type operator--(int) {
		this_type result(*this);
		--(*this);
		return result;
	}

	/// Negation
	this_type operator-() {
		this_type result;
		result -= (*this);
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

private:
	/// Here we disable all methods which are related to division, 
	/// to force user to calculate the inverse number instead.
	/// So, when it is needed to calculate "a/b", at first "b^(-1)"
	/// will be calculated, and "a*[b^(-1)]" will be written instead.
	/// This will prevent user from calculating inverse of "b" implicitly.
	using base_type::div_mod;
	using base_type::operator%=;
	using base_type::operator/=;

public:
	/// Calculates and returns inverse of this modular number.
	this_type inversed() const {
		static constexpr size_t module_bits 
				= detail::util::obtain_bits_count( _module );
		static constexpr std::bitset< module_bits > exponent_bits
				= detail::util::obtain_bits< module_bits >( _module - base_type(2) );
		return detail::util::power( *this, exponent_bits );
	}

	/// Same calculation of invertion, but called by an operator.
	this_type operator~() const {
		return inversed();
	}

	/// Inverses current value of this number in-place, and returns 
	/// this object.
	this_type& inverse() {
		(*this) = inversed();
		return *this;
	}




};


// Global operators


template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator+(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& lhs,
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	auto result( lhs );
	result += rhs;
	return result;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator+(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& lhs,
		typename BigIntegerType::limb_type rhs )
{
	auto result( lhs );
	result += rhs;
	return result;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator+(
		typename BigIntegerType::limb_type lhs, 
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	auto result( rhs );
	result += lhs;
	return result;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator-(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& lhs,
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	auto result( lhs );
	result -= rhs;
	return result;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator-(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& lhs,
		typename BigIntegerType::limb_type rhs )
{
	auto result( lhs );
	result -= rhs;
	return result;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator-(
		typename BigIntegerType::limb_type lhs, 
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType > result( lhs );
	result -= rhs;
	return result;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator*(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& lhs,
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
			this_type;
	typedef typename this_type::base_type base_type;
	typedef typename this_type::limb_type limb_type;
	static constexpr size_t limbs_count = this_type::_limbs_count;
	typedef typename this_type::dbl_limb_type dbl_limb_type;
	// Perform regular multiplication
	binary_integer_over_array< limb_type, limbs_count * 2, dbl_limb_type > result_raw
			= multiply_by_limbs< limbs_count * 2 >( lhs, rhs );
	return this_type( result_raw );
			// We expect that the conversion constructor of this class
			// will reduce the result.
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator*(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& lhs,
		typename BigIntegerType::limb_type rhs )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
			this_type;
	typedef typename this_type::base_type base_type;
	typedef typename this_type::limb_type limb_type;
	static constexpr size_t limbs_count = this_type::_limbs_count;
	typedef typename this_type::dbl_limb_type dbl_limb_type;
	// Perform regular multiplication
	binary_integer_over_array< limb_type, limbs_count + 1, dbl_limb_type > result_raw
			= multiply_by_limbs< limbs_count + 1 >( lhs, rhs );
	return this_type( result_raw );
			// We expect that the conversion constructor of this class
			// will reduce the result.
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator*(
		typename BigIntegerType::limb_type lhs,
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	return rhs * lhs;
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator%(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& a,
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& b )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
			this_type;
	typedef typename this_type::base_type base_type;
	static_assert( false, 
			"Modulo calculation should not be called on modular integers."
			" In case if division is required, at first calculate inverse of "
			"the second argument, and use multiplication instead." );
	return this_type();
}

template< typename BigIntegerType, typename ModuleCarrierType >
inline binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
operator/(
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& a,
		const binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& b )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
			this_type;
	typedef typename this_type::base_type base_type;
	static_assert( false, 
			"Division should not be called on modular integers."
			" In case if division is required, at first calculate inverse of "
			"the second argument, and use multiplication instead." );
	return this_type();
}


// Stream operators


template< typename BigIntegerType, typename ModuleCarrierType >
inline std::istream& operator>>( 
		std::istream& istr, 
		binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >& rhs )
{
	// Just some shortcuts to types of the arguments
	typedef binary_modular_integer_over_array< BigIntegerType, ModuleCarrierType >
			this_type;
	typedef typename this_type::base_type base_type;
	// Input raw number
	istr >> static_cast< base_type& >( rhs );
	// Normalize
	this_type::reduce( static_cast< base_type& >( rhs ) );
}


/**
 * ToDo:
 * 
 * + Add global addition / subtraction operators
 * 
 * In base class, add casting to twice more limbs count and twice less limbs count
 * 
 * - Decide about changing template arguments of this class to:
 *      LimbType, LimbsCount, DblLimbType,
 *   instead of relying on BigIntegerType.
 * 
 * + Check that conversion from 'base_type' to 'this_type' can work.
 *     ... perhaps make it explicit.
 * 
 * [later] Check that comparison between 'modular' and 'regular' works as expected.
 * 
 * + Implement negation
 * 
 * + Adjust 'reduce()' method to work both on regular 'base_type', and 'extended_base_type'.
 * 
 * + Decide if to disable division operator for this class.
 * 
 * + Decide if to change the method how module value is provided.
 * 
 */

}
}

#endif // NIL__MULTIPRECISION__BINARY_MODULAR_INTEGER_OVER_ARRAY_HPP
