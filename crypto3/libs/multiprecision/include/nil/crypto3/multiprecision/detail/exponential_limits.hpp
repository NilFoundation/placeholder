
#ifndef NIL__MULTIPRECISION__DETAIL__EXPONENTIAL_LIMITS_HPP
#define NIL__MULTIPRECISION__DETAIL__EXPONENTIAL_LIMITS_HPP

#include <utility>

namespace nil {
namespace multiprecision {
namespace detail {


/// This class is inteded for calculation of maximal powers of 'base', 
/// that can fit in provided number type 'ValueType'
template< typename ValueType, unsigned int Base = 10 >
class exponential_limits
{
public:
	typedef ValueType value_type;
	static constexpr unsigned int base = Base;
	typedef exponential_limits< ValueType, Base > this_type;

private:
	/// Calculates all necessary member variables of this class, 
	/// and returns them.
	static constexpr std::pair< value_type, unsigned int > calculate() {
		value_type p = 1;
		unsigned int e = 0;
		while ( true ) {
			// Check if we can increment exponent
			value_type altered_p( p );
			altered_p *= base;
			altered_p /= base;
			if ( altered_p != p )
				break;
			// Increment it
			p *= base;
			++e;
		}
		return std::make_pair( p, e );
	}

public:
	// The maximal power of 'Base', which can fit in 'ValueType'.
	static constexpr value_type max_power
			= calculate().first;

	// The exponent of that power.
	static constexpr unsigned int max_exponent
			= calculate().second;
};


}
}
}

#endif // NIL__MULTIPRECISION__DETAIL__EXPONENTIAL_LIMITS_HPP
