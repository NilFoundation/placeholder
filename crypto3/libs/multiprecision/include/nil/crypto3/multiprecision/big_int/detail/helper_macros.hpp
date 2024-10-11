#pragma once

//  Copyright 2001 John Maddock.
//  Copyright 2017 Peter Dimov.
//
//  Distributed under the Boost Software License, Version 1.0.
//
//  See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt
//
//  NIL_CO3_MP_STRINGIZE(X)
//  NIL_CO3_MP_JOIN(X, Y)
//
//  Note that this header is C compatible.

//
// Helper macro NIL_CO3_MP_STRINGIZE:
// Converts the parameter X to a string after macro replacement
// on X has been performed.
//
#define NIL_CO3_MP_STRINGIZE(X) NIL_CO3_MP_DO_STRINGIZE(X)
#define NIL_CO3_MP_DO_STRINGIZE(X) #X

//
// Helper macro NIL_CO3_MP_JOIN:
// The following piece of macro magic joins the two
// arguments together, even when one of the arguments is
// itself a macro (see 16.3.1 in C++ standard).  The key
// is that macro expansion of macro arguments does not
// occur in NIL_CO3_MP_DO_JOIN2 but does in NIL_CO3_MP_DO_JOIN.
//
#define NIL_CO3_MP_JOIN(X, Y) NIL_CO3_MP_DO_JOIN(X, Y)
#define NIL_CO3_MP_DO_JOIN(X, Y) NIL_CO3_MP_DO_JOIN2(X, Y)
#define NIL_CO3_MP_DO_JOIN2(X, Y) X##Y
