///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  <stdbool.h>
//
//  stdbool.h is part of the C99 standard. Unforunately MSVC compiler does not support C99. Although it has several
//  types such as stdint.h, it does not include stdbool.h. This file defines the type bool and values true and false
//  according to the C99 standard. This only needs to be included on systems such as MSVC that do not have stdbool.h
//  gcc has its own version of stdbool.h that should be used in preference.
//
//  This is free and unencumbered software released into the public domain - June 2013 waterjuice.org
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef _STDBOOL_H_
#define _STDBOOL_H_

#ifndef __cplusplus
#ifndef __bool_true_false_are_defined

typedef int     bool;
#define true    1
#define false   0

#define __bool_true_false_are_defined

#endif //__bool_true_false_are_defined
#endif //__cplusplus

#endif //_STDBOOL_H_
