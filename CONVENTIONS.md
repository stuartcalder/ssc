#Macros
* Generally, before we #define a macro, we explicitly check to see if that name is already defined. If it's already defined, we kill compilation with #error.
```c++
#ifndef EXAMPLE
#	define EXAMPLE
#else
#	error 'EXAMPLE Already Defined'
#endif
```
* Generally, after we are finished with a macro we explicitly #undef it to reduce macro pollution.
```c++
#ifndef EXAMPLE
#	define EXAMPLE
#else
#	error 'EXAMPLE Already Defined'
#endif
/* Some code. */
#undef  EXAMPLE
```
##Local Macros
* Macros defined and then undefined in one file are all caps with no leading underscores.
```c++
#define EXAMPLE_LOCAL_MACRO(something) \
	_EXAMPLE_GLOBAL_MACRO (something)
/* Some code. */
#undef EXAMPLE_LOCAL_MACRO
```
##Global Macros
* Global macros always begin with a leading underscore, for example
```c++
/* We use _CTIME_CONST whenever we seek to explicitly use a
 * constexpr variable as a compile-time constant. */
#define _CTIME_CONST(type) static constexpr const type
/* We do not #undef _CTIME_CONST at the end of its originating file because we
 * want it to be usable in all files that #include it. */
```
* Global macros that begin with two leading underscores, but have no trailing underscores, represent compile-time defined.
```c++
#ifdef __SSC_DISABLE_MEMORYLOCKING
	/* If this macro is defined, it is defined at compile-time using build options. */
#endif
```
* Global macros that begin with two leading underscores and end with two trailing underscores represent the support or non-support of an optional feature.
```c++
#include <ssc/memory/os_memory_locking.hh>
/* If we support locking memory on this platform, LOCK_MEMORY will lock memory, otherwise it will do nothing. */
#ifdef __SSC_MemoryLocking__
#	define   LOCK_MEMORY(pointer,size)   ssc::lock_os_memory( pointer, size )
#	define UNLOCK_MEMORY(pointer,size) ssc::unlock_os_memory( pointer, size )
#else
#	define   LOCK_MEMORY(do,nothing)
#	define UNLOCK_MEMORY(do,nothing)
#endif
```
#Compile-Time vs Run-Time Syntactical Differences
* In SSC and its consuming programs, we explicitly use differences in spacing to represent the difference between code that is executed at runtime vs code that is executed by the compiler (i.e. constexpr functions, macros, etc.)
```c++
/* For regular function calls, there is no space between the name of the function and the parenthesis that contain its arguments. */
regular_function_call( first_arg, second_arg );
/* For constexpr functions that are constant evaluated (or later when c++20 has more support, consteval functions)
 * we explicitly place a space between the name of the function, and the arguments, and we place no spaces between the arguments. They are placed right next to each other. */
constexpr_function_call (first_arg,second_arg);
/* We use the same syntax rules to represent constexpr function calls to represent function-like macro usage. */
MACRO_FUNCTION_CALL (first_arg,second_arg);
```
* Modern C++ allows us to write expressions that are "executed", or evaluated at different times, but doesn't give us much in the way of differentiating between these different execution times syntactically. We propose using whitespace for this purpose to make complex interleaved usage of run-time code and compile-time code easier to read.
* This extends to other kinds of statements, to show whether "execution happens on this line"
```c++
/* In `example_array` below, we put a space between the name of the array and the `[5]`,
 * and put no spaces in `[5]` to emphasize that this is a definition of an array, not an access of an array. See below.*/
int example_array [5] = { 0, 1, 2, 3, 4 };
/* In the for loop below, we do not put a space between `for` and the parenthesis to keep in line with the theme that
 * this for loop is being executed at runtime.
 * We index example_array with `example_array[ i ]` with spaces in `[ i ]` to express that this is an array access not a definition, occuring at runtime. */
for( int i = 0; i < sizeof(example_array); ++i )
	std::printf( "Index %d of example_array contains the integer %d\n", i, example_array[ i ] );
/* In the constexpr if below, we put spaces between `if`, `constexpr`, and the parenthesis, but do not use spaces within
 * `(sizeof(example_array) == 5)` to express that this is not being evaluated at runtime, but at compile-time; that this
 * branch does not express a cost at runtime. */
if constexpr (sizeof(example_array) == 5) {
	// Code.
} else {
	// Code.
}
```
#Function Classes
* All the classes postfixed with \_F represent function classes, where all the functions in the class are static.
* Type aliases of Function Classes are postfixed with \_f, as type aliases of other types are postfixed with \_t.
