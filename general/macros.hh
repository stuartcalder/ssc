/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#if    defined (_PUBLIC) || defined (_PRIVATE)
#	error 'Symbol Macro Already Defined'
#endif
/* Symbol visibility macros */
#if defined (__BUILD_STATIC) || defined (__IMPORT_STATIC)
#	define	_PUBLIC
#	define	_PRIVATE
#else
#	if    defined (_WIN32) || defined (__CYGWIN__)
#		ifdef	__BUILD_DLL
#			ifdef	__GNUC__
#				define	_PUBLIC	__attribute__ ((dllexport))
#			else
#				define	_PUBLIC __declspec(dllexport)
#			endif /* ~ #ifdef __GNUC__ */
#		else
#			ifdef	__GNUC__
#				define	_PUBLIC __attribute__ ((dllimport))
#			else
#				define	_PUBLIC __declspec(dllimport)
#			endif /* ~ #ifdef __GNUC__ */
#		endif /* ~ #ifdef __BUILD_DLL */
#		define	_PRIVATE
#	else
#		if    defined (__GNUC__) && (__GNUC__ >= 4)
#			define	_PUBLIC  __attribute__ ((visibility ("default")))
#			define	_PRIVATE __attribute__ ((visibility ("hidden")))
#		else
#			define	_PUBLIC
#			define	_PRIVATE
#		endif /* ~ #if defined (__GNUC__) && (__GNUC__ >= 4) */
#	endif /* ~ #if defined (_WIN32) || defined (__CYGWIN__) */
#endif /* ~ #if defined (__BUILD_STATIC) || defined (__IMPORT_STATIC) */

/* Operating System Macros */

#if    defined (__APPLE__) && defined (__MACH__)
#	ifndef __Mac_OSX__
#		define __Mac_OSX__
#	else
#		error '__Mac_OSX__ Already Defined'
#	endif
#endif

/* Define OpenBSD, FreeBSD, GNU/Linux, and Mac OSX as UNIX-like operating systems. */
#if    defined (__OpenBSD__)   || \
       defined (__FreeBSD__)   || \
       defined (__gnu_linux__) || \
       defined (__Mac_OSX__)
#	ifndef __UnixLike__
#		define __UnixLike__
#	else
#		error '__UnixLike__ Already Defined'
#	endif /* ~ #ifndef __UnixLike__ */
/* Define MS Windows, naming scheme consistent with the above. */
#elif  defined (_WIN32) || defined (_WIN64)
#	ifndef __Windows__
#		define __Windows__
#	else
#		error '__Windows__ Already Defined'
#	endif /* ~ #ifndef __Windows__ */
#else
#	error 'Unsupported OS'
#endif /* ~ #if defined (__OpenBSD__) || defined (__FreeBSD__) || defined (__gnu_linux__) */

/* Define 32-bit and 64-bit MS Windows, naming scheme consistent with the above. */
#ifdef __Windows__
#	ifndef	_WIN64
#		ifndef	__Win32__
#			define __Win32__
#		else
#			error '__Win32__ Already Defined'
#		endif /* ~ #ifndef __Win32__ */
#	else
#		ifndef	__Win64__
#			define __Win64__
#		else
#			error '__Win64__ Already Defined'
#		endif /* ~ #ifndef __Win64__ */
#	endif /* ~ #ifndef _WIN64 */
#endif /* ~ #ifndef __Windows__ */

/* Compile-Time-Constant short-hand macros. */
#if    defined (_CTIME_CONST) || defined (_RESTRICT)
#	error '_CTIME_CONST or _RESTRICT Already Defined'
#endif
#define _CTIME_CONST(type) static constexpr const type
#define _RESTRICT(pointer) pointer __restrict

/* OpenBSD-specific mitigations */
#ifdef	__OpenBSD__
#	if    defined (_OPENBSD_UNVEIL) || defined (_OPENBSD_PLEDGE)
#		error '_OPENBSD_UNVEIL or _OPENBSD_PLEDGE already defined'
#	endif
#	include <ssc/general/error_conditions.hh>
#	include <unistd.h>
#	define _OPENBSD_UNVEIL(path,permissions) \
		if( unveil( path, permissions ) != 0 ) \
			errx( "Failed to unveil()\n" )
#	define _OPENBSD_PLEDGE(promises,execpromises) \
		if( pledge( promises, execpromises ) != 0 ) \
			errx( "pledge() failed\n" )
#else
#	define _OPENBSD_UNVEIL(null0,null1)  // Define as nothing on Non-OpenBSD systems.
#	define _OPENBSD_PLEDGE(null0,null1)  // Define as nothing on Non-OpenBSD systems.
#endif /* ~ #ifdef __OpenBSD__ */

/* Simplification Macros */
#if    defined (_MACRO_SHIELD) || defined (_MACRO_SHIELD_EXIT)
#	error '_MACRO_SHIELD or _MACRO_SHIELD_EXIT Already Defined'
#else
#	define _MACRO_SHIELD		do {
#	define _MACRO_SHIELD_EXIT	} while(0)
#endif
