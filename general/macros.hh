/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#if    defined (SSC_PUBLIC) || defined (SSC_PRIVATE)
#	error 'Symbol Macro Already Defined'
#endif
/* Symbol visibility macros */
#if defined (SSC_BUILD_STATIC) || defined (SSC_IMPORT_STATIC)
#	define  SSC_PUBLIC
#	define  SSC_PRIVATE
#else
#	if    defined (_WIN32) || defined (__CYGWIN__)
#		ifdef	SSC_BUILD_DLL
#			ifdef	__GNUC__
#				define	SSC_PUBLIC __attribute__ ((dllexport))
#			else
#				define	SSC_PUBLIC __declspec(dllexport)
#			endif // ~ #ifdef __GNUC__
#		else
#			ifdef	__GNUC__
#				define	SSC_PUBLIC __attribute__ ((dllimport))
#			else
#				define	SSC_PUBLIC __declspec(dllimport)
#			endif // ~ #ifdef __GNUC__
#		endif // ~ #ifdef SSC_BUILD_DLL
#		define	SSC_PRIVATE
#	else
#		if    defined (__GNUC__) && (__GNUC__ >= 4)
#			define	SSC_PUBLIC  __attribute__ ((visibility ("default")))
#			define	SSC_PRIVATE __attribute__ ((visibility ("hidden")))
#		else
#			define	SSC_PUBLIC
#			define	SSC_PRIVATE
#		endif // ~ #if defined (__GNUC__) && (__GNUC__ >= 4)
#	endif // ~ #if defined (_WIN32) || defined (__CYGWIN__)
#endif // ~ #if defined (SSC_BUILD_STATIC) || defined (SSC_IMPORT_STATIC)

/* Operating System Macros */

#if    defined (__APPLE__) && defined (__MACH__)
#	ifndef SSC_OS_OSX
#		define SSC_OS_OSX
#	else
#		error 'SSC_OS_OSX Already Defined'
#	endif
#endif

/* Define OpenBSD, FreeBSD, GNU/Linux, and Mac OSX as UNIX-like operating systems. */
#if    defined (__OpenBSD__)   || \
       defined (__FreeBSD__)   || \
       defined (__gnu_linux__) || \
       defined (SSC_OS_OSX)
#	ifndef SSC_OS_UNIXLIKE
#		define SSC_OS_UNIXLIKE
#	else
#		error 'SSC_OS_UNIXLIKE Already Defined'
#	endif // ~ #ifndef SSC_OS_UNIXLIKE
/* Define MS Windows, naming scheme consistent with the above. */
#elif  defined (_WIN32) || defined (_WIN64)
#	ifndef SSC_OS_WINDOWS
#		define SSC_OS_WINDOWS
#	else
#		error 'SSC_OS_WINDOWS Already Defined'
#	endif
#else
#	error 'Unsupported OS'
#endif // ~ #if defined (__OpenBSD__) || defined (__FreeBSD__) || defined (__gnu_linux__)

/* Define 32-bit and 64-bit MS Windows, naming scheme consistent with the above. */
#ifdef SSC_OS_WINDOWS
#	ifndef	_WIN64
#		ifndef	SSC_OS_WIN32
#			define	SSC_OS_WIN32
#		else
#			error 'SSC_OS_WIN32 Already Defined'
#		endif // ~ #ifndef SSC_OS_WIN32
#	else
#		ifndef	SSC_OS_WIN64
#			define	SSC_OS_WIN64
#		else
#			error 'SSC_OS_WIN64 Already Defined'
#		endif // ~ #ifndef SSC_OS_WIN64
#	endif // ~ #ifndef _WIN64
#endif // ~ #ifndef SSC_OS_WINDOWS

/* Compile-Time-Constant short-hand macros. */
#ifdef SSC_RESTRICT
#	error 'SSC_RESTRICT Already Defined'
#endif
#define SSC_RESTRICT(pointer) pointer __restrict

/* OpenBSD-specific mitigations */
#ifdef	__OpenBSD__
#	if    defined (SSC_OPENBSD_UNVEIL) || defined (SSC_OPENBSD_PLEDGE)
#		error 'SSC_OPENBSD_UNVEIL or SSC_OPENBSD_PLEDGE already defined'
#	endif
#	include <ssc/general/error_conditions.hh>
#	include <unistd.h>
#	define SSC_OPENBSD_UNVEIL(path,permissions) \
		if( unveil( path, permissions ) != 0 ) \
			errx( "Failed to unveil()\n" )
#	define SSC_OPENBSD_PLEDGE(promises,execpromises) \
		if( pledge( promises, execpromises ) != 0 ) \
			errx( "pledge() failed\n" )
#else
#	define SSC_OPENBSD_UNVEIL(null0,null1)  // Define as nothing on Non-OpenBSD systems.
#	define SSC_OPENBSD_PLEDGE(null0,null1)  // Define as nothing on Non-OpenBSD systems.
#endif // ~ #ifdef __OpenBSD__

/* Simplification Macros */
#if    defined (SSC_MACRO_SHIELD) || defined (SSC_MACRO_SHIELD_EXIT)
#	error 'MACRO_SHIELD or MACRO_SHIELD_EXIT Already Defined'
#else
#	define SSC_MACRO_SHIELD		do {
#	define SSC_MACRO_SHIELD_EXIT	} while(0)
#endif
