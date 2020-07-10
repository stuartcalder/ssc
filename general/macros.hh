/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#if   !defined (__cplusplus) || (__cplusplus != 201703L)
#	error 'SSC needs c++17'
#endif // ~ !defined (__cplusplus) || (__cplusplus != 201703L)

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
#	ifdef SSC_OS_OSX
#		error 'SSC_OS_OSX already defined'
#	endif
#	define SSC_OS_OSX
#endif

/* Define the BSDs, GNU/Linux, and Mac OSX as UNIX-like operating systems. */
#if    defined (__OpenBSD__)   || \
       defined (__FreeBSD__)   || \
       defined (__NetBSD__)    || \
       defined (__gnu_linux__) || \
       defined (SSC_OS_OSX)
#	ifdef SSC_OS_UNIXLIKE
#		error 'SSC_OS_UNIXLIKE already defined'
#	endif
#	define SSC_OS_UNIXLIKE
/* Define MS Windows, naming scheme consistent with the above. */
#elif  defined (_WIN32)
#	ifdef SSC_OS_WINDOWS
#		error 'SSC_OS_WINDOWS already defined'
#	endif
#	define SSC_OS_WINDOWS
#	ifdef _WIN64
#		ifdef SSC_OS_WIN64
#			error 'SSC_OS_WIN64 already defined'
#		endif
#		define SSC_OS_WIN64
#	else
#		ifdef SSC_OS_WIN32
#			error 'SSC_OS_WIN32 already defined'
#		endif
#		define SSC_OS_WIN32
#	endif
#else
#	error 'Unsupported OS'
#endif // ~ #if defined (unixlike_os's...)

/* Compile-Time-Constant short-hand macros. */
#ifdef SSC_RESTRICT
#	error 'SSC_RESTRICT Already Defined'
#endif
#define SSC_RESTRICT(pointer) pointer __restrict

/* OpenBSD-specific mitigations */
#ifdef	__OpenBSD__
#	if    defined (SSC_OPENBSD_UNVEIL)
#		error 'SSC_OPENBSD_UNVEIL already defined'
#	elif  defined (SSC_OPENBSD_PLEDGE)
#		error 'SSC_OPENBSD_PLEDGE already defined'
#	endif
#	include <ssc/general/error_conditions.hh>
#	include <unistd.h>
#	define SSC_OPENBSD_UNVEIL(path,permissions) \
		if( unveil( path, permissions ) != 0 ) \
			errx( "Failed to unveil()\n" )
#	define SSC_OPENBSD_PLEDGE(promises,execpromises) \
		if( pledge( promises, execpromises ) != 0 ) \
			errx( "Failed to pledge()\n" )
#else
/* These macros define to nothing on non-OpenBSD operating systems.
 */
#	define SSC_OPENBSD_UNVEIL(null0,null1)
#	define SSC_OPENBSD_PLEDGE(null0,null1)
#endif // ~ #ifdef __OpenBSD__

/* Simplification Macros */
#if    defined (SSC_MACRO_SHIELD)
#	error 'SSC_MACRO_SHIELD already defined'
#elif  defined (SSC_MACRO_SHIELD_EXIT)
#	error 'SSC_MACRO_SHIELD_EXIT already defined'
#endif
#define SSC_MACRO_SHIELD	do {
#define SSC_MACRO_SHIELD_EXIT	} while(0)
