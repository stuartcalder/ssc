/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#			endif /* ifdef __GNUC__ */
#		else
#			ifdef	__GNUC__
#				define	_PUBLIC __attribute__ ((dllimport))
#			else
#				define	_PUBLIC __declspec(dllimport)
#			endif /* ifdef __GNUC__ */
#		endif /* ifdef __BUILD_DLL */
#		define	_PRIVATE
#	else
#		if    defined (__GNUC__) && (__GNUC__ >= 4)
#			define	_PUBLIC  __attribute__ ((visibility ("default")))
#			define	_PRIVATE __attribute__ ((visibility ("hidden")))
#		else
#			define	_PUBLIC
#			define	_PRIVATE
#		endif /* if defined (__GNUC__) && (__GNUC__ >= 4) */
#	endif /* if defined (_WIN32) || defined (__CYGWIN__) */
#endif /* if defined (__BUILD_STATIC) || defined (__IMPORT_STATIC) */

/* Operating System Macros */

/* Define OpenBSD, FreeBSD, and GNU/Linux as UNIX-like operating systems. */
#if    defined (__OpenBSD__) || \
       defined (__FreeBSD__) || \
       defined (__gnu_linux__)
#	ifndef __UnixLike__
#		define __UnixLike__
#	else
#		error '__UnixLike__ Already Defined'
#	endif /* ifndef __UnixLike__ */
/* Define MS Windows, naming scheme consistent with the above. */
#elif  defined (_WIN32) || defined (_WIN64)
#	ifndef __Windows__
#		define __Windows__
#	else
#		error '__Windows__ Already Defined'
#	endif /* ifndef __Windows__ */
#else
#	error 'Unsupported OS'
#endif /* if defined (__OpenBSD__) || defined (__FreeBSD__) || defined (__gnu_linux__) */

/* Define 32-bit and 64-bit MS Windows, naming scheme consistent with the above. */
#ifdef __Windows__
#	ifndef	_WIN64
#		ifndef	__Win32__
#			define __Win32__
#		else
#			error '__Win32__ Already Defined'
#		endif /* ifndef __Win32__ */
#	else
#		ifndef	__Win64__
#			define __Win64__
#		else
#			error '__Win64__ Already Defined'
#		endif /* ifndef __Win64__ */
#	endif /* ifndef _WIN64 */
#endif /* ifndef __Windows__ */

/* Compile-Time-Constant short-hand macros. */
#ifndef	_CTIME_CONST
#	define _CTIME_CONST(type) static constexpr const type
#else
#	error '_CTIME_CONST Already Defined'
#endif /* ifndef _CTIME_CONST */
