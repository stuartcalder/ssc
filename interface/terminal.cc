/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <memory>

#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/interface/terminal.hh>
#include <ssc/memory/os_memory_locking.hh>

#if    defined (SSC_OS_UNIXLIKE)
#	include <ncurses.h>
#elif  defined (SSC_OS_WIN64)
#	include <windows.h>
#	include <conio.h>
#else
#	error 'Unsupported OS'
#endif

#if     defined (LOCK_MEMORY)
#	error 'LOCK_MEMORY Already Defined'
#elif   defined (UNLOCK_MEMORY)
#	error 'UNLOCK_MEMORY Already Defined'
#endif

#ifdef SSC_FEATURE_MEMORYLOCKING
#	define   LOCK_MEMORY(address,size)   lock_os_memory( address, size )
#	define UNLOCK_MEMORY(address,size) unlock_os_memory( address, size )
#else
#	define   LOCK_MEMORY(address,size)
#	define UNLOCK_MEMORY(address,size)
#endif

namespace ssc {
	Terminal::Terminal (void) {
#if    defined (SSC_OS_UNIXLIKE)
		initscr();
		getmaxyx( stdscr, std_height, std_width );
		clear();
#elif  defined (SSC_OS_WIN64)
		system( "cls" );
#else
#	error 'Unsupported OS'
#endif
	}/*ssc::Terminal::Terminal{}*/
	Terminal::~Terminal (void) {
#if    defined (SSC_OS_UNIXLIKE)
		endwin();
#elif  defined (SSC_OS_WIN64)
		system( "cls" );
#else
#	error 'Unsupported OS'
#endif
	}/*ssc::Terminal::~Terminal{}*/
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
