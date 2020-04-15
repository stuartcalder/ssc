/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

namespace ssc::ctime
{
	template <typename T>
	constexpr T Return_Largest (T first, T second)
	{
		if (first > second)
			return first;
		return second;
	}
	template <typename T, typename... Args>
	constexpr T Return_Largest (T first, T second, Args... args)
	{
		T biggest = first;
		if (second > biggest)
			biggest = second;
		return Return_Largest( biggest, args... );
	}
	
	template <typename T>
	constexpr T Return_Smallest (T first, T second)
	{
		if (first < second)
			return first;
		return second;
	}
	template <typename T, typename... Args>
	constexpr T Return_Smallest (T first, T second, Args... args)
	{
		T smallest = first;
		if (second < smallest)
			smallest = second;
		return Return_Smallest( smallest, args... );
	}
}/* ~ namespace ssc::ctime */
