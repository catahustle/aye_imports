#pragma once

#include <cstdint>
#include <cstddef>

#include "fnv.h"

namespace imports
{
	constexpr std::uint32_t generate_key( const std::uint32_t hash )
	{
		return ( ~( hash * 0xa24a7c ) ^
			0xcfc9 ^
			( hash * 0x5a99 ) ^
			0x57f3aaa9 ^
			~( hash * 0x84575a ) ^
			0x51f6 ^
			( hash * 0x1cd2 ) ^
			0x7dee4b90 ^
			~( hash * 0x38ab64 ) ^
			0x661198b );
	}

	template< typename T >
	__forceinline auto load_to_eax( T val )
	{
		return val;
	}

	template< typename ret, typename... args >
	__forceinline auto wrap( const std::uint32_t hash, volatile const std::uint32_t key, ret( __stdcall * function )( args... ), args... arguments )
	{
		volatile std::uint32_t pidoras = hash;
		ret( __stdcall * fn )( args... ) = reinterpret_cast< decltype( fn ) >( load_to_eax( ( std::uint32_t )( pidoras ) ^ key ) );
		fn( arguments... );
	}
}

#define wrap_import( function, ... ) imports::wrap( FNV1A( #function ), imports::generate_key( FNV1A( #function ) ), function, __VA_ARGS__ ) 