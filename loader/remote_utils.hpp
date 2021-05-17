#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <unordered_map>

#include "../aye_imports/include/fnv.h"

namespace remote_utils
{
	struct c_module
	{
		std::uint32_t m_base;
		std::uint32_t m_size;
	};

	std::unordered_map< std::uint32_t, c_module > modules;
	HANDLE process;
	int pid;
	std::uint8_t* allocated = nullptr;

	char* to_lower( char* str )
	{
		int length = strlen( str );

		for ( int i = 0; i < length; ++i )
			str[ i ] = std::tolower( str[ i ] );

		return str;
	}	

	int get_process_id( const char* process_name )
	{
		HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof( entry );

		int pid = 0;

		Process32First( snapshot, &entry );
		do
		{
			if ( !_stricmp( process_name, entry.szExeFile ) )
			{
				pid = entry.th32ProcessID;
				break;
			}
		} while ( Process32Next( snapshot, &entry ) );

		CloseHandle( snapshot );

		return pid;
	}	

	void setup( HANDLE process_handle, int process_id )
	{
		process = process_handle;
		pid = process_id;
	}
	
	void free( std::uint8_t* address )
	{
		VirtualFreeEx( process, address, 0, MEM_RELEASE );
	}

	void shutdown( )
	{
		::remote_utils::free( allocated );
	}

	std::uint8_t* allocate( std::uint32_t size )
	{
		return reinterpret_cast< std::uint8_t* >( VirtualAllocEx( process, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
	}	

	template< typename T >
	void write( std::uint8_t* address, T* buffer, std::uint32_t size )
	{
		WriteProcessMemory( process, address, buffer, size, nullptr );
	}

	template< typename T = std::uint32_t >
	T read( std::uint8_t* address, std::uint32_t size )
	{
		T buffer;
		memset( &buffer, 0, sizeof( T ) );
		ReadProcessMemory( process, address, &buffer, size, nullptr );
		return buffer;
	}

	HANDLE create_thread( std::uint8_t* function, std::uint8_t* arg = nullptr, bool wait = false )
	{
		HANDLE thread = CreateRemoteThread( process, nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( function ), arg, 0, nullptr );

		if ( thread && wait )
		{
			WaitForSingleObject( thread, INFINITE );
			CloseHandle( thread );
			return nullptr;
		}

		return thread;
	}

	void load_library( const char* module_name )
	{
		std::uint32_t length = strlen( module_name ) + 1;
		std::uint8_t* allocated_module_name = allocate( length );
		write( allocated_module_name, module_name, length );
		create_thread( reinterpret_cast< std::uint8_t* >( LoadLibraryA ), allocated_module_name, true );
	}

	c_module get_module_data( char* module_name )
	{
		std::uint32_t hash = FNV1A_RT( to_lower( module_name ) );
		if ( modules.find( hash ) != modules.end( ) )
			return modules[ hash ];

		c_module data;
		memset( &data, 0, sizeof( c_module ) );
		bool found = false;

		HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid );
		MODULEENTRY32 entry;
		entry.dwSize = sizeof( entry );

		Module32First( snapshot, &entry );
		do
		{
			if ( !_stricmp( module_name, entry.szModule ) )
			{
				data.m_base = reinterpret_cast< std::uint32_t >( entry.modBaseAddr );
				data.m_size = entry.modBaseSize;
				found = true;
				break;
			}
		} while ( Module32Next( snapshot, &entry ) );

		CloseHandle( snapshot );

		if ( !found )
		{
			load_library( module_name );
			return get_module_data( module_name );
		}

		modules[ hash ] = data;

		return data;
	}

	std::uint32_t get_proc_address( char* module_name, const char* proc_name = nullptr, bool is_ordinal = false, std::uint32_t ordinal = 0 )
	{
		if ( !allocated )
			allocated = allocate( 0x1000 );

		std::uint32_t place = 0;

		c_module data;
		std::uint32_t hash = FNV1A_RT( to_lower( module_name ) );

		std::uint8_t* allocated_proc_name = nullptr;
		if ( !is_ordinal )
		{
			allocated_proc_name = allocated + place;
			place += strlen( proc_name ) + 1;
			write( allocated_proc_name, proc_name, strlen( proc_name ) + 1 );
		}
		
		data = get_module_data( module_name );

		std::uint8_t get_proc_address_thread_buf[ 27 ] =
		{
			0x68, 0x00, 0x00, 0x00, 0x00,			//push proc name 
			0x68, 0x00, 0x00, 0x00, 0x00,			//push module address 
			0xB8, 0x00, 0x00, 0x00, 0x00,			//mov eax, GetProcAddress 
			0xFF, 0xD0,								//call eax 
			0xA3, 0x00, 0x00, 0x00, 0x00,			//mov result, eax 
			0x33, 0xC0,								//xor eax, eax (eax = 0) 
			0xC2, 0x04, 0x00						//retn 4 
		};

		std::uint8_t* allocated_result = allocated + place;
		place += 4;

		*( std::uint32_t* )( get_proc_address_thread_buf + 0x01 ) = is_ordinal ? ordinal : ( unsigned long )allocated_proc_name;
		*( std::uint32_t* )( get_proc_address_thread_buf + 0x06 ) = data.m_base;
		*( std::uint32_t* )( get_proc_address_thread_buf + 0x0B ) = reinterpret_cast< std::uint32_t >( GetProcAddress );
		*( std::uint32_t* )( get_proc_address_thread_buf + 0x12 ) = reinterpret_cast< std::uint32_t >( allocated_result );

		std::uint8_t* allocated_thread_buffer = allocated + place;
		place += sizeof( get_proc_address_thread_buf );
		write( allocated_thread_buffer, get_proc_address_thread_buf, sizeof( get_proc_address_thread_buf ) );
		create_thread( allocated_thread_buffer, nullptr, true );
		
		std::uint32_t result = read( allocated_result, 4 );

		static std::uint8_t zeros[ 0x1000 ];
		if ( zeros[ 0 ] != 0 )
			memset( zeros, 0, 0x1000 );
		write( allocated, zeros, 0x1000 );

		return result;
	}	
}