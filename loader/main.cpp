#include <Windows.h>

#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include "remote_utils.hpp"
#include "hde/hde32.h"

#define report_error( message ) { std::cout << message << std::endl; system( "pause" ); return 1; }
#define log_error( message ) { std::cout << message <<< std::endl; }
#define log( message, ... ) { printf( message, __VA_ARGS__ ); std::cout << std::endl; }

std::uint32_t generate_key( const std::uint32_t hash )
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

struct c_export
{
	std::string module_name;
	std::string proc_name;
};

std::unordered_map< std::uint32_t, c_export > parse_exports( )
{
	std::vector< std::string > modules = {
		"kernel32.dll", "user32.dll"
	};

	std::unordered_map < std::uint32_t, c_export > exports;

	for ( auto mod : modules )
	{
		std::uint8_t* module_base = reinterpret_cast< std::uint8_t* >( LoadLibraryA( mod.c_str( ) ) );

		IMAGE_NT_HEADERS* nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( module_base + reinterpret_cast< IMAGE_DOS_HEADER* >( module_base )->e_lfanew );

		IMAGE_EXPORT_DIRECTORY* export_dir = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( module_base + nt_headers->OptionalHeader.DataDirectory[ 0 ].VirtualAddress );

		std::uint32_t* m_pFunctionsTable = reinterpret_cast< std::uint32_t* >( module_base + export_dir->AddressOfFunctions );
		std::uint16_t* m_pOrdinalTable = reinterpret_cast< std::uint16_t* >( module_base + export_dir->AddressOfNameOrdinals );
		std::uint32_t* m_pNamesTable = reinterpret_cast< std::uint32_t* >( module_base + export_dir->AddressOfNames );

		for ( DWORD i = 0; i < export_dir->NumberOfNames; i++ )
		{
			c_export exp;
			exp.module_name = mod;
			exp.proc_name = std::string( reinterpret_cast< char* >( module_base + m_pNamesTable[ i ] ) );

			exports[ FNV1A_RT( reinterpret_cast< char* >( module_base + m_pNamesTable[ i ] ) ) ] = exp;
		}
	}	

	return exports;
}

void process_imports( std::vector< std::uint8_t >& image, IMAGE_NT_HEADERS* nt_headers )
{
	std::uint8_t* imports_redirect = remote_utils::allocate( 0x1000 );
	int place = 0;

	if ( nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress )
	{
		IMAGE_IMPORT_DESCRIPTOR* import_desc = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( image.data( ) + nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

		for ( ; import_desc->Name; import_desc++ )
		{
			char* module_name = reinterpret_cast< char* >( image.data( ) + import_desc->Name );

			IMAGE_THUNK_DATA* thunk_data = nullptr;
			IMAGE_THUNK_DATA* func_data = reinterpret_cast< IMAGE_THUNK_DATA* >( image.data( ) + import_desc->FirstThunk );

			if ( import_desc->OriginalFirstThunk )
				thunk_data = reinterpret_cast< IMAGE_THUNK_DATA* >( image.data( ) + import_desc->OriginalFirstThunk );
			else
				thunk_data = reinterpret_cast< IMAGE_THUNK_DATA* >( image.data( ) + import_desc->FirstThunk );

			if ( !thunk_data || !func_data )
				continue;

			for ( ; thunk_data->u1.AddressOfData; thunk_data++, func_data++ )
			{
				std::uint32_t proc_address = 0;
				std::uint32_t key = 0;

				if ( IMAGE_SNAP_BY_ORDINAL( thunk_data->u1.Ordinal ) )
				{
					proc_address = remote_utils::get_proc_address( module_name, nullptr, true, thunk_data->u1.Ordinal & 0xFFFF );
					key = generate_key( FNV1A_RT( module_name ) );
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* import_by_name = reinterpret_cast< IMAGE_IMPORT_BY_NAME* >( image.data( ) + thunk_data->u1.AddressOfData );
					proc_address = remote_utils::get_proc_address( module_name, import_by_name->Name );
					key = generate_key( FNV1A_RT( import_by_name->Name ) );
					memset( import_by_name->Name, 0, strlen( import_by_name->Name ) );
					import_by_name->Hint = 0;
				}

				std::uint8_t redirect_buf[ ] = {
					0xb8, 0x00, 0x00, 0x00, 0x00,		// mov eax, address
					0x35, 0x00, 0x00, 0x00, 0x00,		// xor eax, key
					0xff, 0xe0							// jmp eax
				};

				*( std::uint32_t* )( redirect_buf + 1 ) = proc_address ^ key;
				*( std::uint32_t* )( redirect_buf + 6 ) = key;

				remote_utils::write( imports_redirect + place, redirect_buf, sizeof( redirect_buf ) );
				func_data->u1.Function = reinterpret_cast< std::uint32_t >( imports_redirect + place );

				place += sizeof( redirect_buf );
			}

			memset( module_name, 0, strlen( module_name ) );
			memset( import_desc, 0, sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
		}
	}	

	auto exports = parse_exports( );

	IMAGE_SECTION_HEADER* current_section = IMAGE_FIRST_SECTION( nt_headers );
	for ( std::uint32_t i = 0; i != nt_headers->FileHeader.NumberOfSections; ++i, ++current_section )
	{
		if ( current_section->Characteristics & IMAGE_SCN_MEM_EXECUTE || current_section->Characteristics & IMAGE_SCN_CNT_CODE )
		{
			std::uint32_t section_address = reinterpret_cast< std::uint32_t >( image.data( ) + current_section->VirtualAddress );

			for ( std::uint32_t current_address = section_address; current_address < section_address + current_section->SizeOfRawData; )
			{
				hde32s hs;
				std::uint32_t instr_length = hde32_disasm( reinterpret_cast< void* >( current_address ), &hs );

				if ( instr_length >= 5 )
				{
					std::uint32_t* possible_hash = reinterpret_cast< std::uint32_t* >( current_address + instr_length - 4 );
					if ( exports.find( *possible_hash ) != exports.end( ) )
					{
						c_export& exp = exports[ *possible_hash ];
						char* module_name = new char[ exp.module_name.length( ) + 1 ];
						memcpy( module_name, exp.module_name.c_str( ), exp.module_name.length( ) + 1 );
						std::uint32_t proc_address = remote_utils::get_proc_address( module_name, exp.proc_name.c_str( ) );
						*possible_hash = proc_address ^ generate_key( FNV1A_RT( exp.proc_name.c_str( ) ) );

						log( "[+] Found xored import entry %s", exp.proc_name.c_str( ) );
					}
				}

				current_address += instr_length;
			}
		}
	}

	log( "[+] Processed imports" );
}

void relocate_image( std::vector< std::uint8_t >& image, std::uint32_t allocated_base, IMAGE_NT_HEADERS* nt_headers )
{
	IMAGE_BASE_RELOCATION* base_relocation = reinterpret_cast< IMAGE_BASE_RELOCATION* >( image.data( ) + nt_headers->OptionalHeader.DataDirectory[ 5 ].VirtualAddress );

	std::uint32_t delta = allocated_base - nt_headers->OptionalHeader.ImageBase;

	if ( !delta )
	{
		log( "[+] No need in relocation" );
		return;
	}

	std::uint32_t bytes = 0;
	while ( bytes < nt_headers->OptionalHeader.DataDirectory[ 5 ].Size )
	{
		std::uint32_t reloc_base = reinterpret_cast< std::uint32_t >( image.data( ) + base_relocation->VirtualAddress );
		std::uint32_t reloc_count = ( base_relocation->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( std::uint16_t );
		std::uint16_t* reloc_data = reinterpret_cast< std::uint16_t* >( ( std::uint32_t )base_relocation + sizeof( IMAGE_BASE_RELOCATION ) );

		for ( unsigned int i = 0; i < reloc_count; i++ )
		{
			if ( ( ( *reloc_data >> 12 ) & 3 ) )
				*reinterpret_cast< std::uint32_t* >( reloc_base + ( *reloc_data & 0xFFF ) ) += delta;

			reloc_data++;
		}

		bytes += base_relocation->SizeOfBlock;
		base_relocation = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reloc_data );
	}

	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION( nt_headers );
	for ( int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++ )
	{
		if ( !strcmp( ".reloc", ( char* )section_header[ i ].Name ) )
		{
			void* m_pDest = image.data( ) + section_header[ i ].PointerToRawData;
			memset( m_pDest, 0, section_header[ i ].SizeOfRawData );
		}
	}

	log( "[+] Relocated image" );
}

struct c_loader_data
{
	std::uint32_t module_base;
	std::uint32_t entry;
	std::uint32_t tls_dir;
};

int main( )
{
	int pid = remote_utils::get_process_id( "csgo.exe" );
	if ( !pid )
		report_error( "[-] Failed to find process id" );

	HANDLE process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if ( !process )
		report_error( "[-] Failed to open target process" );

	log( "[+] Opened target process" );

	remote_utils::setup( process, pid );

	std::vector< std::uint8_t > raw_image;
	std::vector< std::uint8_t > mapped_image;

	std::ifstream file( "sample.dll", std::ios::binary );
	file.unsetf( std::ios::skipws );
	file.seekg( 0, std::ios::end );

	const auto raw_size = file.tellg( );

	file.seekg( 0, std::ios::beg );
	raw_image.reserve( static_cast< uint32_t >( raw_size ) );
	raw_image.insert( raw_image.begin( ), std::istream_iterator< std::uint8_t >( file ), std::istream_iterator< std::uint8_t >( ) );

	file.close( );

	log( "[+] Read binary file" );

	IMAGE_DOS_HEADER* dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( raw_image.data( ) );
	IMAGE_NT_HEADERS* nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( raw_image.data( ) + dos_header->e_lfanew );

	mapped_image.resize( nt_headers->OptionalHeader.SizeOfImage );
	memcpy( mapped_image.data( ), raw_image.data( ), nt_headers->OptionalHeader.SizeOfHeaders );

	IMAGE_SECTION_HEADER* current_section = IMAGE_FIRST_SECTION( nt_headers );
	for ( std::uint32_t i = 0; i != nt_headers->FileHeader.NumberOfSections; ++i, ++current_section )
		if ( current_section->SizeOfRawData )
			memcpy( mapped_image.data( ) + current_section->VirtualAddress, raw_image.data( ) + current_section->PointerToRawData, current_section->SizeOfRawData );

	raw_image.clear( );

	nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( mapped_image.data( ) + reinterpret_cast< IMAGE_DOS_HEADER* >( mapped_image.data( ) )->e_lfanew );

	std::uint8_t* allocated_base = remote_utils::allocate( nt_headers->OptionalHeader.SizeOfImage );

	process_imports( mapped_image, nt_headers );
	relocate_image( mapped_image, reinterpret_cast< std::uint32_t >( allocated_base ), nt_headers );

	remote_utils::write( allocated_base, mapped_image.data( ), mapped_image.size( ) );

	c_loader_data loader_data;
	loader_data.entry = nt_headers->OptionalHeader.AddressOfEntryPoint;
	loader_data.module_base = reinterpret_cast< std::uint32_t >( allocated_base );
	loader_data.tls_dir = nt_headers->OptionalHeader.DataDirectory[ 9 ].Size ?
		nt_headers->OptionalHeader.DataDirectory[ 9 ].VirtualAddress :
		0;

	std::uint8_t shell[ ] =
	{
	  0x55,									// push ebp
	  0x8B, 0xEC,							// mov ebp, esp
	  0x57,									// push edi
	  0x8B, 0x7D, 0x08,						// mov edi, [ebp+8]
	  0x83, 0x7F, 0x08, 0x00,				// cmp dword ptr [edi+8], 0
	  0x74, 0x28,							// jz 0xa
	  0x8B, 0x07,							// mov eax, [edi]
	  0x03, 0x47, 0x08,						// add eax, [edi+8]
	  0x56,									// push esi
	  0x8B, 0x70, 0x0C,						// mov esi, [eax+0xC]
	  0x85, 0xF6,							// test esi, esi
	  0x74, 0x1A,							// jz 0x1c
	  0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,	// nop
	  0x8B, 0x0E,							// mov ecx, [esi]
	  0x85, 0xC9,							// test ecx, ecx
	  0x74, 0x0E,							// jz 0x10
	  0x8B, 0x07,							// mov eax, [edi]
	  0x6A, 0x00,							// push 0
	  0x6A, 0x01,							// push 1
	  0x50,									// push eax,
	  0xFF, 0xD1,							// call ecx
	  0x83, 0xC6, 0x04,						// add esi, 4
	  0x75, 0xEC,							// jnz 0xffffffee
	  0x5E,									// pop esi
	  0x8B, 0x4F, 0x04,						// mov ecx, [edi+4]
	  0x03, 0x0F,							// add ecx, [edi]
	  0x8B, 0x07,							// mov eax, [edi]
	  0x6A, 0x00,							// push 0
	  0x6A, 0x01,							// push 1
	  0x50,									// push eax
	  0xFF, 0xD1,							// call ecx
	  0x5F,									// pop edi
	  0x5D,									// pop ebp
	  0xC3									// retn
	};

	std::uint8_t* allocated_shell = remote_utils::allocate( sizeof( shell ) + sizeof( c_loader_data ) );
	remote_utils::write( allocated_shell, shell, sizeof( shell ) );
	remote_utils::write( allocated_shell + sizeof( shell ), &loader_data, sizeof( c_loader_data ) );

	remote_utils::create_thread( allocated_shell, allocated_shell + sizeof( shell ), true );

	remote_utils::free( allocated_shell );
	remote_utils::shutdown( );
	CloseHandle( process );

	return 0;
}