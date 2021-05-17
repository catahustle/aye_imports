#include <Windows.h>

#include "include/aye_imports.hpp"

void sample_thread( )
{
	wrap_import( MessageBoxA, ( HWND )nullptr, ( LPCSTR )"123", ( LPCSTR )"123", ( UINT )0 );
}

int __stdcall _DllMainCRTStartup( HINSTANCE h_module, DWORD reason, LPVOID )
{
    if ( reason == DLL_PROCESS_ATTACH )
        wrap_import( CreateThread, ( LPSECURITY_ATTRIBUTES )nullptr, ( SIZE_T )0, reinterpret_cast< LPTHREAD_START_ROUTINE >( sample_thread ), ( LPVOID )nullptr, ( DWORD )0, ( LPDWORD )0 );

	return 1;
}