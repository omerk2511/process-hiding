#include "pch.h"
#include "iat_hook.h"

static const std::string TASKMGR_IMAGE = "Taskmgr.exe";

iat_hook::iat_hook(const std::string& function_name, void* hook) :
	_iat_entry(nullptr),
	_original_function(nullptr)
{
	auto taskmgr_module = reinterpret_cast<unsigned char*>(::GetModuleHandleA(TASKMGR_IMAGE.c_str()));
	if (!taskmgr_module)
	{
		throw std::exception("Could not get a handle to the Taskmgr module");
	}
	
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(taskmgr_module);
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(taskmgr_module + dos_header->e_lfanew);

	for (auto import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
			taskmgr_module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		import_descriptor->Name;
		import_descriptor++)
	{
		for (PIMAGE_THUNK_DATA ilt_entry = reinterpret_cast<PIMAGE_THUNK_DATA>(
				taskmgr_module + import_descriptor->OriginalFirstThunk),
			iat_entry = reinterpret_cast<PIMAGE_THUNK_DATA>(
				taskmgr_module + import_descriptor->FirstThunk);
			ilt_entry->u1.AddressOfData;
			ilt_entry++, iat_entry++)
		{
			auto raw_ilt_entry = *reinterpret_cast<unsigned long long*>(ilt_entry);
			if (!(raw_ilt_entry & 0x8000000000000000))
			{
				std::string import_name(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(taskmgr_module + ilt_entry->u1.AddressOfData)->Name);
				if (function_name == import_name)
				{
					_iat_entry = iat_entry;

					DWORD old_protect;
					::VirtualProtect(
						&iat_entry->u1.Function,
						sizeof(void*),
						PAGE_READWRITE,
						&old_protect
					);

					_original_function = reinterpret_cast<void*>(::InterlockedExchange64(
						reinterpret_cast<volatile long long*>(&iat_entry->u1.Function),
						reinterpret_cast<long long>(hook)
					));

					::VirtualProtect(
						&iat_entry->u1.Function,
						sizeof(void*),
						old_protect,
						&old_protect
					);

					return;
				}
			}
		}
	}
}

iat_hook::~iat_hook()
{
	try
	{
		if (_iat_entry && _original_function)
		{
			DWORD old_protect;
			::VirtualProtect(
				&_iat_entry->u1.Function,
				sizeof(void*),
				PAGE_READWRITE,
				&old_protect
			);

			::InterlockedExchange64(
				reinterpret_cast<volatile long long*>(&_iat_entry->u1.Function),
				reinterpret_cast<long long>(_original_function)
			);

			::VirtualProtect(
				&_iat_entry->u1.Function,
				sizeof(void*),
				old_protect,
				&old_protect
			);
		}
	} catch (...) { }
}

void* iat_hook::get_original_function() const
{
	return _original_function;
}
