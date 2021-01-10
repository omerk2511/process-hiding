#pragma once

#include <string>

class iat_hook final
{
public:
	explicit iat_hook(const std::string& function_name, void* hook);
	~iat_hook();

public:
	iat_hook(const iat_hook&) = delete;
	iat_hook& operator=(const iat_hook&) = delete;

public:
	void* get_original_function() const;

private:
	PIMAGE_THUNK_DATA _iat_entry;
	void* _original_function;
};
