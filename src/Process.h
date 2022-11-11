#pragma once
#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

#include <spdlog/spdlog.h>

struct PESection {
	uintptr_t BaseAddress;
	DWORD VirtualAddress;
	DWORD sizeOfSection;
	char Name[8];
};

class Process {
private:
	HANDLE hProcess;
	DWORD dwProcessId;
public:
	Process(DWORD dwProcessId) {
		this->dwProcessId = dwProcessId;
		this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
		if (this->hProcess == INVALID_HANDLE_VALUE) {
			throw "failed to create handle";
		}

		spdlog::debug("Opened Process handle");
	}


	HANDLE getHandle() {
		return this->hProcess;
	}


	~Process() {
		CloseHandle(hProcess);
	}

	HMODULE GetMainModule(bool silent = false) 
	{
		HMODULE hMods[1024];
		DWORD cbNeeded = 0;
		if (!EnumProcessModules(this->hProcess, hMods, sizeof(hMods), &cbNeeded)) {
			throw "failed to enumerate modules";
		}

		if (!silent) {
			spdlog::debug("Process baseAddress : {0:x}", (uintptr_t)hMods[0]);
		}

		return hMods[0];
	}

	template <typename T> T Read(uintptr_t Address) {
		T buffer;
		if (!ReadProcessMemory(hProcess, (LPCVOID)Address, &buffer, sizeof(buffer), 0)) {
			throw "failed to read memory";
		}

		return buffer;
	}

	bool Read(uintptr_t Address, DWORD size, void* buffer) {
		if (!ReadProcessMemory(this->hProcess, (LPCVOID)Address, buffer, size, 0)) {
			return false;
		}

		return true;
	}

	PESection getPESection(const char* name, uintptr_t moduleBase) {
		LONG fieldOffset = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader);

		IMAGE_DOS_HEADER dosHeaders = this->Read<IMAGE_DOS_HEADER>(moduleBase);
		IMAGE_NT_HEADERS ntHeaders = this->Read<IMAGE_NT_HEADERS>(moduleBase + dosHeaders.e_lfanew);
		WORD NumberOfSections = ntHeaders.FileHeader.NumberOfSections;
		uintptr_t firstSection = moduleBase + dosHeaders.e_lfanew + ntHeaders.FileHeader.SizeOfOptionalHeader + fieldOffset;
		IMAGE_SECTION_HEADER section = this->Read<IMAGE_SECTION_HEADER>(firstSection);
		for (unsigned int i = 0; i < NumberOfSections; i++, section = this->Read<IMAGE_SECTION_HEADER>(firstSection + (sizeof(IMAGE_SECTION_HEADER) * i))) {
			if (strcmp(name, reinterpret_cast<const char*>(section.Name)) == 0) {
				PESection parsedSection = {0};
				parsedSection.BaseAddress = moduleBase + section.VirtualAddress;
				parsedSection.VirtualAddress = section.VirtualAddress;
				size_t sizeOfName = strlen(reinterpret_cast<const char*>(section.Name));
				for (unsigned int k = 0; k < sizeOfName; k++) {
					parsedSection.Name[k] = section.Name[k];
				}
				parsedSection.Name[sizeOfName] = '\0';
				parsedSection.sizeOfSection = section.SizeOfRawData;
				return parsedSection;
			}
		}
		return PESection();
	}
};