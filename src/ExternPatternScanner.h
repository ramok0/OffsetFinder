#pragma once
#include "Process.h"
#include <spdlog/spdlog.h>
#include <vector>

typedef std::pair<PESection, std::uint8_t*> cached_pe;

class ExternPatternScanner {
private:
	Process* proc;
	uintptr_t baseAddress;
	std::vector<cached_pe> peCache{};
public:
	ExternPatternScanner(DWORD process_id) {
		this->proc = new Process(process_id);
		this->baseAddress = (uintptr_t)this->proc->GetMainModule();
		spdlog::debug("Created Process instance");
	}

	Process* getProcess() {
		return this->proc;
	}

	bool isEndOfFunction(std::uint8_t byte) {
		return byte == 0xCC || byte == 0xC3;
	}

	uintptr_t getStartOfFunction(uintptr_t instructionAddress) {
		cached_pe section = this->getPESection(".text");
		std::uint8_t* scanBytes = (std::uint8_t*)section.second;

		uintptr_t offset = instructionAddress - this->getBaseAddress();

		while (!isEndOfFunction(scanBytes[offset - 0x1000])) {
			offset--;
		}

		return offset+1;
	}

	//bool isReadable(uintptr_t address) {
	//	MEMORY_BASIC_INFORMATION info;
	//	if (VirtualQueryEx(this->proc->getHandle(), (LPCVOID)baseAddress, &info, sizeof(info))) {
	//		if (info.Protect == 0x2 || info.Protect == 0x20 || info.Protect == 0x4 || info.Protect == 0x40) {

	//		}
	//		else {
	//			printf("%llX is unreadable (0x%X)\n", address, info.Protect);
	//		}
	//	}
	//	else {
	//		return false;
	//	}
	//}

	void* cloneSection(uintptr_t baseAddress, DWORD size) 
	{
		DWORD ImageSize = sizeof(std::uint8_t) * size;
		void* Image = malloc(ImageSize);
		if (Image) {
			spdlog::debug("Successfully allocated {0:x} bytes", ImageSize);
			DWORD oldProtection = 0;
			VirtualProtectEx(this->proc->getHandle(), (LPVOID)baseAddress, size, PAGE_EXECUTE_READWRITE, &oldProtection);
			//for (uintptr_t i = baseAddress; i < baseAddress + size; i++) {
			//	isReadable(i);
			//}

			if (!this->proc->Read(baseAddress, size, Image)) {
				spdlog::critical("Failed to read section at address : {0:x}", baseAddress);
				spdlog::critical("ReadProcessMemory error : 0x{0:x}", GetLastError());
				spdlog::critical("ImageSize : 0x{0:x}", ImageSize);
			}
			else {
				spdlog::debug("Successfully readed section.");
				return Image;
			}
		}
		else {
			spdlog::critical("Failed to allocate {0:x} bytes", ImageSize);
		}

		return nullptr;
	}

	uintptr_t getBaseAddress() {
		return this->baseAddress;
	}

	cached_pe getPESection(const char* name) {
		for (cached_pe pe : peCache) {
			if (strcmp(pe.first.Name, name) == 0) {
				return pe;
			}
		}

		PESection pe_section = this->proc->getPESection(name, this->baseAddress);
		void* Image = cloneSection(pe_section.BaseAddress, pe_section.sizeOfSection);
		peCache.push_back({ pe_section, (std::uint8_t*)Image });
		return { pe_section, (std::uint8_t*)Image };
	}

	std::vector<int> patternToBytes(const char* pattern)
	{
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(0xFF);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	}

	uintptr_t GetAbsoluteAddress(uintptr_t pInstruction, unsigned int instruction_size) {
		if (!this->proc) return 0;
		uint32_t offset = 0;
		if (!this->proc->Read(pInstruction + (instruction_size - 4), sizeof(uint32_t), &offset)) {
			spdlog::critical("Failed to read relative offset");
			return 0;
		}
		return pInstruction + offset + instruction_size;
	}

	uintptr_t FindPattern(std::uint8_t* Image, uintptr_t base, size_t size, std::vector<int> pattern, unsigned long long skipBytes = 0)
	{
		size_t scanSize = size - pattern.size();
		for (unsigned long i = 0ul; i < scanSize; i++) {
			bool found = true;
			for (int k = 0; k < pattern.size() && found; k++) {
				if(pattern[k] != 0xFF)
					found = Image[i + skipBytes + k] == (std::uint8_t)pattern[k];
			}

			if (found) {
				return base+i+skipBytes;
			}
		}

		return 0;
	}

	std::vector<int> createStringPattern(const char* string, bool wide = false) {
		std::vector<int> result{};
		size_t length = strlen(string);
		for (int i = 0; i < length; i++) {
			result.push_back((int)string[i]);
			if (wide) {
				result.push_back(0x00);
			}
		}

		return result;
	}

	uintptr_t FindPattern(const char* sectionName, std::vector<int> pattern) {
		cached_pe section = this->getPESection(sectionName);
		std::uint8_t* scanBytes = section.second;
		uintptr_t result = FindPattern(scanBytes, section.first.BaseAddress, section.first.sizeOfSection, pattern);
		return result;
	}

	uintptr_t ReverseFindPattern(const char* sectionName, const char* pattern, uintptr_t instructionAddress, size_t range) 
	{
		std::vector<int> bytesPattern = this->patternToBytes(pattern);
		cached_pe section = this->getPESection(sectionName);
		std::uint8_t* scanBytes = section.second;

		return FindPattern(scanBytes, section.first.BaseAddress, range, bytesPattern, instructionAddress - section.first.VirtualAddress - range - this->getBaseAddress());
	}

	uintptr_t FindPatternWithPredicate(const char* sectionName, const char* pattern, std::function<bool(uintptr_t)> Predicate) {
		std::vector<int> bytesPattern = this->patternToBytes(pattern);
		cached_pe section = this->getPESection(sectionName);
		std::uint8_t* scanBytes = section.second;
		DWORD size = section.first.sizeOfSection;

		size_t scanSize = size - bytesPattern.size();
		for (unsigned long i = 0ul; i < scanSize; i++) {
			bool found = true;
			for (int k = 0; k < bytesPattern.size() && found; k++) {
				if (bytesPattern[k] != 0xFF)
					found = scanBytes[i + k] == (std::uint8_t)bytesPattern[k];
			}

			if (found && Predicate((uintptr_t)(section.first.BaseAddress + i))) {
				return section.first.BaseAddress + i;
			}
		}

		return 0;
	}

	uintptr_t FindPatternEx(const char* sectionName, const char* pattern, int skipBytes = 0, bool bRelative = false, int instruction_size = 0) {
		cached_pe section = this->getPESection(sectionName);
		std::uint8_t* scanBytes = section.second;
		uintptr_t result =  FindPattern(scanBytes, section.first.BaseAddress, section.first.sizeOfSection, this->patternToBytes(pattern));
		if (bRelative) {
			result = this->GetAbsoluteAddress(result+ skipBytes, instruction_size);
		}
		else {
			result += skipBytes;
		}
		return result;
	}

	~ExternPatternScanner() {
		delete this->proc;
		for (auto pe : peCache) {
			free(pe.second);
			spdlog::debug("Freed section {} from cache !", pe.first.Name);
		}
	}
};