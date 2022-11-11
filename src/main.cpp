#include <iostream>
#include <fstream>
#include <format>
#include "ExternPatternScanner.h"
#include "Finder.h"

#define TOIDA(addr) addr - scanner->getBaseAddress() + 0x140000000

ExternPatternScanner* scanner;

int main(int argc, char **argv)
{
	DWORD dwProcessId = 0;
	for (int i = 0; i < argc; i++) 
	{
		char* arg = argv[i];
		if (strstr(arg, "--trace")) {
			spdlog::set_level(spdlog::level::trace);
			break;
		}
		else if (strstr(arg, "--pid=")) {
			char* endPtr;
			dwProcessId = strtol(&arg[4], &endPtr, 10);
		}
	}

	if (dwProcessId == 0) {
		HWND window = FindWindowA("UnrealWindow", nullptr);
		if (window && IsWindow(window)) {
			GetWindowThreadProcessId(window, &dwProcessId);
		}
		else {
			spdlog::error("No PID found");
			return 1;
		}
	}

	spdlog::set_pattern("[%^%l%$] %v");
	spdlog::info("Welcome to Ramok's goofy aww UE 4.25-4.47 unstable broken offset dumper ");
	scanner = new ExternPatternScanner(dwProcessId);
	uintptr_t EngineTick        =	Finder::EngineTick();
	uintptr_t World             =	Finder::World(EngineTick);
	uintptr_t Engine            =	Finder::Engine();
	uintptr_t FNamePoolFunction =	Finder::FNamePoolFunction();
	uintptr_t FNamePool         =	Finder::FNamePool(FNamePoolFunction);
	uintptr_t Objects           =	Finder::Objects();
	uintptr_t FMemoryFree       =	Finder::FMemoryFree(EngineTick);
	uintptr_t ProcessEvent      =	Finder::ProcessEvent(Engine);

	char ProcFileName[MAX_PATH];	
	if (GetModuleFileNameExA(scanner->getProcess()->getHandle(), scanner->getProcess()->GetMainModule(true), ProcFileName, MAX_PATH)) {
		int lastIndex = 0;
		for (int i = 0; i < strlen(ProcFileName); i++) {
			if (ProcFileName[i] == '\\')
				lastIndex = i;
		}
		lastIndex++;
		ProcFileName[strlen(ProcFileName) - 4] = '\0';
		std::string fileName = &ProcFileName[lastIndex];
		fileName += "-offsetdump.txt";

		std::ofstream result = std::ofstream(fileName);
		auto const time = std::chrono::current_zone()->to_local(std::chrono::system_clock::now());
		result << "## THIS DUMP MAY BE PARTIALLY UNACCURATE." << std::endl << std::endl;
		result << std::format("Dumped at :  {:%Y-%m-%d %X}", time) << std::endl;
		result << "Offset dump for " << &ProcFileName[lastIndex] << std::endl << std::endl << std::endl << std::endl;
		result << std::format("FEngineLoop::Tick : 0x{0:x}", EngineTick) << std::endl;
		result << std::format("GWorld : 0x{0:x}", World) << std::endl;
		result << std::format("GEngine : 0x{0:x}", Engine) << std::endl;
		result << std::format("FNamePool::FNamePool : 0x{0:x}", FNamePoolFunction) << std::endl;
		result << std::format("FNamePool : 0x{0:x}", FNamePool) << std::endl;
		result << std::format("TUObjectArray : 0x{0:x}", Objects) << std::endl;
		result << std::format("FMemory::Free : 0x{0:x}", FMemoryFree) << std::endl;
		result << std::format("UObject::ProcessEvent : 0x{0:x}", ProcessEvent) << std::endl;
		result << std::flush;
		result.close();
	}

	scanner->~ExternPatternScanner();
	Sleep(15000);
}