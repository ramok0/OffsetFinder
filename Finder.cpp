#include "Finder.h"

uintptr_t Finder::EngineTick()
{
	uintptr_t stringOffset = scanner->FindPattern(".rdata", scanner->createStringPattern("r.OneFrameThreadLag", true));
	uintptr_t stringRef =scanner->FindPatternWithPredicate(".text", "48 8D 15 ?? ?? ?? ?? 41 ?? ??", [stringOffset](uintptr_t instructionAddress) {
		return scanner->GetAbsoluteAddress(instructionAddress, 7) == stringOffset;
	});

	//48 89 ?? ?? ?? 55 53 56 57

	spdlog::debug("engine tick string ref ptr : {0:d}", stringRef);

	uintptr_t pasLoin = scanner->ReverseFindPattern(".text", "41 54 41 55 41 56 41 57", stringRef, 0x2500);
	uintptr_t result = scanner->getStartOfFunction(pasLoin);
//spdlog::debug("Engine Tick Ptr : 0x{0:x}", result);
	spdlog::info("Engine Tick Offset : 0x{0:x}", result);
	return result;
}

uintptr_t Finder::Engine()
{
	uintptr_t Engine = scanner->FindPatternEx(".text", "41 B8 01 00 00 00 ?? ?? ?? 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0", 9, true, 7);
	spdlog::info("Engine Offset : 0x{0:x}", Engine - scanner->getBaseAddress());
	return Engine - scanner->getBaseAddress();
}

uintptr_t Finder::World(uintptr_t EngineTick)
{
	//
	cached_pe section = scanner->getPESection(".text");
	uintptr_t WorldRelative = scanner->FindPattern(section.second, section.first.VirtualAddress, 0x1000, scanner->patternToBytes("74 ? 48 8B 1D ? ? ? ?"), EngineTick-section.first.VirtualAddress);
	spdlog::info("WorldRelative Offset (+2 RVA 7) : 0x{0:x}", WorldRelative);
	//uint32_t offset = scanner->getProcess()->Read<uint32_t>(scanner->getBaseAddress()+ WorldRelative + 5);
	//printf("offset : %d\n", offset);
	uintptr_t World = scanner->GetAbsoluteAddress(scanner->getBaseAddress() + WorldRelative+2, 7);
	if (World) {
		spdlog::info("World Offset : 0x{0:x}", World - scanner->getBaseAddress());
	}
	else {
		spdlog::warn("Failed to get World offset");
	}
	return World - scanner->getBaseAddress();
}

uintptr_t Finder::FNamePoolFunction()
{
	uintptr_t stringOffset = scanner->FindPattern(".rdata", scanner->createStringPattern("DuplicatedHardcodedName", true));
	if (!stringOffset) {
		spdlog::critical("Failed to find 'DuplicatedHardcodedName' ptr");
		return 0;
	}
	uintptr_t stringRef = scanner->FindPatternWithPredicate(".text", "4C 8D 0D ? ? ? ? 4C", [stringOffset](uintptr_t instructionAddress) {
		return scanner->GetAbsoluteAddress(instructionAddress, 7) == stringOffset;
		});
	if (!stringRef) {
		spdlog::critical("Failed to find 'DuplicatedHardcodedName' reference");
		return 0;
	}

	spdlog::debug("FNamePool 'DuplicateHardcodedName' ref : {0:x}", stringRef - scanner->getBaseAddress());

	uintptr_t FNamePoolFunction = scanner->ReverseFindPattern(".text", "40 55 53 56 57", stringRef, 0x4000);
	spdlog::info("FNamePool::FNamePool Offset : 0x{0:x}", FNamePoolFunction - scanner->getBaseAddress());
	return FNamePoolFunction - scanner->getBaseAddress();
}

uintptr_t Finder::FNamePool(uintptr_t FNamePoolFunction)
{
	uintptr_t FNameFct = scanner->FindPatternWithPredicate(".text", "E8 ? ? ? ? C6", [FNamePoolFunction](uintptr_t instructionAddress) {
		return (scanner->GetAbsoluteAddress(instructionAddress, 5) - scanner->getBaseAddress()) == FNamePoolFunction;
	});

	spdlog::info("FName::FName => call FNamePool::FNamePool Offset : 0x{0:x}", FNameFct - scanner->getBaseAddress());
	uintptr_t FNamePoolRelative = scanner->ReverseFindPattern(".text", "74 ?? 48 8D ?? ?? ?? ??", FNameFct, 0x200);
	spdlog::debug("FNamePoolRelative Offset : 0x{0:x}", FNamePoolRelative);
	uintptr_t FNamePool = scanner->GetAbsoluteAddress(FNamePoolRelative + 2, 7);
	spdlog::info("FNamePool Offset : 0x{0:x}", FNamePool - scanner->getBaseAddress());
	return FNamePool - scanner->getBaseAddress();
}

uintptr_t Finder::ProcessEvent(uintptr_t Engine)
{
	if (scanner->getProcess() == nullptr) return 0;
	void* EngineR = scanner->getProcess()->Read<void*>(Engine + scanner->getBaseAddress());
	if (EngineR == 0) {
		spdlog::critical("Failed to read Engine, failed to find ProcessEvent");
		return 0;
	}
	spdlog::debug("Engine ptr : 0x{0:x}", (uintptr_t)EngineR);
	void* VTable = scanner->getProcess()->Read<void*>((uintptr_t)EngineR);
	spdlog::debug("VTable ptr : 0x{0:x}", (uintptr_t)VTable);


	for (int i = 10; i < 100; i++) {
		void* fct = scanner->getProcess()->Read<void*>((uintptr_t)VTable + (i*0x8));
		if (!fct) continue;
		UINT8 bytes[0x16];
		if (scanner->getProcess()->Read((uintptr_t)fct, 0x16 * sizeof(UINT8), bytes)) {
			std::vector<int> pattern = { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xec, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D };

			bool found = true;
			for (int k = 0; k < pattern.size(); k++) {
				if (pattern[k] != 0x00)
					found = bytes[k] == pattern[k];
			}

			if (found) {
				spdlog::trace("Found ProcessEvent at 0x{0:x}", i);
				spdlog::info("ProcessEvent Offset: 0x{0:x}", (uintptr_t)fct - scanner->getBaseAddress());
				return (uintptr_t)fct - scanner->getBaseAddress();
			}
		}
	}



	return 0;
 }

uintptr_t Finder::FMemoryFree(uintptr_t EngineTick)
{
	if (!EngineTick) {
		spdlog::critical("EngineTick is nullptr, aborting FMemory::Free");
		return 0;
	}

	cached_pe section = scanner->getPESection(".text");
	uintptr_t FreeRelative = scanner->FindPattern(section.second, section.first.VirtualAddress, 0x3000, scanner->patternToBytes("74 ?? 48 8B C8 E8 ?? ?? ?? ??"), EngineTick - section.first.VirtualAddress);
	spdlog::info("FreeRelative Offset (+5 RVA 5) : 0x{0:x}", FreeRelative);
	uintptr_t FreeOffset = scanner->GetAbsoluteAddress(scanner->getBaseAddress() + FreeRelative + 5, 5);
	if (!FreeOffset) {
		spdlog::critical("Failed to read FreeOffset");
		return 0;
	}

	if (FreeOffset) {
		spdlog::info("FMemory::Free Offset : 0x{0:x}", FreeOffset - scanner->getBaseAddress());
	}
	else {
		spdlog::warn("Failed to get FMemory::Free offset");
	}

	return FreeOffset - scanner->getBaseAddress();
}

uintptr_t Finder::Objects()
{
	uintptr_t DisableDisregardForGCptr = scanner->FindPattern(".rdata", scanner->createStringPattern("DisableDisregardForGC", false));
	if (!DisableDisregardForGCptr) {
		spdlog::critical("Failed to find 'DisableDisregardForGC' string ptr");
		return 0;
	}

	uintptr_t DisableDisregardForGCref = scanner->FindPatternWithPredicate(".text", "48 8D 15 ? ? ? ? 48 8D", [DisableDisregardForGCptr](uintptr_t instructionAddress) {
		return scanner->GetAbsoluteAddress(instructionAddress, 7) == DisableDisregardForGCptr;
	});

	if (!DisableDisregardForGCref) {
		spdlog::critical("Failed to find 'DisableDisregardForGC' string reference");
		return 0;
	}

	cached_pe pe = scanner->getPESection(".text");

	uintptr_t ObjectsRelative = scanner->FindPattern(pe.second, pe.first.BaseAddress, 0x40, scanner->patternToBytes("48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??"), DisableDisregardForGCref - pe.first.BaseAddress);
	if (!ObjectsRelative) {
		spdlog::critical("Failed to find FUObjectArray");
		return 0;
	}

	uintptr_t result = scanner->GetAbsoluteAddress(ObjectsRelative, 7);

	spdlog::info("FUObjectArray offset : 0x{0:x}", result - scanner->getBaseAddress());

	return result - scanner->getBaseAddress();
}
