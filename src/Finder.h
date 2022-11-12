#pragma once

#include "ExternPatternScanner.h"

extern ExternPatternScanner* scanner;

class Finder {
public:
	static uintptr_t EngineTick();
	static uintptr_t EngineTick2();
	static uintptr_t Engine();
	static uintptr_t World2();
	static uintptr_t World(uintptr_t EngineTick);
	static uintptr_t FNamePoolFunction();
	static uintptr_t FNamePool(uintptr_t FNamePoolFunction);
	static uintptr_t ProcessEvent(uintptr_t Engine);
	static uintptr_t FMemoryFree(uintptr_t EngineTick);
	static uintptr_t Objects();
};