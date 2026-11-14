#pragma once
#include <cstdint>
#include <vector>

namespace hr {

// Private heap of the core module (all operator new/delete of this module allocate here)
void* core_heap();
// Allocation bases (VirtualQuery AllocationBase) currently used by the private heap: the background scan skips these allocations
std::vector<uintptr_t> core_heap_allocations();

} // namespace hr
