
# Kernel-Toolkit

A powerful and flexible framework for implementing Windows kernel exploits.

## Overview

Kernel-Toolkit is a sophisticated C++ framework designed to assist security researchers and exploit developers in prototyping, testing, and implementing Windows kernel exploits. The toolkit provides abstractions for common kernel operations, making it easier to interact with the Windows kernel in a controlled and structured manner.

## Features

- **Driver Loading/Unloading**: Seamlessly load and unload vulnerable drivers for exploitation
- **Memory Manipulation**: Read from and write to kernel and process memory spaces
- **Function Calling**: Call kernel functions directly from usermode
- **Process and Module Management**: Find and interact with processes and their modules
- **Context Management**: Easily switch between process contexts for memory operations
- **Pattern Scanning**: Find specific byte patterns in kernel modules
- **Driver Trace Clearing**: Cover your tracks by clearing traces of loaded drivers
- **PDB Symbol Resolution**: Resolve Windows kernel structures using PDB information

## Core Components

- **Context**: The central class that orchestrates all operations
- **DriverLoader**: Handles loading and unloading of drivers
- **ObjectFetcher**: Retrieves kernel objects, modules, and processes
- **FunctionCaller**: Facilitates calling kernel functions
- **Memory**: Provides memory reading and writing capabilities
- **Syscall**: Manages system call mechanisms

## Usage Example

```cpp
#include "Context.hpp"

int main() {
    // Initialize the kernel toolkit with a driver name
    Kernel::Context context("YourDriverName");
    
    if (!context.Initilize()) {
        printf("Failed to initialize kernel toolkit\n");
        return 1;
    }
    
    // Get process object by name hash
    uint64_t processObj = context.FetchProcess(HashString_("notepad.exe"), true);
    
    // Get process context
    uint64_t processCtx = context.FetchContext(processObj, false);
    
    // Switch to process context
    uint64_t prevCtx = Kernel::Memory::SetContext(processCtx);
    
    // Perform memory operations
    // ...
    
    // Restore previous context
    Kernel::Memory::SetContext(prevCtx);
    
    // Clean up and shutdown
    context.Shutdown();
    
    return 0;
}
```

## Advanced Features

### Kernel Function Calling

The toolkit allows calling kernel functions directly, which is particularly useful for exploitation:

```cpp
// Initialize function caller for a specific function
context.InitilizeFunctionCaller(HashString_("NtGdiEngStretchBlt"));

// Call a kernel function
uint64_t threadObj = context.GetFunction()->Call<uint64_t>(HashString_("PsGetCurrentThread"));
```

### Memory Manipulation

```cpp
// Read virtual memory
uint64_t value;
Kernel::Memory::ReadVirtual(address, &value, sizeof(uint64_t));

// Write virtual memory
uint64_t newValue = 0x1337;
Kernel::Memory::WriteVirtual(address, &newValue, sizeof(uint64_t));
```

### Module and Structure Information

```cpp
// Get module information
Kernel::ObjectFetcher::ModuleInformation modInfo = context.FetchModule(HashString_("ntoskrnl.exe"));

// Get structure information
Kernel::Struct& eprocessStruct = context.FetchModuleStruct(HashString_("ntoskrnl.exe"), HashString_("_EPROCESS"));
```

## Security Notice

:warning: **WARNING**: This toolkit is designed for security research and educational purposes only. Misuse of this software to exploit vulnerabilities in systems without proper authorization is illegal and unethical. Always obtain proper permissions before testing any exploitation techniques.

## Requirements

- Windows OS (Tested on Windows 10/11)
- Modern C++ compiler with C++17 support
- Administrator privileges

[MIT License](LICENSE)

## Disclaimer

This project is provided for educational and research purposes only. The authors are not responsible for any misuse of this software or for any damage it may cause. Use at your own risk.
