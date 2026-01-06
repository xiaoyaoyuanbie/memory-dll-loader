# Memory DLL Loader

A Windows PE file loader that can load DLL files from memory and call their exported functions without using `LoadLibrary`.

## Features

- Load PE files (DLL/EXE) from disk into memory
- Process relocation table correctly to fix hardcoded addresses
- Fix import table (IAT) by resolving dependencies
- Call `DllMain` entry point with proper parameters
- Get and call exported functions by name or ordinal
- Dynamic API resolution to avoid direct linking

## Project Structure

```
memory-dll-loader/
├── dll_load/
│   └── 1.cpp          # Main loader implementation
├── Dll1/
│   └── dllmain.cpp    # Test DLL with sample exports
└── README.md
```

## Technical Details

### Loading Process

1. **File Mapping**: Map the PE file into memory using `CreateFileMapping` and `MapViewOfFile`
2. **Image Conversion**: Convert file layout to memory image layout
3. **Relocation**: Apply base relocations using the delta between actual load address and preferred image base
4. **Import Resolution**: Load required DLLs and resolve imported functions
5. **Entry Point**: Call `DllMain` with `DLL_PROCESS_ATTACH`
6. **Export Lookup**: Find exported functions by name in the export directory
7. **Function Call**: Invoke the exported function

### Key Implementation Notes

- **ImageBase Preservation**: The original `ImageBase` from the PE file is saved before memory conversion, as it's critical for correct relocation calculation
- **Relocation Formula**: `NewAddress = OldAddress + (CurrentBase - PreferredBase)`
- **32-bit Only**: Currently targets x86 (32-bit) architecture

## Building

### Requirements

- Windows SDK
- Visual Studio 2019 or later (or MinGW)

### Compile with Visual Studio

```bash
# Build the test DLL
cl /LD Dll1\dllmain.cpp /Fe:Dll1.dll

# Build the loader
cl /EHsc dll_load\1.cpp
```

### Compile with MinGW

```bash
# Build the test DLL
g++ -shared -o Dll1.dll Dll1/dllmain.cpp -Wl,--out-implib,libDll1.a

# Build the loader
g++ -o memloader.exe dll_load/1.cpp
```

## Usage

```bash
memloader.exe <dll_path> <function_name>
```

### Example

```bash
# Load Dll1.dll and call the Add function
memloader.exe Dll1.dll Add

# Output:
# [*] Loading DLL: Dll1.dll
# [*] Converting file to image...
# [*] Saving original ImageBase: 0x10000000
# [*] Processing relocations...
# [*] Delta: 0xFF500000 (Original: 0x10000000, Current: 0x500000)
# [*] Applied 42 relocations
# [*] Processing imports...
# [*] Calling DllMain (DLL_PROCESS_ATTACH)...
#     [DLL] DLL_PROCESS_ATTACH - DLL loaded!
#     [DLL] Module handle: 0x00500000
# [*] Getting export function: Add
# [+] Function found at address: 0x00501050
# [*] Calling function...
#     [DLL] Add(10, 20) called
# [+] Function returned: 30
# [*] Calling DllMain (DLL_PROCESS_DETACH)...
#     [DLL] DLL_PROCESS_DETACH - DLL unloading!
```

## Test DLL (Dll1)

The included `Dll1` project exports the following functions:

| Function | Description |
|----------|-------------|
| `Add(int, int)` | Integer addition |
| `Sub(int, int)` | Integer subtraction |
| `Mul(int, int)` | Integer multiplication |
| `ShowMessage(char*)` | Print a message |
| `GetValue()` | Returns 42 |
| `OrdinalFunc()` | Exported by ordinal |

## Educational Purpose

This project is for educational and research purposes only. It demonstrates:
- PE file format internals
- Windows memory management
- Dynamic linking and relocation
- Manual PE loading without standard APIs

## License

This project is provided as-is for educational purposes.

## References

- [Microsoft PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Image-Based Load Options](https://docs.microsoft.com/en-us/windows/win32/memory/memory-management-functions)
