# rspe

Reflective PE loader library in pure Rust (`no_std`). Loads native and .NET assemblies from memory.

## Features

- Native PE loading (C/C++/Rust/Go...)
    - [x] 64-bit (x86_64)
    - [x] 32-bit (x86)
    - [x] ARM/ARM64 relocation support
    - [x] Architecture validation (PE bitness must match host process)
- .NET assembly loading (C#/VB/CLR)
    - [x] 64-bit .NET execution via CLR hosting
    - [x] 32-bit .NET execution via CLR hosting
    - [x] Command-line argument passing to `Main(string[] args)`
    - [x] Automatic runtime version detection from PE metadata

### PE Loading Pipeline

1. Parse DOS/NT headers (PE32 and PE32+ at runtime)
2. Map sections into allocated memory
3. Resolve imports (name and ordinal, PE32 4-byte / PE32+ 8-byte thunks)
4. Apply base relocations (HIGHLOW, DIR64, ARM_MOV32, THUMB_MOV32)
5. Resolve delayed imports (DataDirectory\[13\], modern RVA format)
6. Register exception handlers (RtlAddFunctionTable, x64/ARM64 only)
7. Set per-section memory protections
8. Invoke TLS callbacks (DLL_PROCESS_ATTACH)
9. Execute entry point via CreateThread
10. Cleanup (unregister exception tables, free memory)

### Advanced Security Features

- [x] Security Cookie Initialization (`__security_cookie` for /GS buffer security)
- [x] CFG (Control Flow Guard) - Registers valid call targets via `SetProcessValidCallTargets`
- [x] SxS / Activation Context - Activates embedded manifests for GUI applications
- [x] Bound Import Directory invalidation

### Export Table Resolution

Utility functions for resolving exports from a loaded PE image:

- `get_export_by_name(baseptr, ntheader, name)` — resolve by name
- `get_export_by_ordinal(baseptr, ntheader, ordinal)` — resolve by ordinal

Handles forwarded exports automatically by loading the target DLL (e.g., `"NTDLL.RtlAllocateHeap"` resolves to the actual function in ntdll.dll).

### API Set Resolution

Automatically resolves Windows API sets (`api-ms-win-*`, `ext-ms-win-*`) to their actual host DLLs using the PEB ApiSetMap. This enables loading PEs that import from virtual API set DLLs.

### Utility Functions

- `utils::detect_platform(bytes)` — Detect if PE is 32-bit or 64-bit
- `utils::check_dotnet(pe)` — Check if PE is a .NET assembly
- `utils::get_dotnet_version(pe)` — Extract .NET runtime version string from metadata
- `utils::rva_to_file_offset(pe, rva)` — Convert RVA to raw file offset

### Supported Machine Types

| Architecture | Machine Code | Bitness |
|--------------|--------------|---------|
| i386         | 0x014c       | 32-bit  |
| AMD64        | 0x8664       | 64-bit  |
| IA64         | 0x0200       | 64-bit  |
| ARM (ARMNT)  | 0x01C4       | 32-bit  |
| ARM64        | 0xAA64       | 64-bit  |

### Error Handling

The library uses a `PeError` enum for error handling:

```rust
pub enum PeError {
    InvalidPe,
    FileTooSmall,
    ArchMismatch,        // PE bitness doesn't match host process
    AllocFailed,
    InvalidNtHeader,
    ImportResolveFailed,
    SectionOutOfBounds,
    UnsupportedRelocationType,
    ThreadCreationFailed,
    VirtualProtectFailed,
    DotNetError(&'static str),
}
```

## Cargo Features

```toml
[dependencies]
rust-pe = { version = "0.1", default-features = true }

# Or disable .NET support to reduce binary size:
rust-pe = { version = "0.1", default-features = false }
```

| Feature  | Default | Description                        |
|----------|---------|-----------------------------------|
| `dotnet` | Yes     | Enable .NET assembly execution via CLR hosting |

## Usage

### Basic Usage (Embedded PE)

```rust
use rust_pe::reflective_loader;

fn main() {
    let data = include_bytes!("app.exe");

    // Native PE or .NET assembly — detected automatically
    unsafe {
        reflective_loader(data).expect("failed to load PE");
    }
}
```

### With Command-Line Arguments

```rust
use rust_pe::reflective_loader_with_args;

fn main() {
    let data = include_bytes!("app.exe");

    // Arguments are passed to native PE via PEB CommandLine patching
    // or to .NET Main(string[] args) via CLR invocation
    unsafe {
        reflective_loader_with_args(data, &["arg1", "arg2"]).expect("failed");
    }
}
```

### Loading from File

```rust
use rust_pe::reflective_loader;
use std::fs;

fn main() {
    let data = fs::read("path/to/executable.exe").expect("failed to read file");

    unsafe {
        reflective_loader(&data).expect("failed to load PE");
    }
}
```

### Forwarding CLI Arguments

```rust
use rust_pe::reflective_loader_with_args;

fn main() {
    let data = include_bytes!("app.exe");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    unsafe {
        reflective_loader_with_args(data, &arg_refs).expect("failed");
    }
}
```

### How Argument Passing Works

- **Native PEs**: Arguments are passed by patching the PEB CommandLine, so `GetCommandLineW()` returns the provided arguments
- **.NET Assemblies**: Arguments are passed directly to `Main(string[] args)` via CLR invocation

## `no_std` Support

This library is `no_std` compatible (requires `alloc`). It uses no standard library dependencies, making it suitable for constrained environments or when minimal binary size is important.

## Credits / References

Special thanks to the following individuals and projects for their contributions to this project:

- [memN0ps](https://github.com/memN0ps) for providing useful winapi rust code for learning
- [trickster0](https://github.com/trickster0) for providing many OffensiveRust code for learning

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.