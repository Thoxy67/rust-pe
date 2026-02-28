# rspe

Reflective PE loader library in pure Rust (`no_std`). Loads native and .NET assemblies from memory.

## Features

- Native PE loading (C/C++/Rust/Go...)
    - [x] 64-bit (x86_64)
    - [x] 32-bit (x86)
    - [x] ARM/ARM64 relocation support
- .NET assembly loading (C#/VB/CLR)
    - [x] 64-bit .NET execution via CLR hosting
    - [x] 32-bit .NET execution via CLR hosting
    - [x] Command-line argument passing to `Main(string[] args)`

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

### Export Table Resolution

Utility functions for resolving exports from a loaded PE image:

- `get_export_by_name(baseptr, ntheader, name)` — resolve by name
- `get_export_by_ordinal(baseptr, ntheader, ordinal)` — resolve by ordinal

Handles forwarded export detection (returns null for forwarded exports).

## Use

```rust
use rspe::reflective_loader_with_args;

fn main() {
    let data = include_bytes!(r#".\example.exe"#);

    // Native PE or .NET assembly — detected automatically
    unsafe {
        reflective_loader_with_args(&data[..], &["arg1", "arg2"]);
    }
}
```

## Credits / References

Special thanks to the following individuals and projects for their contributions to this project:

- [memN0ps](https://github.com/memN0ps) for providing useful winapi rust code for learning
- [trickster0](https://github.com/trickster0) for providing many OffensiveRust code for learning

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.