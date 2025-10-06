# README.md

## Project Goal (Summary)
### Phase 1
- Load arbitrary non-executable files into memory and execute them as independent processes.

### Phase 2
- Create a sample that can execute both ELF and PE (EXE) binaries regardless of the operating system.
- Success condition: printing `Hello, World!` on any OS.

### Phase 3
- Build an experimental OS environment on VMware for extended verification and development.

## Scope of Work (Core)
- Replace ELF files with PE-compatible structures (format conversion).
- Assemble and copy the `.text` execution section into a separate external memory (section) adapted for Windows.
- Implement an **interpreter (shim)** that translates syscalls into WinAPI calls at runtime.

## Success Criteria (Detailed)
- Whether built as an ELF on Linux or a PE on Windows, the binary must, through the converter/loader/interpreter, print `Hello, World!` to standard output upon execution.

## References
- https://processhacker.sourceforge.io/doc/index.html  
- https://doxygen.reactos.org  
- https://github.com/torvalds/linux  
- https://tldp.org  
- https://tldp.org/LDP/tlk/tlk.html  

## Future Expansion
- Gradual support for ABI/calling conventions, relocations, and library dependencies.
