# WinStruct

**Explore Windows internals, one pointer at a time.**

WinStruct is an educational, command-line project for exploring how Windows organizes processes, memory, and system-level data. It aims to make low-level concepts easier to inspect and understand by combining readable tables, raw memory views, field explanations, and reproducible C examples.

The project is intentionally **not limited to a particular Windows structure**. Its current implementation focuses on process loader data, but the long-term goal is to provide a growing set of tools for learning about Windows internals and memory organization.

> [!NOTE]
> WinStruct is an evolving learning project, not a production debugger, forensic tool, or comprehensive disassembler.

## Current capabilities

The initial Windows x64 implementation can:

- Follow pointers through selected process-internal structures and enumerate loaded modules.
- Display field offsets, addresses, and values in aligned console tables.
- Highlight important addresses for easier pointer tracing.
- Optionally show hexadecimal memory previews, field descriptions, and C pointer-arithmetic examples.
- Attempt limited, built-in x86-64 instruction decoding for executable memory regions, without external disassembly libraries.

The optional table columns are designed to keep related information grouped, even when a cell spans multiple lines.

## Build

**Requirements:** Windows x64 and a MinGW-w64 x86-64 GCC toolchain.

```bash
x86_64-w64-mingw32-gcc.exe winstruct.c -o winstruct.exe -static
```

## Usage

```bash
winstruct.exe [--hex] [--asm] [--desc] [--code] [--help]
```

| Option | Purpose |
| --- | --- |
| `--hex` | Show up to 32 bytes at pointer destinations. |
| `--asm` | Attempt to decode up to 10 instructions from up to 64 bytes of executable memory. |
| `--desc` | Add concise explanations of fields to the table. |
| `--code` | Add C snippets using explicit Windows x64 offsets and pointer arithmetic. |
| `--help` | Show the available options. |

Options can be combined:

```bash
winstruct.exe --desc --code
winstruct.exe --hex --desc
winstruct.exe --hex --asm --desc --code
```

Running without options displays a more compact view.

## Project direction

WinStruct is intended to grow beyond its first process-memory walkthrough. Potential areas include:

- Portable Executable (PE) layout and metadata.
- Process and thread memory organization.
- Memory regions, protections, and mappings.
- Stacks, heaps, and other runtime data structures.
- Module loading, linking, and symbol resolution.
- Additional visualizations and cross-references between related structures.

These are **possible directions, not implemented features or commitments**. The scope will evolve as the project develops.

## Technical notes

- The current implementation targets **64-bit Windows** and uses architecture-specific offsets. Internal layouts may vary across Windows versions and are not stable public APIs.
- Memory contents and virtual addresses can differ between runs because of ASLR, allocation behavior, and process state.
- A memory region being executable does **not** prove that every byte in it is a valid instruction. The built-in decoder supports only a subset of x86-64 and stops on unsupported or incomplete instructions.
- Inspecting internal loader lists assumes they remain consistent during traversal. The current implementation should not be treated as a hardened general-purpose memory inspector.
- The project reads memory in the context of the running process; it does not claim to inspect arbitrary remote processes.

## Contributing

Suggestions, corrections, and small, well-explained improvements are welcome. When proposing support for a new structure or Windows version, include the relevant architecture, assumptions, and a way to reproduce or validate the results.

## License

No license has been selected yet. Add a `LICENSE` file before inviting code reuse or outside contributions.
