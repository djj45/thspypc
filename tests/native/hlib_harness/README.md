# hlib x86 Harness

This helper loads the 32-bit `hlib.dll` in a standalone 32-bit process.  It is
the first stage of the Shanghai auction decoder investigation and deliberately
does not attach to or launch `hexin.exe`.

The currently supported binary is:

```text
Path: C:\同花顺软件\同花顺\hlib.dll
Version: 2.3.4
Size: 4,752,616 bytes
SHA-256: 07F371026341E0F9B88232274DBE4252A185C56D589CD35F50531921879550D7
```

This build is protected with VMProtect.  Its `.text`, `.rdata`, and `.data`
sections have no raw bytes in the on-disk PE, so the old 2.2.0 RVAs must not be
reused.  `dump-image` captures the post-`LoadLibraryExW` memory image for
offline analysis.

## Build

Run from a normal Command Prompt or PowerShell:

```bat
tests\native\hlib_harness\build_x86.cmd
```

The script discovers Visual Studio through `vswhere.exe`, initializes the x86
toolchain, and writes:

```text
build\x86\hlib_harness\hlib_harness.exe
```

## Commands

```bat
build\x86\hlib_harness\hlib_harness.exe fingerprint ^
  --dll "C:\同花顺软件\同花顺\hlib.dll"

build\x86\hlib_harness\hlib_harness.exe probe-chquote ^
  --dll "C:\同花顺软件\同花顺\hlib.dll" --input fixed.bin

build\x86\hlib_harness\hlib_harness.exe scan-ascii ^
  --dll "C:\同花顺软件\同花顺\hlib.dll" --needle "hd1."

build\x86\hlib_harness\hlib_harness.exe dump-image ^
  --dll "C:\同花顺软件\同花顺\hlib.dll" ^
  --output "captures_live\hlib_2.3.4.memory.bin"
```

Every command emits one JSON object on stdout.  Diagnostics go to stderr.
`fingerprint` exits with code 3 when the DLL does not match the supported
fingerprint and code 4 when a loaded-code signature differs. `probe-chquote`
is the only command that invokes undocumented functions; it refuses to run
unless both checks pass.

## Reverse-engineering result

The current static slice rules out the hlib request dispatcher as the
4214/7176 auction normalizer:

```text
0x7d3b0  build request, register waiter, wait for response
0x7a890  dispatch an hlib transport frame
0x79f60  append (frame + 11, frame_size - 11) to the waiter
0x75750  copy the waiter payload to the caller
0x66c90  pass that payload to CHQuoteFile
```

No byte transformation occurs between the hlib frame payload and
`CHQuoteFile::parse`. The Shanghai 4214/7176 captures therefore either use a
different hexin parsing path or were extracted at a different protocol
boundary. `0x7d3b0` is stateful transport code and must not be exposed as a
`normalize` command.

On this machine, Smart App Control / enterprise Code Integrity may block a
newly rebuilt unsigned executable. The source still builds as PE32, but
running a new build requires an organization-approved signature or policy
exception. Do not bypass the policy.

## Safety boundary

- No process attachment or injection.
- No login, socket, or account interaction.
- Internal calls are limited to `probe-chquote` after exact fingerprint and
  entry-signature checks.
- Unknown DLL builds are identified explicitly.
- Future commands that invoke internal code must require both an exact
  fingerprint and per-RVA entry signatures.
