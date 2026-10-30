![Banner](banner.png)

# arte-Executable-Header-Fuzzer
Fuzzes a given file to test for parsing vulnerabilities in emulators. For each iteration it flips bits and replaces bytes at random positions across the whole file (the rate is set by the fuzz factor; the file header is not parsed or targeted separately), writes the result to the output directory, and runs it through an emulator subprocess, logging any non-zero exit as a possible crash. - Focused on Tools designed to dynamically emulate and analyze potentially malicious artifacts like shellcode, PE files, or other encoded payloads in a sandboxed environment for behavior analysis and threat assessment.

## Install
`git clone https://github.com/ShadowStrikeHQ/arte-executable-header-fuzzer`

## Usage
`./arte-executable-header-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-e`: Path to the emulator executable. Defaults to qemu-system-x86_64.
- `-o`: Directory to store the fuzzed files. Defaults to fuzzed_files.
- `-i`: Number of fuzzing iterations. Defaults to 10.
- `-f`: No description provided
- `--seed`: Seed for the random number generator. If not provided, a random seed is used.

## License
Copyright (c) ShadowStrikeHQ
