# XInject Rosetta Supported

## Overview
XInject is a dylib injection tool for macOS, supporting multiple architectures including macOS x86_64, ARM64, and ARM64e.
## Architecture Support

| Injector Architecture | Can Inject Into            |
|-----------------------|----------------------------|
| ARM64e                | ARM64, ARM64e              |
| ARM64                 | ARM64                      |
| x86_64                | x86_64(Intel Mac not test) |

### Build

clang -arch arm64 -arch arm64e -arch x86_64 xinjector_payload.c -shared -o libxinjector-payload.dylib -O3

clang -arch arm64 -arch arm64e -arch x86_64 ./xinjector.c -o xinjector -L . -l xinjector-payload -O3

### Example
Inject into Rosetta process

sudo arch -arch x86_64 ./xinjector libpath processname
