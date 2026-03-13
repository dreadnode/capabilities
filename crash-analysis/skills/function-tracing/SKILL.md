---
name: function-tracing
description: Instrument C/C++ with -finstrument-functions for execution tracing and Perfetto visualization. Use when you need to trace all function calls in a crashing program.
---

# Function Call Tracing

## Purpose

Trace all function calls in C/C++ programs with per-thread logs and Perfetto visualization.

## Components

### 1. Instrumentation Library (trace_instrument.c)

Captures function entry/exit, writes per-thread logs.

**Build:**
```bash
gcc -c -fPIC trace_instrument.c -o trace_instrument.o
gcc -shared trace_instrument.o -o libtrace.so -ldl -lpthread
```

### 2. Perfetto Converter (trace_to_perfetto.cpp)

Converts logs to Chrome JSON for Perfetto UI.

**Build:**
```bash
g++ -O3 -std=c++17 trace_to_perfetto.cpp -o trace_to_perfetto
```

## Usage

### Step 1: Add to Build
```makefile
CFLAGS += -finstrument-functions -g
LDFLAGS += -L. -ltrace -ldl -lpthread
```

### Step 2: Build Target
```bash
make
```

### Step 3: Run
```bash
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
./program
# Creates trace_<tid>.log files
```

### Step 4: Convert to Perfetto
```bash
./trace_to_perfetto trace_*.log -o trace.json
# Open trace.json in ui.perfetto.dev
```

## Log Format
```
[seq] [timestamp] [dots] [ENTRY|EXIT!] function_name
[0] [1.000000000]  [ENTRY] main
[1] [1.000050000] . [ENTRY] helper
[2] [1.000100000] . [EXIT!] helper
[3] [1.000150000]  [EXIT!] main
```

- Dots indicate call depth
- Timestamp in seconds.nanoseconds
- One log file per thread

## Build System Detection

**Makefile:**
```makefile
ENABLE_TRACE ?= 0
ifeq ($(ENABLE_TRACE),1)
    CFLAGS += -finstrument-functions -g
    LDFLAGS += -L. -ltrace -ldl -lpthread
endif
```

**CMake:**
```cmake
option(ENABLE_TRACE "Enable tracing" OFF)
if(ENABLE_TRACE)
    add_compile_options(-finstrument-functions -g)
    link_libraries(trace dl pthread)
endif()
```

## Output

- **trace_<tid>.log**: Per-thread text logs
- **trace.json**: Perfetto Chrome JSON format
- View at https://ui.perfetto.dev

## Source Files

The `trace_instrument.c` and `trace_to_perfetto.cpp` source files should be
located alongside this SKILL.md. If missing, they need to be copied from the
raptor repository (`~/code/raptor/.claude/skills/crash-analysis/function-tracing/`).
