---
name: line-execution-checker
description: Check if specific lines were executed using gcov data. Use when you need to quickly verify whether a particular line of code was reached during execution.
---

# Line Execution Checker

## Purpose

Fast tool to check if specific source lines were executed during test runs.

## Tool: line-checker

### Build
```bash
g++ -O3 -std=c++17 line_checker.cpp -o line-checker
```

### Usage
```bash
# Single line
./line-checker file.c:42

# Multiple lines
./line-checker file.c:42 main.c:100 util.c:55
```

### Output
```
file.c:42 EXECUTED (5 times)
main.c:100 NOT EXECUTED
util.c:55 EXECUTED (12 times)
```

### Exit Codes
- 0: All lines executed
- 1: One or more lines NOT executed
- 2: Error

## Prerequisites

Coverage data must exist from prior test run with `--coverage` flag.

## Steps

1. Verify `.gcda` files exist: `find . -name "*.gcda" -print -quit`
2. Build tool if needed: `g++ -O3 -std=c++17 line_checker.cpp -o line-checker`
3. Run: `./line-checker file.c:X`
4. Report result to user

## Source File

The `line_checker.cpp` source file should be located alongside this SKILL.md.
If missing, it needs to be copied from the raptor repository
(`~/code/raptor/.claude/skills/crash-analysis/line-execution-checker/`).
