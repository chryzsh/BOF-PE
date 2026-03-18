# BOF-PE Code Review Findings

**Reviewed:** 2026-01-26
**Files:** beacon/beacon.cpp, common/standalone.cpp, loader/main.cpp

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| CRITICAL | 2 | Memory safety issues that could cause crashes or corruption |
| HIGH | 4 | Significant bugs that affect functionality |
| MEDIUM | 1 | Minor issues that should be fixed |
| LOW | 3 | Code quality / consistency improvements |

**Total issues found:** 10

---

## Recommended PR Strategy

Group fixes by theme rather than one mega-PR or many tiny PRs:

| PR | Issues | Description |
|----|--------|-------------|
| **PR 1** | #2, #6 | Memory safety fixes (buffer bounds, file validation) |
| **PR 2** | #4, #5, #8 | NULL pointer check consistency |
| **PR 3** | #3 | BeaconFormatInt bounds logic fix |
| **PR 4** | #7 | Loader ordinal import handling |
| **PR 5** | #1, #9, #10 | Code quality cleanup (low priority, optional) |

**Rationale:**
- Related fixes are easier to review together
- If maintainer disagrees with one fix, it doesn't block others
- Easier to bisect if something breaks later
- Reduces overhead vs 10 individual PRs

---

## Critical Issues

### ~~1. WriteString(string_view) reads past buffer end~~ (Downgraded to LOW)
**File:** common/standalone.cpp:61-64
**Status:** [ ] Not fixed (may not warrant a PR)

```cpp
static void WriteString(std::stringstream& ss, const std::string_view& str) {
    WriteInt(ss, str.length() + 1);
    ss.write((char*)str.data(), str.length() + 1);  // Reads past string_view range
}
```

**Problem:** `std::string_view` does not guarantee null termination. The code writes `length + 1` bytes but the view only guarantees `length` valid bytes.

**Mitigating factor:** In practice, these string_views are always constructed from `argv` entries (line 103), which are null-terminated C strings. The null byte is always present in memory. This is a defensive coding concern, not a real bug in the current code.

**Fix (if desired):** Write data then explicit null: `ss.write(str.data(), str.length()); ss.put('\0');`

---

### 2. BeaconDataExtract integer underflow
**File:** beacon/beacon.cpp:78-101
**Status:** [ ] Not fixed

```cpp
extern "C" BEACON_IMPEX char* BeaconDataExtract(datap* parser, int* size) {
    uint32_t length = 0;
    char* outdata = NULL;
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    length = swap_endianess(length);

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;   // BUG: no bounds check, underflows if length > parser->length
    parser->buffer += length;   // BUG: pointer flies past valid memory
    // ...
}
```

**Problem:** The bounds check on line 82 only verifies there are 4 bytes available to read the length prefix. It does NOT verify that the length value read from the data is within the remaining buffer. Since `length` is `uint32_t` (unsigned) and `parser->length` is `int` (signed), the subtraction on line 95 can underflow.

**Detailed walkthrough with malformed data:**

Normal case (`parser->length = 20`, length prefix = 6 for `"Hello\0"`):
```
Line 82:  20 >= 4? Yes
Line 85:  Read length = 6
Line 94:  parser->length -= 4  → 16
Line 95:  parser->length -= 6  → 10  ✓
Line 96:  parser->buffer += 6        ✓
```

Bug case (`parser->length = 10`, length prefix = 0xFFFFFFFF):
```
Line 82:  10 >= 4? Yes (only checks if we can read the prefix)
Line 85:  Read length = 4294967295
Line 94:  parser->length -= 4  → 6
Line 95:  parser->length -= 4294967295
          C++ converts int to uint32_t for mixed arithmetic:
          (uint32_t)6 - (uint32_t)4294967295 = 7 (unsigned wraparound)
          Stored back as int → parser->length = 7 (WRONG: should be exhausted)
Line 96:  parser->buffer += 4294967295 (pointer ~4GB past end of valid memory)
```

The function returns `outdata` (which is valid), but the parser is now corrupted:
- `parser->length` is 7 — thinks it has data remaining when it doesn't
- `parser->buffer` points ~4GB into invalid memory

Any subsequent `BeaconDataExtract`, `BeaconDataInt`, etc. reads from wherever that pointer landed.

**Comparison with BeaconDataInt (safe):** `BeaconDataInt` always subtracts the hardcoded value 4, matching its bounds check. `BeaconDataExtract` subtracts a data-controlled value without validating it.

**Impact:** Under normal operation (standalone or well-formed C2 data), length values are correct and this never triggers. But this is a security tool's data parsing layer — if C2 comms are tampered with or there's a protocol bug, malformed data corrupts the parser state and leads to out-of-bounds reads.

**Fix:** Add a bounds check after reading the length:

```cpp
parser->length -= 4;

if (length > (uint32_t)parser->length) {
    parser->length = 0;
    return NULL;
}

parser->length -= length;
parser->buffer += length;
```

---

### 3. BeaconFormatInt has inverted bounds check
**File:** beacon/beacon.cpp:175-177
**Status:** [ ] Not fixed

```cpp
if (format->length < 4) {
    return;
}
```

**Problem:** This checks if the current length is less than 4, which makes no sense. It should check if there's *room* for 4 more bytes: `format->length + 4 > format->size`.

**Impact:** Prevents legitimate use of the format API when buffer has 0-3 bytes used. Also doesn't prevent overflow when buffer is nearly full.

**Fix:** Change to `if (format->length + 4 > format->size)` to match `BeaconFormatAppend`.

---

## High Priority Issues

### 4. BeaconFormatToString NULL pointer dereference
**File:** beacon/beacon.cpp:167-170
**Status:** [ ] Not fixed

```cpp
extern "C" BEACON_IMPEX char* BeaconFormatToString(formatp* format, int* size) {
    *size = format->length;  // BUG: no NULL check
    return format->original;
}
```

**Problem:** If `size` is NULL, this crashes. Other functions in this file check for NULL parameters.

**Impact:** Crashes if caller passes NULL for size parameter.

**Fix:** Add `if (size != NULL)` check before dereferencing, or check both `format` and `size`.

---

### 5. BeaconFormatReset NULL pointer dereference
**File:** beacon/beacon.cpp:116-121
**Status:** [ ] Not fixed

```cpp
extern "C" BEACON_IMPEX void BeaconFormatReset(formatp* format) {
    memset(format->original, 0, format->size);  // BUG: no NULL check
    format->buffer = format->original;
    format->length = 0;
    return;
}
```

**Problem:** `BeaconFormatAlloc` and `BeaconFormatFree` both check `if (format == NULL)`, but this function doesn't.

**Impact:** Crashes if caller passes NULL format.

**Fix:** Add `if (format == NULL) return;` at the start.

---

### 6. ReadFileData doesn't validate file open
**File:** common/standalone.cpp:84-94
**Status:** [ ] Not fixed

```cpp
static ByteArray ReadFileData(const std::string& file) {
    std::ifstream infile(file, std::ios::binary);
    // No check if file opened successfully!
    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();  // Returns -1 on failure
    infile.seekg(0, std::ios::beg);
    ByteArray buffer(length);        // -1 becomes huge size_t!
    infile.read(&buffer[0], length);
    return std::move(buffer);
}
```

**Problem:** If the file doesn't exist or can't be opened, `tellg()` returns -1. When cast to `size_t`, this becomes a massive value (e.g., 18446744073709551615), causing allocation of a huge buffer.

**Impact:** Memory exhaustion or crash when using `b` format with nonexistent file.

**Fix:** Add `if (!infile) throw ...` check after opening, similar to `ReadFileAsString`.

---

### 7. Ordinal import for beacon.dll causes crash
**File:** loader/main.cpp:127
**Status:** [ ] Not fixed

```cpp
}else{
    // Current DLL is beacon.dll, resolve via internal C2 mechanism
    *ptr = ResolveBeaconFunction(imp.name()->Name);  // BUG
}
```

**Problem:** For non-beacon modules, the code handles both name and ordinal imports (lines 116-120). But for beacon.dll, it assumes name import only. If beacon.dll uses ordinal imports, `imp.name()` returns NULL and dereferencing `->Name` crashes.

**Impact:** Crashes if beacon.dll has ordinal exports (unlikely but possible).

**Fix:** Add ordinal check similar to the non-beacon path, or assert that beacon only uses named exports.

---

## Medium Priority Issues

### 8. BeaconDataLength NULL pointer dereference
**File:** beacon/beacon.cpp:74-76
**Status:** [ ] Not fixed

```cpp
extern "C" BEACON_IMPEX int BeaconDataLength(datap* parser) {
    return parser->length;  // BUG: no NULL check
}
```

**Problem:** Crashes if parser is NULL. Other BeaconData* functions check for NULL.

**Fix:** Add `if (parser == NULL) return 0;`.

---

## Low Priority Issues

### 9. swap_endianess_short returns wrong type
**File:** beacon/beacon.cpp:30
**Status:** [ ] Not fixed

```cpp
static uint32_t swap_endianess_short(uint16_t indata) {
```

**Problem:** Function swaps a 16-bit value but returns 32-bit. Works correctly but is confusing and inconsistent.

**Fix:** Change return type to `uint16_t`.

---

### 10. Error message doesn't match condition
**File:** common/standalone.cpp:98-99
**Status:** [ ] Not fixed

```cpp
if(argc-1 > strlen(bof_args_def)){
    printf("Not enough arguments to satisfy BOF packed args with definition %s\n", bof_args_def);
```

**Problem:** The condition checks if there are MORE args than format specifiers, but the message says "not enough arguments".

**Fix:** Either change the message to "Too many arguments provided" or change the condition to `<` if the intent was to check for too few args.

---

## Already Fixed

### exists() vs is_regular_file() for directory paths
**File:** common/standalone.cpp:112, 118
**Status:** [x] Fixed in branch `fix-directory-path-args`

Changed `std::filesystem::exists()` to `std::filesystem::is_regular_file()` to prevent directory paths from being incorrectly treated as files to read.
