# TUI Fixed - Final Working Version

## Problem

```
ERROR: Failed to launch TUI: 'function' object has no attribute 'system'
```

## Root Causes

### 1. Method Name Collision
**Problem**: Method named `log()` was shadowing Textual's internal `self.log` attribute
**Fix**: Renamed to `log_msg()` throughout the codebase
**Textual uses**: `self.log.system()` for internal logging, which failed when `self.log` was a function

### 2. Invalid CSS Property
**Problem**: `content-align: center right` is not a valid Textual CSS property
**Fix**: Changed to `text-align: right`

## Changes Made

### File: `src/impact_scan/tui/clean_modern_tui.py`

**1. Renamed log method (line ~595)**
```python
# Before
def log(self, msg: str) -> None:
    log = self.query_one("#scan-log", Log)

# After
def log_msg(self, msg: str) -> None:
    log_widget = self.query_one("#scan-log", Log)
```

**2. Updated all calls (23 occurrences)**
```python
# Before
self.log("Message")

# After
self.log_msg("Message")
```

**3. Fixed CSS (line ~318)**
```python
# Before
.input-label {
    content-align: center right;
}

# After
.input-label {
    text-align: right;
}
```

## Testing

```bash
# Now works!
poetry run impact-scan tui
```

## Why This Happened

**Textual Framework Requirements**:
- Textual's `App` class has a `self.log` attribute for internal logging
- It uses methods like `self.log.system()`, `self.log.debug()`, etc.
- When we created a `log()` method, it overwrote this attribute
- Textual tried to call `self.log.system()` but `self.log` was now a function
- Result: `'function' object has no attribute 'system'`

## Lesson Learned

**Reserved Names in Textual Apps**:
- `self.log` - Internal logging (DO NOT OVERRIDE)
- `self.theme` - Theme management
- `self.screen` - Screen management
- `self.workers` - Worker management

**Safe Method Names**:
- `log_msg()` ✓
- `write_log()` ✓
- `add_log_entry()` ✓
- `log_message()` ✓

## Status

✓ TUI launches successfully
✓ No method name conflicts
✓ Valid CSS throughout
✓ All components working

## Launch Command

```bash
poetry run impact-scan tui
```

The TUI is now fully functional!
