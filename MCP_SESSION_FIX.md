# MCP Server Session Folder Fix

## Summary

Fixed the MCP server (`mcp_server.py`) to create isolated session folders for each penetration test, matching the behavior of the original tool (run.sh/main.py). This prevents mixing of screenshots, findings, and reports between different pentest sessions.

## What Was Fixed

### 1. MCP Server Session Management

**Problem:**
- MCP was writing all data directly to `workspace/` folder
- Running multiple pentests or using MCP alongside run.sh would cause data mixing
- Screenshots and reports from different tests would overwrite each other

**Solution:**
- Added `_get_or_create_session_dir()` function to create timestamped session folders
- Modified all MCP tool calls to ensure session directory exists before executing
- Each MCP session now creates `workspace/session_YYYYMMDD_HHMMSS/` folder
- Updated `agent.tools.WORKSPACE_DIR` to point to the session directory

### 2. New MCP Tools

#### `start_new_session(target_url, session_name)`
- Forces start of a fresh session with custom name
- Resets browser and REPL from previous session
- Creates new isolated workspace folder
- Initializes `_G` globals with BASE, SESSION_DIR, FINDINGS, etc.
- Saves session metadata to `session_metadata.json`

#### `get_session_info()`
- Returns current session information
- Shows session directory, target URL, findings count, created timestamp
- Useful for debugging and knowing where files are saved

#### `generate_report(output_filename)`
- Generates PDF report from current session findings
- Automatically finds screenshots in the session folder
- Saves report in the session directory
- Properly reads `_G` state from `.pentest_state.json`

### 3. PDF Report Generator Fix

**Problem:**
- Was only searching `workspace/` and `.` for screenshots
- Would pick up screenshots from old sessions (false findings!)

**Solution:**
- Added `_SCREENSHOT_SEARCH_PATHS` global variable
- Added `_find_screenshot()` helper function that searches intelligently
- Searches in priority order:
  1. Current session directory (`workspace/session_XXX/`)
  2. `workspace/` (fallback)
  3. Current directory `.` (fallback)
- Updated `generate_pdf_report()` signature to accept `session_dir` parameter
- Screenshots are now pulled from the correct session folder

### 4. Screenshot Filename Handling

**Problem:**
- Screenshots were always saved with timestamps: `screenshot_label_1234567890.png`
- Phase files stored just the base name: `phase_06_sqli_proof.png`
- PDF generator couldn't find the files

**Solution:**
- Modified `_BrowserSession._save_screenshot()` in `agent/tools.py`
- Now handles two filename patterns:
  - **Exact filename** (with .png): `phase_06_sqli_proof.png` → saves exactly as provided
  - **Label only**: `phase_06_sqli` → saves with timestamp: `screenshot_phase_06_sqli_1234567890.png`
- Matches what phase files expect

## File Changes

| File | Changes | Lines Added |
|------|---------|-------------|
| `mcp_server.py` | Added session management, 3 new tools, fixed all tools to use session dirs | ~150 |
| `agent/report_pdf.py` | Added screenshot search function, updated report signature | ~50 |
| `agent/tools.py` | Fixed screenshot filename handling | ~15 |

## Usage

### Starting a New Pentest Session

```python
# Via MCP (Claude Code / OpenCode):
start_new_session(target_url="http://example.com", session_name="example_pentest")

# Then proceed with testing:
run_python(code="import requests; _G['session'] = requests.Session()...")
browser_action(action="navigate", url="http://example.com")
```

### Checking Session Info

```python
# See current session details:
get_session_info()
# Returns: {"session_dir": "workspace/session_20250123_143025",
#          "session_name": "example_pentest",
#          "target": "http://example.com",
#          "findings_count": 12,
#          "has_session": true}
```

### Generating Report

```python
# Generate PDF report with proper screenshots:
generate_report(output_filename="report.pdf")
# Saves: workspace/session_20250123_143025/report.pdf
```

## Directory Structure

```
workspace/
├── session_20250123_143000/          # First MCP session
│   ├── session_metadata.json
│   ├── report.pdf
│   ├── phase_06_sqli_proof.png
│   ├── phase_05_xss_search_q.png
│   ├── .pentest_state.json
│   └── pentest_memory.md
├── session_20250123_150000/          # Second MCP session (isolated!)
│   ├── session_metadata.json
│   ├── report.pdf
│   ├── phase_06_sqli_proof.png
│   └── .pentest_state.json
└── session_20250124_100000/          # run.sh session (also isolated!)
    ├── session_metadata.json
    └── report.pdf
```

## Benefits

1. **No Data Mixing**: Each pentest is isolated in its own folder
2. **Multiple Parallel Sessions**: Can run MCP and run.sh simultaneously
3. **Proper Report Generation**: Screenshots pulled from correct session
4. **No False Findings**: Old screenshots won't contaminate new reports
5. **Audit Trail**: Session folders preserve history of all pentests
6. **Easy Cleanup**: Delete entire session folder to clean up

## Backwards Compatibility

- **Original run.sh/main.py**: Works exactly as before (unchanged)
- **MCP Server**: New tools added, session management enabled automatically
- **Phase Files**: Use new screenshot checkpoint instructions (already updated)

## Testing Checklist

- [x] MCP server compiles without errors
- [x] `start_new_session()` creates isolated folder
- [x] `run_python` saves files to session directory
- [x] `browser_action` saves screenshots to session directory with correct filename
- [x] `get_session_info()` returns correct session data
- [x] `generate_report()` finds screenshots in session folder
- [x] PDF generator searches session directory first
- [x] Multiple sessions don't interfere with each other
- [x] Screenshot filenames match between saving and finding

## Notes

- Session directory is created on first tool call if not explicitly started
- Default session name format: `session_YYYYMMDD_HHMMSS`
- Custom session names are sanitized (special chars → underscores)
- Browser and REPL are reset when starting a new session
- Phase files store screenshot filenames without `screenshot_` prefix
- PDF generator auto-detects session directory if not specified

## Context Compaction & State Restoration

### Two Files Saved by `compact_state()`:

1. **`pentest_memory.md`** — Human-readable summary you write
   - Contains: Your summary of what was done, findings found, phases completed
   - **CAN be incomplete** if you forget to list everything
   - Use for: Reference, debugging, knowing where you left off

2. **`.pentest_state.json`** — Complete, automatic state dump
   - Contains: **ALL** serializable data from `_G` dict
   - Includes: `FINDINGS`, `BASE`, `ALL_LINKS`, `API_ENDPOINTS`, cookies, tested endpoints
   - **CANNOT be incomplete** - auto-saved after every `run_python()` call
   - Use for: **THIS is what you restore from!**

### When Context Gets Too Long:

```python
# 1. Save your progress (saves BOTH files)
compact_state(summary="""
Target: http://example.com
Phases 1-4 completed.
Found: SQL Injection on login, XSS on search.
Tested: 15 endpoints.
Continue with Phase 5.
""")

# 2. After compaction, when continuing in new session:
# RESTORE FROM JSON (not the summary!)
restore_state_from_json()
# This loads ALL data from .pentest_state.json into _G

# 3. Read plan.md to see which phase to continue
read_file('plan.md')

# 4. Continue from the next unchecked phase
```

### Why This Matters:

- JSON state is **authoritative** - has ALL findings and test results
- Summary is **reference only** - can be incomplete, but doesn't break restoration
- When you forget something in the summary → JSON still has it!
- **Always use `restore_state_from_json()` to continue, never rely on summary alone**

### Auto-Saved State:

The `.pentest_state.json` file is automatically saved after EVERY `run_python()` call:

```python
# This happens automatically (no need to call _save_state manually)
run_python(code="""
_G['FINDINGS'].append({'severity': 'CRITICAL', 'title': 'SQL Injection', ...})
""")
# .pentest_state.json is now updated with the new finding
```

### New MCP Tool: `restore_state_from_json()`

- Loads complete state from `.pentest_state.json` into `_G`
- Restores ALL findings, tested endpoints, session data
- Reports how many keys restored
- **Use this when continuing after compaction** (not just reading the summary)