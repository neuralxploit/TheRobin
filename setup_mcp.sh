#!/usr/bin/env bash
# Generate .mcp.json for the current machine (Mac or Linux)
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sed "s|__REPO_ROOT__|${REPO_ROOT}|g" "${REPO_ROOT}/.mcp.json.template" > "${REPO_ROOT}/.mcp.json"

echo "Generated .mcp.json for: ${REPO_ROOT}"
