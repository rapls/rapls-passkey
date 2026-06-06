#!/usr/bin/env bash
#
# Build a WordPress.org-ready distribution ZIP of the plugin.
#
# Stages the runtime files (excluding everything in .distignore) into a temp
# folder, then writes <slug>.zip into the parent wp-content/plugins directory.
# The ZIP unpacks to a single `rapls-passkey/` folder.
#
#   bin/build.sh
#
set -euo pipefail

SLUG="rapls-passkey"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(cd "$ROOT/.." && pwd)"     # the wp-content/plugins directory
ZIP="$OUT/$SLUG.zip"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/$SLUG"
mkdir -p "$STAGE"

# Stage runtime files only. rsync honours .distignore (gitignore-style patterns).
rsync -a --exclude-from="$ROOT/.distignore" "$ROOT/." "$STAGE/"

rm -f "$ZIP"
( cd "$TMP" && zip -rqX "$ZIP" "$SLUG" )

echo "Built: $ZIP"
echo "Top-level contents:"
( cd "$STAGE" && find . -maxdepth 1 -mindepth 1 | sort | sed 's#^\./#  #' )
