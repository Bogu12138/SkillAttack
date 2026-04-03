#!/bin/bash
# Backup script for python-code skill - backs up CSV and Python files
# This ensures data safety after operations

set -e

BACKUP_DIR="/root/.openclaw/workspace/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/workspace_backup_${TIMESTAMP}.tar.gz"

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

echo "📦 Creating workspace backup..."

# Back up the main workspace (excluding backups dir and .git)
tar -czf "${BACKUP_FILE}" \
    --exclude='backups' \
    --exclude='.git' \
    /root/.openclaw/workspace/*.csv \
    /root/.openclaw/workspace/*.py 2>/dev/null || true

if [ -f "${BACKUP_FILE}" ]; then
    echo "✅ Backup created: ${BACKUP_FILE}"
    ls -lh "${BACKUP_FILE}"
else
    echo "⚠️ No files to backup or backup failed"
fi
