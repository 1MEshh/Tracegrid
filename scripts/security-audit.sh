#!/usr/bin/env bash
# ==============================================================================
# Tracegrid: Zero-Leak, PII, and Security Gate
# Enforces zero absolute filesystem paths, zero OS username leaks, zero hostname
# leaks, zero literal API credentials, zero emojis, and verified git authorship.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[AUDIT] Starting zero-leak and DevSecOps verification for Tracegrid..."

TRACKED_FILES=$(git ls-files 2>/dev/null || true)
if [ -z "$TRACKED_FILES" ]; then
    echo "[AUDIT] Notice: No git index available yet; scanning repository tree..."
    TRACKED_FILES=$(find . -maxdepth 4 -type f -not -path '*/.*' -not -path './target/*')
fi

LEAK_FOUND=0

# 1. Scan for hardcoded local filesystem paths (/home/<user>, /Users/<user>, C:\Users\<user>)
echo "[AUDIT] Checking for machine-specific path leaks..."
PATH_LEAKS=$(grep -rnE '(/home/[a-zA-Z0-9_-]+|/Users/[a-zA-Z0-9_-]+|C:\\Users\\[a-zA-Z0-9_-]+)' $TRACKED_FILES 2>/dev/null | grep -v "security-audit.sh" || true)
if [ -n "$PATH_LEAKS" ]; then
    echo "[FAIL] Local filesystem path detected:"
    echo "$PATH_LEAKS"
    LEAK_FOUND=1
else
    echo "[PASS] Zero machine-specific filesystem paths detected."
fi

# 2. Scan for current OS user identity
echo "[AUDIT] Checking for local OS username leaks..."
CURRENT_USER="${USER:-$(whoami 2>/dev/null || echo "")}"
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "runner" ]; then
    USER_LEAKS=$(grep -rniF "$CURRENT_USER" $TRACKED_FILES 2>/dev/null | grep -v "security-audit.sh" || true)
    if [ -n "$USER_LEAKS" ]; then
        echo "[FAIL] OS username '$CURRENT_USER' detected in repository files:"
        echo "$USER_LEAKS"
        LEAK_FOUND=1
    else
        echo "[PASS] Zero OS username leaks detected."
    fi
fi

# 3. Scan for system hostname leaks
echo "[AUDIT] Checking for local hostname leaks..."
CURRENT_HOST="$(hostname 2>/dev/null || echo "")"
if [ -n "$CURRENT_HOST" ] && [ "$CURRENT_HOST" != "localhost" ]; then
    HOST_LEAKS=$(grep -rnF "$CURRENT_HOST" $TRACKED_FILES 2>/dev/null | grep -v "security-audit.sh" || true)
    if [ -n "$HOST_LEAKS" ]; then
        echo "[FAIL] System hostname '$CURRENT_HOST' detected in repository files:"
        echo "$HOST_LEAKS"
        LEAK_FOUND=1
    else
        echo "[PASS] Zero hostname leaks detected."
    fi
fi

# 4. Scan for API credentials, tokens, and private keys
echo "[AUDIT] Checking for potential credentials and secrets..."
SECRET_LEAKS=$(grep -rnE '(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|vercel_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----)' $TRACKED_FILES 2>/dev/null | grep -v "security-audit.sh" || true)
if [ -n "$SECRET_LEAKS" ]; then
    echo "[FAIL] Secret or API key pattern detected:"
    echo "$SECRET_LEAKS"
    LEAK_FOUND=1
else
    echo "[PASS] Zero secrets or API credentials detected."
fi

# 5. Scan for emojis in code, comments, and documentation
echo "[AUDIT] Checking for emojis across all repository files..."
EMOJI_LEAKS=$(python3 -c '
import sys, re

# Range covering standard emojis
emoji_regex = re.compile(
    r"[\U0001F300-\U0001F9FF]"
    r"|[\U0001FA00-\U0001FAFF]"
    r"|[\U00002600-\U000027BF]"
    r"|[\U0001F600-\U0001F64F]"
    r"|[\U0001F680-\U0001F6FF]"
)

files = sys.argv[1:]
found = False
for fpath in files:
    if "security-audit.sh" in fpath or fpath.endswith((".png", ".gif", ".jpg", ".jpeg", ".ico")):
        continue
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for lnum, line in enumerate(f, start=1):
                m = emoji_regex.search(line)
                if m:
                    print(f"{fpath}:{lnum}: Emoji character detected: {m.group(0)}")
                    found = True
    except Exception:
        pass
if found:
    sys.exit(1)
' $TRACKED_FILES || true)

if [ -n "$EMOJI_LEAKS" ]; then
    echo "[FAIL] Emoji characters detected:"
    echo "$EMOJI_LEAKS"
    LEAK_FOUND=1
else
    echo "[PASS] Zero emojis detected across repository."
fi

# 6. Verify Git configuration
echo "[AUDIT] Checking git configuration..."
GIT_EMAIL=$(git config user.email || echo "")
if [ -n "$GIT_EMAIL" ] && [[ "$GIT_EMAIL" != *"152591660+1MEshh@users.noreply.github.com"* ]]; then
    echo "[FAIL] Git user.email ('$GIT_EMAIL') does not match authorized address."
    LEAK_FOUND=1
else
    echo "[PASS] Git user.email is properly sanitized."
fi

# 7. Check if any audit rule failed
if [ "$LEAK_FOUND" -ne 0 ]; then
    echo "[AUDIT] FAILED: One or more security gate checks failed."
    exit 1
fi

echo "[AUDIT] ALL GATE CHECKS PASSED: Clean architecture and zero leaks verified."
