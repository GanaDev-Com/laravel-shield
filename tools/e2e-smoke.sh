#!/usr/bin/env bash
#
# Ganadev Shield — E2E smoke test terhadap server HTTP nyata.
#
# Menjalankan aplikasi contoh (examples/laravel-demo) dengan `php -S`, lalu
# menguji alur HTTP asli: normal, blok critical, SQLi body, bot terverifikasi,
# ban -> challenge, verify -> kembali ke halaman asal, dan trusted cookie.
#
# Usage: bash tools/e2e-smoke.sh
# Requirements: php + curl, contoh aplikasi belum berjalan di port yang sama.
set -euo pipefail

# Body form di-encode manual (redirect=%2Fhome) supaya MSYS (Git Bash Windows)
# tidak mengubah "/home" menjadi path Windows. Tidak berpengaruh di Linux (CI).
export MSYS2_ARG_CONV_EXCL='redirect=*'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="$ROOT/examples/laravel-demo"
PORT="${PORT:-8099}"
BASE="http://127.0.0.1:${PORT}"
COOKIE_JAR="$(mktemp)"
CHALLENGE_HTML="$(mktemp)"
PASS=0
FAIL=0

SERVER_PID=""
cleanup() {
    rm -f "$COOKIE_JAR" "$CHALLENGE_HTML"
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

ok()    { local name="$1"; PASS=$((PASS+1)); echo "  PASS  $name"; }
bad()   { local name="$1" detail="$2"; FAIL=$((FAIL+1)); echo "  FAIL  $name  $detail"; }
check() { local name="$1" cond="$2"; if [[ "$cond" == "true" ]]; then ok "$name"; else bad "$name" "(got: $cond)"; fi; }

echo "== Ganadev Shield E2E smoke ($PORT) =="

# --- Setup demo app -----------------------------------------------------------
cd "$DEMO"
cp .env.example .env
sed -i 's/^SHIELD_MODE=.*/SHIELD_MODE=enforce/' .env
sed -i 's/^SHIELD_CHALLENGE=.*/SHIELD_CHALLENGE=null/' .env
rm -f database/database.sqlite
php artisan key:generate --force >/dev/null
php artisan migrate --force >/dev/null
php artisan config:clear >/dev/null 2>&1 || true
php artisan cache:clear >/dev/null 2>&1 || true

php -S "127.0.0.1:${PORT}" -t public >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# --- 1. Normal & bot terverifikasi (sebelum ada ban) --------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/home")
check "normal /home -> 200" "$([[ "$code" == "200" ]] && echo true || echo false)"

code=$(curl -s -o /dev/null -w '%{http_code}' \
    -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
    "$BASE/home")
check "verified Googlebot -> 200" "$([[ "$code" == "200" ]] && echo true || echo false)"

# --- 2. Blok critical & payload (menciptakan ban untuk 127.0.0.1) -------------
hdr=$(curl -s -D - -o /dev/null "$BASE/.env" | tr -d '\r' | grep -i '^X-Shield-Blocked:' || true)
check "/.env blocked (sensitive.env)" "$(echo "$hdr" | grep -q 'sensitive.env' && echo true || echo false)"

hdr=$(curl -s -D - -o /dev/null -X POST "$BASE/login" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "username=admin'+UNION+SELECT+password+FROM+users--&password=x" \
    | tr -d '\r' | grep -i '^X-Shield-Blocked:' || true)
check "SQLi body blocked (payload.sqli.union)" "$(echo "$hdr" | grep -q 'payload.sqli.union' && echo true || echo false)"

# --- 3. Ban -> redirect ke challenge ------------------------------------------
loc=$(curl -s -D - -o /dev/null "$BASE/home" | tr -d '\r' | grep -i '^Location:' || true)
check "banned ip /home -> challenge redirect" "$(echo "$loc" | grep -q '/shield/challenge' && echo true || echo false)"

# --- 4. Halaman challenge render ----------------------------------------------
code=$(curl -s -c "$COOKIE_JAR" -o "$CHALLENGE_HTML" -w '%{http_code}' \
    "$BASE/shield/challenge?redirect=/home")
html=$(cat "$CHALLENGE_HTML")
check "challenge page renders (200)" "$([[ "$code" == "200" ]] && echo true || echo false)"
check "challenge page has CSRF token" "$(echo "$html" | grep -q 'name="_token"' && echo true || echo false)"

# --- 5. Verify -> kembali ke /home (regresi redirect relatif) -----------------
token=$(echo "$html" | sed -n 's/.*name="_token" value="\([^"]*\)".*/\1/p' | head -n1)
# Body form di-encode manual (redirect=%2Fhome) agar bebas dari MSYS path
# conversion; nilai "/home" tetap ter-decode server. Satu POST saja (CSRF
# token single-use di Laravel). Ambil status + Location sekaligus.
resp=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" -D - -o /dev/null -w '|%{http_code}' -X POST \
    "$BASE/shield/challenge/verify" \
    --data-binary "_token=$token&shield_challenge_token=test-token&redirect=%2Fhome" \
    -H 'Content-Type: application/x-www-form-urlencoded')
code="${resp##*|}"
loc=$(echo "${resp%|*}" | tr -d '\r' | grep -i '^Location:' || true)
check "verify HTTP 302" "$([[ "$code" == "302" ]] && echo true || echo false)"
check "verify redirects back to /home" "$(echo "$loc" | grep -q '/home' && echo true || echo false)"

code=$(curl -s -b "$COOKIE_JAR" -o /dev/null -w '%{http_code}' "$BASE/home")
check "/home after challenge -> 200" "$([[ "$code" == "200" ]] && echo true || echo false)"

# --- 6. Trusted cookie tidak menembus rule critical ----------------------------
hdr=$(curl -s -b "$COOKIE_JAR" -D - -o /dev/null "$BASE/.env" | tr -d '\r' | grep -i '^X-Shield-Blocked:' || true)
check "/.env still blocked with trusted cookie" "$(echo "$hdr" | grep -q 'sensitive.env' && echo true || echo false)"

echo ""
echo "Result: $PASS passed, $FAIL failed"
exit "$([[ "$FAIL" == "0" ]] && echo 0 || echo 1)"