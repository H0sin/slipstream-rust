#!/bin/bash
set -euo pipefail

# ── DNS Resolver Scanner ─────────────────────────────────────────
# Scans ranges.txt to find working DNS resolvers from this server.
#
# Usage:
#   chmod +x scan_resolvers.sh
#   ./scan_resolvers.sh [ranges_file] [samples_per_range]
#
# Phase 1: Tests all known/named DNS IPs (top of file)
# Phase 2: Samples random IPs from CIDR /16 ranges
#
# Output: working resolvers written to resolvers_found.txt

RANGES_FILE="${1:-ranges.txt}"
SAMPLES="${2:-3}"            # random IPs to try per /16 range
TIMEOUT=3                    # seconds per probe
OUTFILE="resolvers_found.txt"
TMPFILE=$(mktemp)

if [ ! -f "$RANGES_FILE" ]; then
  echo "ERROR: $RANGES_FILE not found"
  exit 1
fi

probe() {
  local ip="$1"
  local result
  result=$(timeout "$TIMEOUT" dig @"$ip" google.com A +short +time=2 +tries=1 2>/dev/null) || true
  if [ -n "$result" ] && echo "$result" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    local ms
    ms=$(timeout "$TIMEOUT" dig @"$ip" google.com A +time=2 +tries=1 2>/dev/null | grep "Query time" | awk '{print $4}') || true
    echo "OK  $ip  (${ms:-?}ms)"
    echo "$ip" >> "$OUTFILE"
    return 0
  fi
  return 1
}

> "$OUTFILE"

# ── Phase 1: Known DNS IPs ───────────────────────────────────────
echo "=== Phase 1: Testing known DNS resolvers ==="
known_ips=()
in_ranges=false
while IFS= read -r line; do
  line=$(echo "$line" | sed 's/#.*//' | tr -d '[:space:]')
  [ -z "$line" ] && continue
  # Stop when we hit CIDR ranges
  if echo "$line" | grep -q '/'; then
    break
  fi
  # Single IP (no CIDR, no dash)
  if echo "$line" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    known_ips+=("$line")
  fi
done < "$RANGES_FILE"

echo "Found ${#known_ips[@]} known DNS IPs to test..."
ok=0
fail=0
for ip in "${known_ips[@]}"; do
  printf "  %-20s " "$ip"
  if probe "$ip"; then
    ((ok++))
  else
    echo "FAIL"
    ((fail++))
  fi
done
echo ""
echo "Phase 1 done: $ok working, $fail failed"
echo ""

# ── Phase 2: Sample from CIDR ranges ────────────────────────────
echo "=== Phase 2: Sampling $SAMPLES IPs per CIDR range ==="

# Parse CIDR ranges
cidr_ranges=()
while IFS= read -r line; do
  line=$(echo "$line" | sed 's/#.*//' | tr -d '[:space:]')
  [ -z "$line" ] && continue
  if echo "$line" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    cidr_ranges+=("$line")
  fi
done < "$RANGES_FILE"

echo "Found ${#cidr_ranges[@]} CIDR ranges to scan..."
echo ""

range_ok=0
range_total=0

for cidr in "${cidr_ranges[@]}"; do
  # Extract base IP and prefix
  base_ip="${cidr%/*}"
  prefix="${cidr#*/}"

  # Convert base IP to integer
  IFS='.' read -r a b c d <<< "$base_ip"
  base_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))

  # Calculate range size
  host_bits=$((32 - prefix))
  range_size=$((1 << host_bits))

  # Pick SAMPLES random IPs from this range
  # Try common DNS-like IPs first: .1, .2, .53, .100, .200, then random
  declare -a offsets=()
  for special in 1 2 53 100 200; do
    if [ "$special" -lt "$range_size" ]; then
      offsets+=("$special")
    fi
  done
  # Add random offsets
  while [ "${#offsets[@]}" -lt "$SAMPLES" ] && [ "${#offsets[@]}" -lt "$range_size" ]; do
    r=$((RANDOM % range_size))
    [ "$r" -eq 0 ] && continue
    offsets+=("$r")
  done

  # Deduplicate and limit
  readarray -t offsets < <(printf '%s\n' "${offsets[@]}" | sort -un | head -n "$SAMPLES")

  found_in_range=false
  for off in "${offsets[@]}"; do
    ip_int=$((base_int + off))
    o1=$(( (ip_int >> 24) & 255 ))
    o2=$(( (ip_int >> 16) & 255 ))
    o3=$(( (ip_int >> 8) & 255 ))
    o4=$(( ip_int & 255 ))
    sample_ip="$o1.$o2.$o3.$o4"

    ((range_total++))
    printf "  [%s] %-20s " "$cidr" "$sample_ip"
    if probe "$sample_ip"; then
      ((range_ok++))
      found_in_range=true
    else
      echo "FAIL"
    fi
  done
done

echo ""
echo "=== SUMMARY ==="
echo "Working resolvers saved to: $OUTFILE"
echo "Total found: $(wc -l < "$OUTFILE")"
echo ""
cat "$OUTFILE"

rm -f "$TMPFILE"
