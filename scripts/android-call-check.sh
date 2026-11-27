#!/system/bin/sh
# WireGuard Plus - call/network self-check for Android (no root needed).
# Run it from Termux, or from a PC:  adb push scripts/android-call-check.sh /data/local/tmp/ && adb shell sh /data/local/tmp/android-call-check.sh
# It prints a short report with no keys, passwords or server addresses. Paste the whole output back to the developer.

say() { printf '%s\n' "$*"; }
run() { "$@" 2>/dev/null; }
have() { command -v "$1" >/dev/null 2>&1; }

say "### WireGuard Plus call check"
say "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "model: $(run getprop ro.product.manufacturer) $(run getprop ro.product.model)"
say "android: $(run getprop ro.build.version.release) (API $(run getprop ro.build.version.sdk))"
say "miui: $(run getprop ro.miui.ui.version.name) hyperos: $(run getprop ro.mi.os.version.name) oneui: $(run getprop ro.build.version.oneui)"
say "miui_optimization: $(run getprop persist.sys.miui_optimization)"
say "kernel: $(run uname -r)"
say

say "## Wi-Fi interface"
WLAN_IP=""
if have ip; then
  WLAN_IP=$(ip -4 addr show wlan0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -n 1)
  say "wlan0 ipv4: ${WLAN_IP:-none}"
  say "mtu: $(ip link show wlan0 2>/dev/null | sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -n 1)"
  say
  say "## Loopback routing (calls use 127.0.0.x relays)"
  for ip4 in 127.0.0.1 127.0.0.31 127.0.0.234; do
    say "route to $ip4: $(ip route get "$ip4" 2>&1 | head -n 1)"
  done
  if [ -n "$WLAN_IP" ]; then
    say "route to 127.0.0.234 from wlan ip: $(ip route get 127.0.0.234 from "$WLAN_IP" 2>&1 | head -n 1)"
  fi
  say "rules:"
  ip rule 2>/dev/null | head -n 12 | sed 's/^/  /'
else
  say "ip tool not available"
fi
say

say "## Kernel network switches that can break loopback relays"
for f in /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/wlan0/rp_filter /proc/sys/net/ipv4/conf/all/route_localnet /proc/sys/net/ipv4/conf/lo/rp_filter; do
  [ -r "$f" ] && say "$f = $(cat "$f" 2>/dev/null)"
done
say

say "## UDP loopback echo test (127.0.0.234:49311)"
if have nc; then
  TMP_BASE="${TMPDIR:-/data/local/tmp}"
  [ -w "$TMP_BASE" ] || TMP_BASE="."
  OUT_FILE="$TMP_BASE/wgp_nc.$$"
  ( nc -u -l -p 49311 -s 127.0.0.234 >"$OUT_FILE" 2>/dev/null || nc -u -l 127.0.0.234 49311 >"$OUT_FILE" 2>/dev/null ) &
  LP=$!
  sleep 1
  printf 'wgp-probe' | nc -u -w1 127.0.0.234 49311 >/dev/null 2>&1
  sleep 1
  kill "$LP" 2>/dev/null
  if [ -s "$OUT_FILE" ]; then say "loopback UDP to 127.0.0.234: OK"; else say "loopback UDP to 127.0.0.234: NO DATA (blocked or nc flags unsupported)"; fi
  rm -f "$OUT_FILE" 2>/dev/null
else
  say "nc not available (skipped)"
fi
say

say "## Battery / background limits"
if have dumpsys; then
  say "deviceidle whitelist hit: $(run dumpsys deviceidle whitelist | grep -c -E 'org.telegram|wgplus')"
  say "standby bucket (telegram): $(run am get-standby-bucket org.telegram.messenger.web) / plus: $(run am get-standby-bucket org.telegram.plus)"
else
  say "dumpsys not available (skipped)"
fi
say

say "## WireGuard Plus status (works over adb shell)"
if have content; then
  run content call --uri content://org.telegram.wgplus.module.status --method automation_status | head -c 3500
  say
else
  say "content tool not available (skipped)"
fi
say
say "### end of report"
