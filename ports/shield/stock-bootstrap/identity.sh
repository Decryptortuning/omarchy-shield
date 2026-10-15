# SPDX-License-Identifier: MIT
stock_inventory_supported() {
  stock_tokens=$1
  [ "$2" = 33 ] && [ "$3" = 1 ] || return 1
  printf '%s\n' "$stock_tokens" | grep -qx 'nvidia,darcy' || return 1
  printf '%s\n' "$stock_tokens" | grep -qx 'nvidia,tegra210' || return 1
  if printf '%s\n' "$stock_tokens" | grep -Eq '^(apple,|qcom,|nvidia,tegra210b01$|nvidia,p2894-2551-)'; then
    return 1
  fi
}
