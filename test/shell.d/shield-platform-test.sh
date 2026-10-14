#!/bin/bash
# Shared fixtures and sourced image helpers assign the test's variables.
# shellcheck disable=SC1091,SC2154

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
require_platform_fixtures "Shield platform fixtures"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fake_platform "$work/board" aarch64-shield
export OMARCHY_PATH=$ROOT
export OMARCHY_PROC_ROOT=$work/board/proc
export PATH=$work/board/bin:$ROOT/bin:$PATH

for board in nvidia,p2894-0050-a08 nvidia,p2894-2551-b00; do
  printf '%s\0' "$board" nvidia,darcy nvidia,tegra210b01 nvidia,tegra210 >"$OMARCHY_PROC_ROOT/device-tree/compatible"
  [[ $(omarchy-hw-platform) == "aarch64-shield" ]] || fail "$board selects the Shield platform"
  omarchy-hw-aarch64-shield || fail "$board passes the Shield predicate"
done
pass "verified 2019 Pro board identifiers select Shield"

printf '%s\0' nvidia,p2571 nvidia,tegra210 >"$OMARCHY_PROC_ROOT/device-tree/compatible"
[[ $(omarchy-hw-platform) == "aarch64" ]] || fail "an older Shield is not a 2019 Pro"
! omarchy-hw-aarch64-shield || fail "the predicate rejects an older Shield"
printf '%s\0' nvidia,p2894-2551-b00 nvidia,tegra210 >"$OMARCHY_PROC_ROOT/device-tree/compatible"
! omarchy-hw-platform >/dev/null 2>&1 || fail "a Shield board without B01 is contradictory"
printf '%s\0' nvidia,p2894-2551-b00 nvidia,tegra210b01 apple,t6021 >"$OMARCHY_PROC_ROOT/device-tree/compatible"
! omarchy-hw-platform >/dev/null 2>&1 || fail "mixed Apple and Shield identity is contradictory"
pass "older hardware and contradictory device trees are refused"

fake_platform "$work/board" aarch64-shield
defaults=$(omarchy-pkg-defaults)
for package in hyprland quickshell omarchy-shield linux-shield snapper openssh mesa-utils linux-firmware-nvidia; do
  grep -qxF "$package" <<<"$defaults" || fail "Shield includes $package"
done
! grep -qxF omarchy-mac <<<"$defaults" || fail "Shield excludes the Mac platform package"
[[ $(omarchy-pkg-defaults aarch64-shield) == "$defaults" ]] || fail "image builders get the same package set"
source "$ROOT/install/helpers/pacman.sh"
[[ $(omarchy_pacman_default_channel aarch64-shield) == "edge" ]] || fail "Shield uses the ARM channel"
templates=$(omarchy_pacman_templates aarch64-shield)
# shellcheck disable=SC2016 # Pacman's $arch token must remain literal here.
grep -qF 'https://pkgs.omarchy.org/edge/$arch' "$templates/pacman-edge.conf" || fail "Shield uses ARM Omarchy packages"
grep -qxF 'IgnorePkg = omarchy omarchy-settings omarchy-shield linux-shield' "$templates/pacman-edge.conf" || fail "repository upgrades preserve the local fork and kernel"
! grep -qF '[multilib]' "$templates/pacman-edge.conf" || fail "Shield has no x86 multilib"
pass "Shield composes the real Omarchy desktop and ARM repository templates"

export OMARCHY_IMAGE_ROOT=$work/image
mkdir -p "$OMARCHY_IMAGE_ROOT/var/lib/omarchy/image"
printf 'format=1\nplatform=aarch64-shield\n' >"$OMARCHY_IMAGE_ROOT/var/lib/omarchy/image/target"
[[ $(omarchy-hw-platform) == "aarch64-shield" ]] || fail "the image manifest selects Shield"
source "$ROOT/install/helpers/image-target.sh"
omarchy_image_init
omarchy_image_read_manifest || fail "hardware deferral accepts the Shield image manifest"
[[ $omarchy_image_platform == "aarch64-shield" ]] || fail "the hardware queue retains Shield identity"
unset OMARCHY_IMAGE_ROOT
pass "Shield image manifests agree with the hardware deferral parser"

export OMARCHY_LIFECYCLE_ROOT=$work/lifecycle
mkdir -p "$OMARCHY_LIFECYCLE_ROOT"
for operation in setup-boot update-verify reset-prepare provision-prepare; do
  status=0
  omarchy-lifecycle-dispatch --resolve "$operation" >"$work/output" 2>"$work/error" || status=$?
  (( status == 3 )) || fail "$operation requires the Shield lifecycle package"
  grep -qF omarchy-shield "$work/error" || fail "$operation names the missing package"
done
pass "Shield boot operations cannot silently use PC lifecycle handling"

! /bin/bash "$ROOT/bin/omarchy-hw-aarch64-shield" -p >/dev/null 2>&1 || fail "the Shield predicate requires privileged Bash startup"
pass "the Shield predicate preserves the privileged startup boundary"
