#!/bin/bash
# SPDX-License-Identifier: MIT
# Functions for the disposable VM copy; the physical root is read-only input.
shield_qemu_validate_accounts() {
  local vm_root=$1 name _password uid _remainder root_count=0
  [[ -f $vm_root/etc/passwd && ! -L $vm_root/etc/passwd ]] || return 1
  while IFS=: read -r name _password uid _remainder; do
    if [[ $name == "qemutest" ]]; then
      echo 'Refusing to reuse a preexisting qemutest account' >&2
      return 1
    fi
    if [[ $name == "root" ]]; then
      [[ $uid == "0" ]] || return 1
      (( root_count += 1 ))
    fi
  done < "$vm_root/etc/passwd"
  (( root_count == 1 )) || { echo 'The VM source requires exactly one root UID0 account' >&2; return 1; }
}

shield_qemu_validate_source() {
  local vm_root=$1 crypto_status
  shield_qemu_validate_accounts "$vm_root" || return 1
  if [[ -e $vm_root/etc/crypttab || -L $vm_root/etc/crypttab ]]; then
    [[ -f $vm_root/etc/crypttab && ! -L $vm_root/etc/crypttab && -r $vm_root/etc/crypttab ]] || return 1
    if grep -Eq '^[[:space:]]*[^#[:space:]]' "$vm_root/etc/crypttab"; then
      echo 'The virtual ext4 test does not accept preset physical crypto mappings' >&2
      return 1
    else
      crypto_status=$?
      (( crypto_status == 1 )) || { echo 'Cannot inspect VM source crypttab' >&2; return 1; }
    fi
  fi
}

shield_qemu_lock_accounts() {
  local vm_guest=$1 name
  shield_qemu_validate_accounts "$vm_guest" || return 1
  usermod --root "$vm_guest" --lock root || return 1
  for name in alarm portbuild; do
    if grep -q "^$name:" "$vm_guest/etc/passwd"; then
      usermod --root "$vm_guest" --lock "$name" || return 1
    fi
  done
}

shield_qemu_write_mounts() {
  local vm_source vm_guest
  vm_source=$(realpath -- "$1") || return 1
  vm_guest=$(realpath -- "$2") || return 1
  if [[ $vm_guest == "/" || $vm_source == "$vm_guest" || $vm_guest == "$vm_source/"* || $vm_source == "$vm_guest/"* ]]; then
    echo 'VM guest and source must be separate directories' >&2
    return 1
  fi
  [[ -d $vm_guest/etc && ! -L $vm_guest/etc && ! -L $vm_guest/etc/fstab ]] || return 1
  printf '%s\n' '# Disposable QEMU virt disk; physical Btrfs mounts are excluded.' \
    '/dev/vda / ext4 defaults 0 1' > "$vm_guest/etc/fstab"
}
