#!/usr/bin/env bash
# vm-provision.sh — one-command KVM VM for the s3tap load test (no snap needed).
#
# Creates an Ubuntu 24.04 VM via system libvirt (qemu:///system, so there is no
# user-group re-login dance), preinstalls every dependency via cloud-init, and
# prints how to log in. Then inside the VM:
#     git clone https://github.com/echemythia/s3tap.git && cd s3tap
#     aws configure                     # your real creds
#     S3TAP_BUCKET=... S3TAP_KEY=... AWS_REGION=... ./scripts/vm-loadtest.sh
#
# Host requirements: KVM enabled (/dev/kvm present) on a Debian/Ubuntu-family host,
# plus an SSH key pair (login is key-based; set VM_SSH_PUBKEY to pick one).
# Re-run safely: it reuses a cached base image; destroy the VM first to recreate.
#
#   Env overrides:  VM_NAME (default s3tap-test), VM_MEM_MB (6144), VM_VCPUS (4),
#                   VM_DISK_GB (20), VM_SSH_PUBKEY (default ~/.ssh/id_ed25519.pub
#                   or ~/.ssh/id_rsa.pub)
set -euo pipefail

VM="${VM_NAME:-s3tap-test}"
MEM="${VM_MEM_MB:-6144}"
VCPUS="${VM_VCPUS:-4}"
DISK_GB="${VM_DISK_GB:-20}"
IMG_URL="https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
IMG_DIR="/var/lib/libvirt/images"
BASE="${IMG_DIR}/ubuntu-24.04-cloudimg-base.img"
DISK="${IMG_DIR}/${VM}.qcow2"
CI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vm-cloud-init.yaml"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
die() { printf '\n\033[31mABORT\033[0m %s\n' "$1"; exit 2; }

# --- preflight ---------------------------------------------------------------
say "Preflight"
[ -e /dev/kvm ] || die "/dev/kvm missing — enable virtualization (VT-x/AMD-V) in BIOS first"
[ -f "$CI" ]    || die "cloud-init file not found: $CI"

# Resolve the SSH public key injected for the guest's `ubuntu` user (key-based
# login — this VM has no password auth). Prefer VM_SSH_PUBKEY, else the usual pair.
PUBKEY="${VM_SSH_PUBKEY:-}"
if [ -z "$PUBKEY" ]; then
  for k in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    [ -f "$k" ] && { PUBKEY="$k"; break; }
  done
fi
[ -n "$PUBKEY" ] && [ -f "$PUBKEY" ] || die "no SSH public key found — generate one \
(ssh-keygen -t ed25519) or set VM_SSH_PUBKEY to a .pub file. The VM uses key-based login."
echo "KVM present; VM=$VM mem=${MEM}MB vcpus=$VCPUS disk=${DISK_GB}G; ssh key=$PUBKEY"

# Build a runtime cloud-init that appends our public key to the template.
USERDATA="$(mktemp --suffix=.yaml)"
trap 'rm -f "$USERDATA"' EXIT
cp "$CI" "$USERDATA"
{
  echo
  echo "ssh_authorized_keys:"
  echo "  - $(cat "$PUBKEY")"
} >> "$USERDATA"

# --- host packages -----------------------------------------------------------
say "Install libvirt/QEMU on the host (idempotent)"
if ! command -v virt-install >/dev/null || ! command -v qemu-img >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y qemu-system-x86 qemu-utils libvirt-daemon-system \
                          libvirt-clients virtinst cloud-image-utils osinfo-db-tools
fi
sudo systemctl enable --now libvirtd >/dev/null 2>&1 || true

# --- default NAT network (gives the guest outbound egress to S3) -------------
say "Ensure the libvirt 'default' NAT network is up"
if ! sudo virsh net-info default >/dev/null 2>&1; then
  sudo virsh net-define /usr/share/libvirt/networks/default.xml 2>/dev/null || true
fi
sudo virsh net-start default   2>/dev/null || true
sudo virsh net-autostart default 2>/dev/null || true

# --- refuse to clobber an existing VM ----------------------------------------
if sudo virsh dominfo "$VM" >/dev/null 2>&1; then
  die "a VM named '$VM' already exists. Remove it first:
    sudo virsh destroy $VM 2>/dev/null; sudo virsh undefine $VM --remove-all-storage"
fi

# --- base image (cached) + a resized per-VM disk copy ------------------------
say "Fetch the Ubuntu 24.04 cloud image (cached at $BASE)"
if [ ! -f "$BASE" ]; then
  sudo curl -fSL --retry 3 -o "$BASE" "$IMG_URL"
else
  echo "reusing cached base image"
fi
say "Create the VM disk (${DISK_GB}G)"
sudo cp --reflink=auto "$BASE" "$DISK"
sudo qemu-img resize "$DISK" "${DISK_GB}G"

# --- os-variant: prefer 24.04, fall back if osinfo-db is older ---------------
if osinfo-query os 2>/dev/null | grep -q 'ubuntu24.04'; then OSV="ubuntu24.04"; else OSV="ubuntu22.04"; fi
echo "using --os-variant $OSV"

# --- create the VM (import the disk, apply cloud-init) -----------------------
say "Boot the VM"
sudo virt-install \
  --connect qemu:///system \
  --name "$VM" --memory "$MEM" --vcpus "$VCPUS" \
  --disk path="$DISK",format=qcow2,bus=virtio \
  --import --os-variant "$OSV" \
  --cloud-init user-data="$USERDATA" \
  --network network=default,model=virtio \
  --graphics none --noautoconsole

# --- wait for the guest to get a DHCP lease ----------------------------------
say "Waiting for the VM's IP (cloud-init installs deps in the background)"
IP=""
for _ in $(seq 1 40); do
  IP="$(sudo virsh domifaddr "$VM" 2>/dev/null | awk '/ipv4/{print $4}' | cut -d/ -f1 | head -1)"
  [ -n "$IP" ] && break
  sleep 5
done

say "Done"
if [ -n "$IP" ]; then
  cat <<EOF
VM '$VM' is up at $IP (login: key-based, as user 'ubuntu').

  ssh ubuntu@$IP          # uses the key injected from $PUBKEY
                          # (sudo virsh console $VM shows boot output; Ctrl-] to detach)

Inside the VM, wait for provisioning to finish, then run the load test:

  cloud-init status --wait                       # deps still installing on first boot
  source ~/.cargo/env
  git clone https://github.com/echemythia/s3tap.git && cd s3tap
  aws configure                                  # your real AWS creds
  S3TAP_BUCKET=your-bucket S3TAP_KEY=path/to/object AWS_REGION=eu-west-1 \\
    ./scripts/vm-loadtest.sh

Teardown when finished:
  sudo virsh destroy $VM; sudo virsh undefine $VM --remove-all-storage
EOF
else
  cat <<EOF
The VM booted but no IP appeared yet. Attach to its console to watch progress:
  sudo virsh console $VM        # boot output only (login is key-based over SSH)
Find the IP once it leases, then SSH in:
  sudo virsh domifaddr $VM
  ssh ubuntu@<ip>
EOF
fi
