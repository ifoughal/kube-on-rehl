#!/bin/bash

# This script extends a logical volume and resizes the filesystem.
set -e  # Exit on error
DEVICE="/dev/sdc2"
VG_NAME="rootvg"
LV_PATH="/dev/mapper/${VG_NAME}-lv_opt"
MOUNT_POINT="/opt"


echo ">>> Creating physical volume on $DEVICE..."
pvcreate "$DEVICE"

echo ">>> Extending volume group $VG_NAME..."
vgextend "$VG_NAME" "$DEVICE"

echo ">>> Extending logical volume $LV_PATH with all free space..."
lvextend -l +100%FREE "$LV_PATH"

echo ">>> Resizing XFS filesystem on $MOUNT_POINT..."
xfs_growfs "$MOUNT_POINT"

echo "✅ Done. New size:"
df -h "$MOUNT_POINT"
