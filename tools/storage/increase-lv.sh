#!/bin/bash
##########################################################################
# COMMON
export VG_NAME="rootvg"
export VG_PART_NAME="lv_var"
export LV_PATH="/dev/mapper/${VG_NAME}-${VG_PART_NAME}"
export MOUNT_POINT="/var"
##########################################################################
# OPTION 1
# This script extends a logical volume and resizes the filesystem.
set -e  # Exit on error
export DEVICE="/dev/sdc"




##########################################################################
# OPTION 2
# resizing with logial volumes:

export DEVICE="/dev/sdc"
export PARTITION_NUMBER="5"
# Create a new partition
echo "Creating a new partition: $PARTITION_NUMBER on $DEVICE..."
sudo fdisk "$DEVICE" <<EOF
n
p
${SUB_DISK}

${PARTITION_SIZE}
w
EOF


sudo partprobe
##########################################################################
# COMMON:
echo ">>> Creating physical volume on $DEVICE..."
sudo pvcreate "$DEVICE"

echo ">>> Extending volume group $VG_NAME..."
sudo vgextend "$VG_NAME" "$DEVICE"

echo ">>> Extending logical volume $LV_PATH with all free space..."
sudo lvextend -l +100%FREE "$LV_PATH"

sudo resize2fs ${LV_PATH}

# echo ">>> Resizing XFS filesystem on $MOUNT_POINT..."
# xfs_growfs "$MOUNT_POINT"

echo "✅ Done. New size:"
df -h "$MOUNT_POINT"

exit 0


##########################################################################
# OPTION 3
# if disk has no overlaps, increase directly:


sudo parted /dev/sdc <<EOF
resizepart 1 100%
EOF


sudo partprobe

sudo pvresize /dev/sdc1
sudo lvextend -l +100%FREE /dev/rootvg/lv_var
sudo resize2fs /dev/rootvg/lv_var

