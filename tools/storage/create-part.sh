#!bin/bash


# This script creates a new partition on a specified disk and formats it with XFS.
# It also mounts the partition to a specified mount point.
# It is designed to be run as root.
#
# Usage: ./create-part.sh <disk> <partition_size> <mount_point>

# Example: ./create-part.sh /dev/sdb 10G /mnt/new_partition

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root!"
    exit 1
fi

DISK=/dev/sdc
SUB_DISK=1
PARTITION="${DISK}${SUB_DISK}" # First partition
MOUNT_POINT=/var
FILESYSTEM=ext4
VOLUME_PATH=/var
LV_PATH=/dev/rootvg/lv_var
PARTITION_SIZE="+10G"

# Check if the disk exists
if [ ! -b "$DISK" ]; then
    echo "Disk $DISK does not exist."
    exit 1
fi

# Check if the mount point exists
if [ ! -d "$MOUNT_POINT" ]; then
    echo "Mount point $MOUNT_POINT does not exist. Creating it..."
    mkdir -p "$MOUNT_POINT"
fi

# Check if the partition already exists
if [ -b "$PARTITION" ]; then
    echo "Partition $PARTITION already exists."
    exit 1
fi
# Check if the filesystem is already mounted
if mountpoint -q "$MOUNT_POINT"; then
    echo "Mount point $MOUNT_POINT is already mounted."
    exit 1
fi
# Check if the filesystem is already formatted
if [ -b "$PARTITION" ]; then
    echo "Partition $PARTITION already formatted."
    exit 1
fi
# Create a new partition
echo "Creating a new partition on $DISK..."
sudo fdisk "$DISK" <<EOF
n
p
${SUB_DISK}

${PARTITION_SIZE}
w
EOF
# Extend rootvg
echo "Extending rootvg with $PARTITION..."
sudo vgextend rootvg "$PARTITION"
# Extend the logical volume
echo "Extending logical volume $LV_PATH..."
sudo lvextend -l +100%FREE "$LV_PATH"


if [ $FILESYSTEM == "xfs" ]; then
    # Resize the XFS filesystem
    echo "Resizing XFS filesystem on $MOUNT_POINT..."
    sudo xfs_growfs "$MOUNT_POINT"
elif [ $FILESYSTEM == "ext4" ]; then
    # Resize the ext4 filesystem
    echo "Resizing ext4 filesystem on $LV_PATH..."
    sudo resize2fs "$LV_PATH"
fi



exit 0




# Format the partition with XFS
echo "Formatting $PARTITION with $FILESYSTEM..."
sudo mkfs.$FILESYSTEM "$PARTITION"
# Create mount point
echo "Creating mount point at $MOUNT_POINT..."
sudo mkdir -p "$MOUNT_POINT"
# Mount the partition
echo "Mounting $PARTITION to $MOUNT_POINT..."
sudo mount "$PARTITION" "$MOUNT_POINT"
# Check if the mount was successful
if mountpoint -q "$MOUNT_POINT"; then
    echo "✅ Successfully mounted $PARTITION to $MOUNT_POINT."
else
    echo "❌ Failed to mount $PARTITION to $MOUNT_POINT."
    # exit 1
fi