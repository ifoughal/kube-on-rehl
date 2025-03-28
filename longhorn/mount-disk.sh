#!/bin/bash

DISK=/dev/sdb
# Check if /dev/sdb exists
if lsblk | grep -q "sdb"; then
  echo "${DISK} exists, proceeding with mounting steps."
else
  echo "${DISK} does not exist. Please check your disk configuration."
  exit 1
fi

# Format the disk with a filesystem like ext4:
# mkfs.ext4 ${DISK}
systemctl stop containerd.service


sudo umount -l ${DISK}

sudo fuser -v /dev/sdb
sudo fuser -k ${DISK}
sudo umount -f ${DISK}

mkfs.xfs -f ${DISK}

# Get the UUID of the disk
UUID=$(blkid -s UUID -o value ${DISK})

# Check if UUID was retrieved successfully
if [ -z "$UUID" ]; then
  echo "Failed to retrieve UUID for ${DISK}"
  exit 1
fi

# Create the mount point
MOUNT_POINT="/mnt/longhorn-1"
sudo mkdir -p $MOUNT_POINT

#  Mount sdb to the created directory
sudo mount ${DISK} /mnt/longhorn-1

# Backup the current fstab file
sudo cp /etc/fstab /etc/fstab.bak

# Add the new entry to fstab
echo "UUID=$UUID $MOUNT_POINT xfs defaults 0 2" | sudo tee -a /etc/fstab

# reload systemctl to account for fstab changes
sudo systemctl daemon-reload

# Mount all filesystems mentioned in fstab
sudo mount -a

echo "Disk ${DISK} has been mounted to $MOUNT_POINT and added to /etc/fstab"

exit 0


#############################################
# create a new mount/parition:
# gpt to extend it above 2Tb
parted ${DISK} mklabel gpt
parted ${DISK} mkpart primary xfs 0% 10GB

mkfs.xfs /dev/sdb1


#############################################
# extend a specific volume:
VOLUME_PATH=/var
VOLUME_TO_EXTEND=/dev/rootvg/lv_var

# Extend rootvg:
vgextend rootvg ${DISK}

lvextend -L+10G $VOLUME_TO_EXTEND
# if ext4
resize2fs ${VOLUME_TO_EXTEND}
# else if xfs:
xfs_growfs ${VOLUME_PATH}
#############################################

DISK="/dev/sdb"      # Change this if using another disk
PARTITION="${DISK}1" # First partition
MOUNT_POINT="/var/lib/longhorn/"
FILESYSTEM="xfs"
PARTITION_SIZE="400GB"


sudo umount -l ${DISK}
sudo fuser -v ${DISK}
sudo fuser -k ${DISK}
sudo umount -f ${DISK}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root!"
    exit 1
fi

# Create a partition table (GPT by default)
echo "Creating partition table on $DISK..."
sudo parted -s "$DISK" mklabel gpt

# Create a 10GB partition
echo "Creating $PARTITION_SIZE partition..."
sudo parted -s "$DISK" mkpart primary "$FILESYSTEM" 0% "$PARTITION_SIZE"

# Wait for the system to detect the new partition
sleep 2

# Format the partition
echo "Formatting $PARTITION as $FILESYSTEM..."
sudo mkfs.$FILESYSTEM "$PARTITION"

# Create mount point
echo "Creating mount point at $MOUNT_POINT..."
sudo mkdir -p "$MOUNT_POINT"

# Mount the partition
echo "Mounting $PARTITION to $MOUNT_POINT..."
sudo mount "$PARTITION" "$MOUNT_POINT"

# Add to /etc/fstab for persistence
echo "Updating /etc/fstab..."
echo "$PARTITION $MOUNT_POINT $FILESYSTEM defaults 0 0" >> /etc/fstab

# Verify
echo "Partition setup complete! Checking mount..."
df -h | grep "$MOUNT_POINT"


