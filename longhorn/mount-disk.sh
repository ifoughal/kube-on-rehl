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
mkfs.ext4 ${DISK}

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
echo "UUID=$UUID $MOUNT_POINT ext4 defaults 0 2" | sudo tee -a /etc/fstab

# reload systemctl to account for fstab changes
sudo systemctl daemon-reload

# Mount all filesystems mentioned in fstab
sudo mount -a

echo "Disk ${DISK} has been mounted to $MOUNT_POINT and added to /etc/fstab"
