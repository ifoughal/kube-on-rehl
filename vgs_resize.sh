#!/bin/bash
VG_NAME="rootvg"
REDUCE_VOL_LV="lv_srv"
REDUCE_VOL_MOUNT="/srv"
EXTEND_VOL_LV="lv_var"
EXTEND_VOL_MOUNT="/var"

# Unmount before resizing
umount $REDUCE_VOL_MOUNT # || exit 1

echo "[*] Running fsck before shrinking..."
e2fsck -f /dev/$VG_NAME/$REDUCE_VOL_LV # || exit 1

# Resize FS safely
resize2fs /dev/$VG_NAME/$REDUCE_VOL_LV 164M # || exit 1

# Shrink LV (with resize)
lvreduce -L 0.17G -r /dev/$VG_NAME/$REDUCE_VOL_LV -y # || exit 1

# Extend /var LV with all remaining space (or fixed size)
lvextend -L +1.53G -r /dev/$VG_NAME/$EXTEND_VOL_LV -y # || exit 1

# Remount the volume
mount /dev/$VG_NAME/$REDUCE_VOL_LV $REDUCE_VOL_MOUNT # || exit 1
