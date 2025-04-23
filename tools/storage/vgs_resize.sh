#!/bin/bash
VG_NAME="rootvg"
REDUCE_VOL_LV="lv_var"
REDUCE_VOL_MOUNT="/var"
REDUCE_TO_SIZE="500M"
EXTEND_VOL_LV="lv_opt"
EXTEND_VOL_MOUNT="/opt"



# Convert REDUCE_TO_SIZE (e.g. 900M) to G (e.g. 0.88G)
size_bytes=$(numfmt --from=iec "$REDUCE_TO_SIZE")
size_gb=$(awk "BEGIN { printf \"%.2f\", $size_bytes / (1024*1024*1024) }")

echo "[+] Calculated target LV size: ${size_gb}G"

# Unmount before resizing
umount "$REDUCE_VOL_MOUNT"  # || { echo "[-] Failed to unmount $REDUCE_VOL_MOUNT"; exit 1; }
if [ "$?" -ne 0 ]; then
    echo "[-] Failed to unmount $REDUCE_VOL_MOUNT"
    mkdir /tmp$REDUCE_VOL_MOUNT
    mount --bind /tmp$REDUCE_VOL_MOUNT $REDUCE_VOL_MOUNT

fi


echo "[*] Running fsck before shrinking..."
e2fsck -f "/dev/$VG_NAME/$REDUCE_VOL_LV"  # || { echo "[-] fsck failed"; exit 1; }

# Resize FS safely
resize2fs "/dev/$VG_NAME/$REDUCE_VOL_LV" "$REDUCE_TO_SIZE"  # || { echo "[-] resize2fs failed"; exit 1; }

# Shrink LV (with resize)
lvreduce -L "${size_gb}G" -r "/dev/$VG_NAME/$REDUCE_VOL_LV" -y  # || { echo "[-] lvreduce failed"; exit 1; }

# Extend the target LV
lvextend -L +1.53G -r "/dev/$VG_NAME/$EXTEND_VOL_LV" -y  # || { echo "[-] lvextend failed"; exit 1; }

# Remount the reduced volume
mount "/dev/$VG_NAME/$REDUCE_VOL_LV" "$REDUCE_VOL_MOUNT"  # || { echo "[-] mount failed"; exit 1; }