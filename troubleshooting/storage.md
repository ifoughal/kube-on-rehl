

# Force delete Persistent volume:
```bash
PV=vault-test-pv
kubectl delete pv ${PV} --grace-period=0 --force
kubectl patch pv ${PV} -p '{"metadata": {"finalizers": null}}'
```





##### Resizing a disk and applying changes:

###### Step 1: Rescan the SCSI Bus
```bash
# Run the following command to rescan the SCSI bus:
echo 1 > /sys/class/block/sda/device/rescan
```

###### Step 2: Verify the Disk Size
```bash
# Use the fdisk command to verify the new disk size:
sudo fdisk -l
```

###### Step 3: Resize the Partition
```bash
# Use parted to resize the partition:
DISK=/dev/sda
sudo parted $DISK
```
Once in parted:
```bash
In the parted prompt, enter the following commands:
(parted) resizepart 3 100%
(parted) quit
```

###### Step 4: Resize the Physical Volume
Resize the physical volume to use the new space:
```bash
sudo pvresize /dev/sda3
```

###### Step 5: Ensure partition changes:
```bash
sudo fdisk -l /dev/sda
```


###### Step 6: Extend the Logical Volumes of your `sda3 partition`:
eg: extending /usr:
```bash
root@lorionstrm01vel:/home/ifoughali/cluster-deployment# lsblk
NAME                 MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda                    8:0    0   50G  0 disk
├─sda1                 8:1    0  228M  0 part /boot/efi
├─sda2                 8:2    0  600M  0 part /boot
└─sda3                 8:3    0 49.2G  0 part
  ├─rootvg-lv_root   253:0    0  1.6G  0 lvm  /
  ├─rootvg-lv_swap   253:1    0    4G  0 lvm
  ├─rootvg-lv_usr    253:2    0    5G  0 lvm  /usr
```

Extend the logical volume to use the new space:
```bash
sudo lvresize -L 10G /dev/rootvg/lv_usr
```

###### Step 7: Resize the Filesystem
Finally, resize the filesystem to use the new space:
**Check your partition type:**
```bash
sudo blkid /dev/rootvg/lv_usr
```

**OPTION 1: for ext4:**
```bash
sudo resize2fs /dev/rootvg/lv_var
```

**OPTION 1: for XFS:**
```bash
sudo xfs_growfs /dev/almalinux/root
```

