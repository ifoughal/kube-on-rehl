### Prerequisites
- Kubernetes 1.25+
- containerd v1.3.7+
- `bash`, `curl`, `findmnt`, `grep`, `awk`, `blkid`, `lsblk`, `jq`, `nfs-utils` must be installed.
- ext4 or XFS filesystem.
- open-iscsi instaLled and iscsid daemon running

### Minimum Recommended Specs:
##### Hardware:
- 3 nodes
- 4 vCPUs per node
- 4 GiB per node
- SSD/NVMe or similar performance block device on the node for storage (recommended)
- HDD/Spinning Disk or similar performance block device on the node for storage (verified)
- 500/250 max IOPS per volume (1 MiB I/O)
- 500/250 max throughput per volume (MiB/s)
##### CPU Arch:
- AMD64
- ARM64
- s390x (experimental)

### Installation procedure:

##### install utilities on all Nodes:

```bash
sudo dnf install curl jq nfs-utils -y
```

##### install open-iscsi on all Nodes:
- **option 1: manually:**
    ```bash
    yum --setopt=tsflags=noscripts install -y iscsi-initiator-utils
    echo "InitiatorName=$(/sbin/iscsi-iname)" > /etc/iscsi/initiatorname.iscsi
    systemctl enable iscsid
    systemctl start iscsid

    systemctl is-active iscsid
    ```
- **option 2: manually:**
through a deployment:
```bash
kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/v1.8.1/deploy/prerequisite/longhorn-iscsi-installation.yaml

kubectl -n longhorn-system get pod | grep longhorn-iscsi-installation
kubectl -n longhorn-system logs longhorn-iscsi-installation-<instance> -c iscsi-installation
```


##### Install NFSv4 client:
Longhorn backup requires NFSv4 and ReadWriteMany (RWX) features.

- **Ensure kernel support for NFS v4.1/v4.2:**
  ```bash
  cat /boot/config-`uname -r`| grep CONFIG_NFS_V4_1
  cat /boot/config-`uname -r`| grep CONFIG_NFS_V4_2
  ```

- **Install NFSv4 Client:**
  **- option 1:** manually on each node:
  ```bash
  dnf install -y nfs-utils
  ```
  **- option 2:** through kubectl:
  ```bash
  kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/v1.8.1/deploy/prerequisite/longhorn-nfs-installation.yaml
  kubectl -n longhorn-system get pod | grep longhorn-nfs-installation
  kubectl -n longhorn-system logs longhorn-nfs-installation-vqcgh -c nfs-installation
  ```

##### Installing Cryptsetup and LUKS

[Cryptsetup](https://gitlab.com/cryptsetup/cryptsetup) is an open-source utility used to conveniently set up dm-crypt based device-mapper targets and Longhorn uses LUKS2 (Linux Unified Key Setup) format that is the standard for Linux disk encryption to support volume encryption.
```bash
dnf install cryptsetup
```

##### Installing Device Mapper Userspace Tool
The device mapper is a framework provided by the Linux kernel for mapping physical block devices onto higher-level virtual block devices. It forms the foundation of the dm-crypt disk encryption and provides the linear dm device on the top of v2 volume. The device mapper is typically included by default in many Linux distributions. Some lightweight or highly customized distributions or a minimal installation of a distribution might exclude it to save space or reduce complexity

```bash
dnf install device-mapper
```

##### Node and Disk Setup

###### Use a Dedicated Disk for Longhorn:

We will be using `sdb` as the dedicated disk for longhorn:
```bash
root@node-1:~# lsblk
NAME                 MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda                    8:0    0   30G  0 disk
├─sda1                 8:1    0  228M  0 part /boot/efi
├─sda2                 8:2    0  600M  0 part /boot
└─sda3                 8:3    0 28.8G  0 part
  ├─rootvg-lv_root   253:0    0  1.6G  0 lvm  /
  ├─rootvg-lv_swap   253:1    0    4G  0 lvm
  ├─rootvg-lv_usr    253:2    0    5G  0 lvm  /usr
  ├─rootvg-lv_tmp    253:3    0  1.7G  0 lvm  /tmp
  ├─rootvg-lv_vartmp 253:4    0  1.5G  0 lvm  /var/tmp
  ├─rootvg-lv_varlog 253:5    0    5G  0 lvm  /var/log
  ├─rootvg-lv_var    253:6    0    5G  0 lvm  /var
  ├─rootvg-lv_opt    253:7    0  1.7G  0 lvm  /opt
  ├─rootvg-lv_home   253:8    0  1.6G  0 lvm  /home
  └─rootvg-lv_srv    253:9    0  1.7G  0 lvm  /srv
sdb                    8:16   0  500G  0 disk
```

For information on how to mount and format disks, refer to the following [wiki](../troubleshooting/README.md)

###### Disk Setup:

The following [mount-disk](./mount-disk.sh) bash script mounts the given disk for Longhorn:
This need to be done on all nodes.
```bash
chmod +x mount-disk.sh

./mount-disk.sh
```
#### Enable iscsi_tcp module on all nodes:

```bash
# install iSCSI utility:
sudo dnf install iscsi-initiator-utils
# Ensure the module loads automatically on boot by adding it to /etc/modules
echo "iscsi_tcp" | sudo tee -a /etc/modules
# Load the Module: Use the modprobe command to load the iscsi_tcp module:
sudo modprobe iscsi_tcp
```
#### Enable dm_crypt
```bash
sudo modprobe dm_crypt
```

#### run environment check:
```bash
curl -sSfL https://raw.githubusercontent.com/longhorn/longhorn/v1.8.1/scripts/environment_check.sh | bash
```


#### Install [longhornctl](https://longhorn.io/docs/1.8.1/advanced-resources/longhornctl/):

1. install on all nodes:
```bash
# For AMD64 platform
cd /tmp
curl -sSfL -o longhornctl https://github.com/longhorn/cli/releases/download/v1.8.1/longhornctl-linux-amd64


sudo mv longhornctl /usr/local/bin/
sudo chmod +x /usr/local/bin/longhornctl
sudo ln -sf /usr/local/bin/longhornctl /usr/bin
```

2. Check the prerequisites and configurations for Longhorn:
```bash
# currently preflight doesnt support almalinux
# so if on almalinx; run os-camo o, alll nodes prior to check preflight
chmod +x os-camo.sh
./os-camo.sh camo

longhornctl check preflight
```

3. Install the preflight:
```bash
longhornctl install preflight
```

4. check the preflight again:
```bash
longhornctl check preflight

# revert back the camo:
./os-camo.sh revert
```





