#!/bin/bash


################################################################################################################################################################
# Initialize variables
CURRENT_HOSTNAME=$(eval hostname)
NODES_FILE=""
NODE_TYPE=""
DRY_RUN=false


# Recommended kernel version
recommended_rehl_version="4.18"
################################################################################################################################################################
# reading .env file
. .env
################################################################################################################################################################
# import library function
. library.sh
################################################################################################################################################################
CONTROLPLANE_ADDRESS=$(eval ip -o -4 addr show $CONTROLPLANE_INGRESS_INTER | awk '{print $4}' | cut -d/ -f1)  # 192.168.66.129
CONTROLPLANE_SUBNET=$(echo $CONTROLPLANE_ADDRESS | awk -F. '{print $1"."$2"."$3".0/24"}')
################################################################################################################################################################


CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi

set -e  # Exit on error
set -o pipefail  # Fail if any piped command fails

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

################################################################################################################################################################
# Parse command-line arguments manually (including --dry-run)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--control-plane-hostname)
            CONTROLPLANE_HOSTNAME="$2"
            shift 2
            ;;
        -p|--control-plane-port)
            CONTROLPLANE_PORT="$2"
            shift 2
            ;;
        -n|--nodes-file)
            NODES_FILE="$2"
            shift 2
            ;;
        -n|--set-hostname-to)
            SET_HOSTNAME_TO="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            echo "Dry run mode: No changes will be made."
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --control-plane-hostname <str> --control-plane-port <str> --nodes-file <nodes_file> --set-hostname-to <str OPTIONAL> [--dry-run] "
            exit 1
            ;;
    esac
done

################################################################################################################################################################
# Validate that required arguments are provided
if [ -z "$CONTROLPLANE_HOSTNAME" ] || [ -z "$CONTROLPLANE_PORT" ] || [ -z "$NODES_FILE" ]; then
    echo "Error: Missing required arguments."
    echo "Usage: $0 --control-plane-hostname <str> --control-plane-port <str> --nodes-file <nodes_file> --set-hostname-to <str OPTIONAL> [--dry-run]"
    exit 1
fi


# Ensure the YAML file exists
if [ ! -f "$NODES_FILE" ]; then
    echo "Error: Node YAML file '$NODES_FILE' not found."
    exit 1
fi

if [ ! -z "$SET_HOSTNAME_TO" ]; then
    # Set hostname
    sudo hostnamectl set-hostname "$SET_HOSTNAME_TO"
    echo "Hostname set to $SET_HOSTNAME_TO"

    CURRENT_HOSTNAME=$(eval hostname)
fi



configure_repos () {

    CURRENT_HOST=$1
    ssh -q $CURRENT_HOST """
    set -e  # Exit on error

    echo 'Configuring AlmaLinux 9 Repositories...'

    # Define repo files
    sudo tee /etc/yum.repos.d/almalinux.repo > /dev/null <<EOF
[baseos]
name=AlmaLinux 9 - BaseOS
mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/baseos
enabled=1
gpgcheck=1
gpgkey=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux

[appstream]
name=AlmaLinux 9 - AppStream
mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/appstream
enabled=1
gpgcheck=1
gpgkey=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux

[crb]
name=AlmaLinux 9 - CRB
mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/crb
enabled=1
gpgcheck=1
gpgkey=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux

[extras]
name=AlmaLinux 9 - Extras
mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/extras
enabled=1
gpgcheck=1
gpgkey=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux
EOF

    echo 'Fetching and importing AlmaLinux GPG keys...'
    sudo curl -o /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
    sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux

    echo 'Enabling EPEL & CRB repositories...'
    sudo dnf install -y epel-release epel-next-release
    sudo dnf config-manager --set-enabled crb

    echo 'Adding RPM Fusion Free & Non-Free Repositories...'
    sudo dnf install -y https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm
    # sudo dnf install -y https://mirrors.rpmfusion.org/nonfree/el/rpmfusion-nonfree-release-9.noarch.rpm

    echo 'Cleaning up DNF cache and updating system...'
    sudo dnf clean all
    sudo dnf makecache
    sudo dnf -y update
    # echo 'Repositories configured successfully!'
"""
}


################################################################################################################################################################
prerequisites_requirements_checks() {
    #########################################################################################
    echo Check if the groups exist with the specified GIDs
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        #####################################################################################
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        #############################################################################
        echo "Installing GO on node: $CURRENT_NODE"
        install_go $CURRENT_NODE $GO_VERSION $TINYGO_VERSION
        echo "Finished installing GO on node: $CURRENT_NODE"
        echo end of test
        exit 1
        #####################################################################################
        echo starting gid and uid configuration for node: $CURRENT_NODE
        echo Check if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP
        ssh -q ${CURRENT_NODE} """
            bash -c '''
                if echo '$SUDO_PASSWORD' | sudo -S grep -q \"^%$SUDO_GROUP[[:space:]]\\+ALL=(ALL)[[:space:]]\\+NOPASSWD:ALL\" /etc/sudoers.d/10_sudo_users_groups; then
                    echo "Visudo entry for $SUDO_GROUP is appended correctly."
                else
                    echo \"Visudo entry for $SUDO_GROUP is not found.\"
                    echo '$SUDO_PASSWORD' | sudo -S bash -c \"\"\"echo %$SUDO_GROUP       ALL\=\\\(ALL\\\)       NOPASSWD\:ALL >> /etc/sudoers.d/10_sudo_users_groups \"\"\"
                fi
            '''
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring visudo on node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo Finsihed checking if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP
        #####################################################################################
        echo "Check if the groups exists with the specified GIDs for node: ${CURRENT_NODE}"
        ssh  -q ${CURRENT_NODE} """
            if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
                echo "'${SUDO_GROUP}' Group exists."
            else
                echo "'${SUDO_GROUP}' Group does not exist, creating..."
                echo "$SUDO_PASSWORD" | sudo -S groupadd ${SUDO_GROUP}
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring sudo group on node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished check if the groups exists with the specified GIDs for node: ${CURRENT_NODE}"
        #####################################################################################
        echo "Check if the user '${SUDO_USERNAME}' exists for node: ${CURRENT_NODE}"
        ssh  -q ${CURRENT_NODE} """
            if id "$SUDO_USERNAME" &>/dev/null; then
                echo "User $SUDO_USERNAME exists."
                id "$SUDO_USERNAME"
                echo "$SUDO_PASSWORD" | sudo -S  bash -c \"\"\"usermod -aG wheel,$SUDO_GROUP -s /bin/bash -m -d /home/$SUDO_USERNAME "$SUDO_USERNAME" \"\"\"
            else
                echo "User $SUDO_USERNAME does not exist."
                echo "$SUDO_PASSWORD" | sudo -S bash -c \"\"\"useradd -m -s /bin/bash -G wheel,$SUDO_GROUP "$SUDO_USERNAME" \"\"\"
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring user on node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished check if the user '${SUDO_USERNAME}' exists for node: ${CURRENT_NODE}"
        #####################################################################################
        if [ ! -z $SUDO_NEW_PASSWORD ]; then
            echo "setting password for user '${SUDO_USERNAME}' for node: ${CURRENT_NODE}"
            ssh  -q ${CURRENT_NODE} << EOF
echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $SUDO_USERNAME:$SUDO_NEW_PASSWORD | chpasswd"
EOF
            # Check if the SSH command failed
            if [ $? -ne 0 ]; then
                echo "Error occurred while setting new sudo password for node ${CURRENT_NODE}. Exiting script."
                exit 1  # This will stop the script execution
            fi
            echo "Finished setting password for user '${SUDO_USERNAME}' for node: ${CURRENT_NODE}"
        fi
        #################################################################*
        echo "Configuring repos on target node: $CURRENT_NODE"
        configure_repos $CURRENT_NODE
        echo "Finished configuring repos on target node: $CURRENT_NODE"
        #####################################################################################
        echo "Check if the kernel is recent enough for node: ${CURRENT_NODE}"
        ssh  -q ${CURRENT_NODE} """
            # Check if the kernel is recent enough
            kernel_version=\$(uname -r)
            echo "Kernel version: \$kernel_version"
            #####################################################################################
            # TODO
            # # Compare kernel versions
            # if [[ "$(printf '%s\n' "$recommended_rehl_version" "\$kernel_version" | sort -V | head -n1)" == "\$recommended_rehl_version" ]]; then
            #     echo "Kernel version is sufficient."
            # else
            #     echo "Kernel version is below the recommended version \($recommended_rehl_version\)."
            #     exit 1
            # fi
            #####################################################################################
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while checking kernel version node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished installing kernet tools node: ${CURRENT_NODE}"
        #####################################################################################
        echo "Checking eBPF support for node: ${CURRENT_NODE}"


        # cd /usr/src/kernels/$(uname -r)
        # make menuconfig
        # Navigate to:
        #     Networking support  --->
        #         Networking options  --->
        #             [*] BPF-based packet filter (BPFILTER)
        # sudo dnf groupinstall "Development Tools" -y
        # sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r) clang llvm gcc gcc-c++ binutils binutils-devel libcap-devel dwarves elfutils-libelf-devel ncurses-devel bison flex openssl-devel bc

        # sudo dnf install gcc make binutils-devel elfutils-libelf-devel libmpc-devel mpfr-devel


        # sudo rm -rf /usr/src/kernels/$(uname -r)
        # sudo dnf -y reinstall kernel-devel-$(uname -r) kernel-source


        # sudo sed -i 's|^obj-y[[:space:]]*+=[[:space:]]*scsi/|# &|' /usr/src/kernels/$(uname -r)/drivers/Makefile
        # sudo sed -i 's|^obj-$(CONFIG_INFINIBAND)[[:space:]]*+=[[:space:]]*infiniband/|# &|' /usr/src/kernels/$(uname -r)/drivers/Makefile
        # sudo sed -i 's|^obj-y[[:space:]]*+=[[:space:]]*host1x/ drm/ vga/|# &|' /usr/src/kernels/$(uname -r)/drivers/gpu/Makefile
        # sudo sed -i 's|^obj-y[[:space:]]*+=[[:space:]]*host1x/ drm/ vga/|# &|' /usr/src/kernels/$(uname -r)/drivers/infiniband/ulp/srp/Makefile



        # cd /usr/src/kernels/$(uname -r)
        # sudo make clean
        # sudo make mrproper
        # sudo make -j$(nproc)
        # make -j$(nproc) KCFLAGS=-D__NO_FORTIFY modules
        # make oldconfig

        # make KCFLAGS="-U_FORTIFY_SOURCE" modules

        # make KCFLAGS="-U_FORTIFY_SOURCE -O2" modules

        # make KCFLAGS="-Wno-error" modules


        # cd /usr/src/kernels/$(uname -r)/tools/objtool
        # sudo make clean
        # sudo make V=1




        ssh  -q ${CURRENT_NODE} """
            # Check if bpftool is installed
            if ! command -v bpftool &> /dev/null; then
                echo "bpftool not found. Installing..."
                sudo dnf install -y bpftool

                # Verify installation
                if ! command -v bpftool &> /dev/null; then
                    echo "Error: Failed to install bpftool."
                    exit 1
                fi
            fi

            # # Run bpftool feature check
            # echo "Running bpftool feature check..."
            # # sudo bpftool feature
            # # echo "eBPF is not enabled. Enabling eBPF..."
            # sudo modprobe bpf
            # sudo modprobe bpfilter
            # # Re-check eBPF features
            # features=\$\(sudo bpftool feature\)
            # if check_ebpf_enabled; then
            #     echo "eBPF has been successfully enabled."
            # else
            #     echo "Failed to enable eBPF."
            # fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring eBPF for node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished checking eBPF support for node: ${CURRENT_NODE}"
        #####################################################################################
        # Ensure that bpf is mounted
        echo "Checking if bpf is mounted for node: ${CURRENT_NODE}"
        ssh  -q ${CURRENT_NODE} '
            mount_output=$(mount | grep /sys/fs/bpf)
            echo mount_output: \$mount_output
            if [[ -n "$mount_output" ]]; then
                echo "bpf is mounted: $mount_output"
            else
                echo "Error ebpf is not mounted. You may need to mount it manually."
                exit 1
            fi
        '
        echo "Finished checking if bpf is mounted for node: ${CURRENT_NODE}"
        #####################################################################################
        #
        # # /etc/environment proxy:
        # # Call the function
        # TODO
        # update_path
        #################################################################
        echo "Disabling swap for node: ${CURRENT_NODE}"
        ssh  -q ${CURRENT_NODE} """
            sudo swapoff -a
            sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while disabling swap node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished Disabling swap for node: ${CURRENT_NODE}"
        #################################################################
        echo "Disable SELinux temporarily and modify config for persistence"
        ssh  -q ${CURRENT_NODE} '
            if sudo setenforce 0 2>/dev/null; then
                echo "SELinux set to permissive mode temporarily."
            else
                echo "Warning: Failed to set SELinux to permissive mode. It may already be disabled."
            fi

            if sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config; then
                echo "SELinux configuration updated."
            else
                echo "Error: Failed to update SELinux configuration."
                exit 1
            fi

            if $(sestatus |grep -q "Current mode:                   permissive"); then
                echo SELinux set to permissive.
            else
                echo ERROR, failed to set SELinux set to permissive.
                exit 1
            fi
        '
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring SELinux node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished disabling SELinux temporarily and modify config for persistence"
        #################################################################*
        #TODO
        # update_firewall $CURRENT_NODE
        #############################################################################
        echo "Configuring bridge network for node: $CURRENT_NODE"
        ssh  -q ${CURRENT_NODE} '
            sudo echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/containerd.conf
            sudo modprobe overlay
            sudo modprobe br_netfilter

            sudo echo -e "net.bridge.bridge-nf-call-iptables = 1\nnet.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-ip6tables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
            sudo sysctl --system > /dev/null 2>&1
        '
        echo "Finished configuring bridge network for node: $CURRENT_NODE"
        #############################################################################
        # install containerD
        echo "Installing containerD on node: $CURRENT_NODE"
        ssh  -q ${CURRENT_NODE} '
            sudo dnf install -y yum-utils
            sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo dnf install containerd.io -y
        '
        echo "Finished installing containerD on node: $CURRENT_NODE"
        #############################################################################
        echo "Enabling containerD NRI: on node: $CURRENT_NODE"
        ssh -q ${CURRENT_NODE} '
            CONFIG_FILE=/etc/containerd/config.toml

            # Backup the original config file
            cp -f -n $CONFIG_FILE ${CONFIG_FILE}.bak

            # Use sed to edit the config file
            sudo sed -i "/\[plugins.\"io.containerd.nri.v1.nri\"\]/,/^\[/{
                s/disable = true/disable = false/;
                s/disable_connections = true/disable_connections = false/;
                s|plugin_config_path = \".*\"|plugin_config_path = \"/etc/nri/conf.d\"|;
                s|plugin_path = \".*\"|plugin_path = \"/opt/nri/plugins\"|;
                s|plugin_registration_timeout = \".*\"|plugin_registration_timeout = \"15s\"|;
                s|plugin_request_timeout = \".*\"|plugin_request_timeout = \"12s\"|;
                s|socket_path = \".*\"|socket_path = \"/var/run/nri/nri.sock\"|;
            }" "$CONFIG_FILE"

            sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
            sudo chown -R root:root /etc/nri /opt/nri
        '
        echo "Finished enabling containerD NRI: on node: $CURRENT_NODE"
        #############################################################################
        echo "Installing GO on node: $CURRENT_NODE"
        install_go $CURRENT_NODE $GO_VERSION $TINYGO_VERSION
        echo "Finished installing GO on node: $CURRENT_NODE"
        #############################################################################
        # echo "Installing Helm on node: $CURRENT_NODE"
        # install_helm $CURRENT_NODE
        # echo "Finished installing Helm on node: $CURRENT_NODE"
        # #############################################################################
        # # configuration for containerd
        # configure_containerD
        # containerd containerd.io 1.7.25 bcc810d6
        ################################################################
    done
}

################################################################################################################################################################






















################################################################################################################################################################
prerequisites_requirements_checks




