#!/bin/bash


################################################################################################################################################################
# Initialize variables
CURRENT_HOSTNAME=$(eval hostname)
NODE_TYPE=""
DRY_RUN=false
PREREQUISITES=false
NODES_FILE=hosts_file.yaml
HOSTSFILE_PATH="/etc/hosts"
################################################################################################################################################################

# Recommended kernel version
recommended_rehl_version="4.18"
################################################################################################################################################################
# reading .env file
. .env
# source .env
################################################################################################################################################################
# import library function
. library.sh
# source library.sh
################################################################################################################################################################
CONTROLPLANE_ADDRESS=$(eval ip -o -4 addr show $CONTROLPLANE_INGRESS_INTER | awk '{print $4}' | cut -d/ -f1)  # 192.168.66.129
CONTROLPLANE_SUBNET=$(echo $CONTROLPLANE_ADDRESS | awk -F. '{print $1"."$2"."$3".0/24"}')
################################################################################################################################################################


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
        -n|--nodes-file)
            NODES_FILE="$2"
            shift 2
            ;;
        -n|--set-hostname-to)
            SET_HOSTNAME_TO="$2"
            shift 2
            ;;
        --with-prerequisites)
            PREREQUISITES=true
            log "WARNING" "Will install cluster prerequisites, manual nodes reboot is required."
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            echo "Dry run mode: No changes will be made."
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --control-plane-hostname <str> --nodes-file <nodes_file> --set-hostname-to <str OPTIONAL> [--dry-run] "
            exit 1
            ;;
    esac
done

################################################################################################################################################################
# Validate that required arguments are provided
if [ -z "$CONTROLPLANE_HOSTNAME" ] || [ -z "$NODES_FILE" ]; then
    log "ERROR" "Missing required arguments."
    log "ERROR" "$0 --control-plane-hostname <str> --nodes-file <nodes_file> --set-hostname-to <str OPTIONAL> [--dry-run]"
    exit 1
fi


# Ensure the YAML file exists
if [ ! -f "$NODES_FILE" ]; then
    log "ERROR" "Error: Node YAML file '$NODES_FILE' not found."
    exit 1
fi

if [ ! -z "$SET_HOSTNAME_TO" ]; then
    # Set hostname
    sudo hostnamectl set-hostname "$SET_HOSTNAME_TO"
    log "INFO" "Hostname set to $SET_HOSTNAME_TO"

    CURRENT_HOSTNAME=$(eval hostname)
fi




################################################################################################################################################################
prerequisites_requirements() {
    #########################################################################################
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        #####################################################################################
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        #####################################################################################
        log "INFO" "starting gid and uid configuration for node: $CURRENT_NODE"
        log "INFO" "Check if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP"
        ssh -q ${CURRENT_NODE} """
            bash -c '''
                if echo '$SUDO_PASSWORD' | sudo -S grep -q \"^%$SUDO_GROUP[[:space:]]\\+ALL=(ALL)[[:space:]]\\+NOPASSWD:ALL\" /etc/sudoers.d/10_sudo_users_groups; then
                    echo \"Visudo entry for $SUDO_GROUP is appended correctly.\"
                else
                    echo \"Visudo entry for $SUDO_GROUP is not found.\"
                    echo '$SUDO_PASSWORD' | sudo -S bash -c \"\"\"echo %$SUDO_GROUP       ALL\=\\\(ALL\\\)       NOPASSWD\:ALL >> /etc/sudoers.d/10_sudo_users_groups \"\"\"
                fi
            '''
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while configuring visudo on node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finsihed checking if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP"
        #####################################################################################
        log "INFO" "Check if the groups exists with the specified GIDs for node: ${CURRENT_NODE}"
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
            log "ERROR" "Error occurred while configuring sudo group on node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished check if the groups exists with the specified GIDs for node: ${CURRENT_NODE}"
        #####################################################################################
        log "INFO" "Check if the user '${SUDO_USERNAME}' exists for node: ${CURRENT_NODE}"
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
            log "ERROR" "Error occurred while configuring user on node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished check if the user '${SUDO_USERNAME}' exists for node: ${CURRENT_NODE}"
        #####################################################################################
        if [ ! -z $SUDO_NEW_PASSWORD ]; then
            log "INFO" "setting password for user '${SUDO_USERNAME}' for node: ${CURRENT_NODE}"
            ssh  -q ${CURRENT_NODE} << EOF
echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $SUDO_USERNAME:$SUDO_NEW_PASSWORD | chpasswd"
EOF
            # Check if the SSH command failed
            if [ $? -ne 0 ]; then
                log "ERROR" "Error occurred while setting new sudo password for node ${CURRENT_NODE}. Exiting script."
                exit 1  # This will stop the script execution
            fi
            log "INFO" "Finished setting password for user '${SUDO_USERNAME}' for node: ${CURRENT_NODE}"
        fi
        #################################################################*
        log "INFO" "Configuring repos on target node: $CURRENT_NODE"
        configure_repos $CURRENT_NODE
        log "INFO" "Finished configuring repos on target node: $CURRENT_NODE"
        #####################################################################################
        log "INFO" "Check if the kernel is recent enough for node: ${CURRENT_NODE}"
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
            log "ERROR" "Error occurred while checking kernel version node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished installing kernet tools node: ${CURRENT_NODE}"
        #####################################################################################
        log "INFO" "Checking eBPF support for node: ${CURRENT_NODE}"
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


        ################################################################################################################################################################
        # Retrieve AlmaLinux version
        # Retrieve AlmaLinux version
        # ALMALINUX_VERSION=$(grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release)

        # # Retrieve Kernel version
        # KERNEL_VERSION=$(uname -r | sed 's/\.[^.]*$//')

        # # Construct the URL
        # base_url="https://repo.almalinux.org/vault"
        # url="${base_url}/${ALMALINUX_VERSION}/BaseOS/Source/Packages/kernel-${KERNEL_VERSION}.src.rpm"

        # # Check if the URL exists
        # if curl --output /dev/null --silent --head --fail "$url"; then
        #     # Download the kernel source RPM
        #     curl -O ${url}
        #     echo "Downloaded kernel source RPM from ${url}"


        #     # TODO, check on kernel compilation

        #     echo "Install mock if not already installed"
        #     sudo useradd mockbuild &> /dev/null
        #     sudo dnf install mock -y


        #     echo "Set the RPMBUILD environment variable to /tmp"
        #     export RPMBUILD_DIR=/mnt/longhorn-1/rpmbuild

        #     echo "Create the necessary directories"
        #     mkdir -p ${RPMBUILD_DIR}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}


        #     # echo "Move the downloaded tarball to the SOURCES directory"
        #     # mv linux-${KERNEL_VERSION}.tar.xz ${RPMBUILD_DIR}/SOURCES/


        #     echo "Install the kernel source RPM to: ${RPMBUILD_DIR}"
        #     # rpm -ivh kernel-${KERNEL_VERSION}.src.rpm
        #     rpm -ivh --define "_topdir ${RPMBUILD_DIR}" kernel-${KERNEL_VERSION}.src.rpm

        #     echo "Build the kernel using rpmbuild"
        #     sudo dnf builddep ${RPMBUILD_DIR}/SPECS/kernel.spec -y


        #     rpmbuild --define "_topdir ${RPMBUILD_DIR}" -ba ${RPMBUILD_DIR}/SPECS/kernel.spec





        #     # mock -r almalinux-9-x86_64 --rebuild ~/rpmbuild/SRPMS/kernel-*.src.rpm
        #     mock -r almalinux-9-x86_64 --rebuild  ${RPMBUILD_DIR}/SRPMS/kernel-*.src.rpm



        #     echo "Kernel rebuild process completed."


        # else
        #     echo "Error: The kernel source RPM for version ${KERNEL_VERSION} is not available at ${url}"
        # fi


        ################################################################################################################################################################

        ssh  -q ${CURRENT_NODE} """
            # Check if bpftool is installed
            if ! command -v bpftool &> /dev/null; then
                echo "bpftool not found. Installing..."
                sudo dnf install -y bpftool  >/dev/null 2>&1

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
            log "ERROR" "Error occurred while configuring eBPF for node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished checking eBPF support for node: ${CURRENT_NODE}"
        #####################################################################################
        # Ensure that bpf is mounted
        log "INFO" "Checking if bpf is mounted for node: ${CURRENT_NODE}"
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
        log "INFO" "Finished checking if bpf is mounted for node: ${CURRENT_NODE}"
        #####################################################################################
        #
        # # /etc/environment proxy:
        # # Call the function
        # TODO
        # update_path
        #################################################################
        log "INFO" "Disabling swap for node: ${CURRENT_NODE}"
        ssh  -q ${CURRENT_NODE} """
            sudo swapoff -a
            sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
        """
        # sudo sed -i '/ swap / s/^/#/' /etc/fstab
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while disabling swap node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished Disabling swap for node: ${CURRENT_NODE}"
        #################################################################
        log "INFO" "Disable SELinux temporarily and modify config for persistence"
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
            log "ERROR" "Error occurred while configuring SELinux node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished disabling SELinux temporarily and modify config for persistence"
        #################################################################*
        #TODO
        # update_firewall $CURRENT_NODE
        #############################################################################
        log "INFO" "Configuring bridge network for node: $CURRENT_NODE"
        ssh  -q ${CURRENT_NODE} '
            sudo echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/containerd.conf
            sudo modprobe overlay
            sudo modprobe br_netfilter

            sudo echo -e "net.bridge.bridge-nf-call-iptables = 1\nnet.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-ip6tables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
            sudo sysctl --system > /dev/null 2>&1
        '
        log "INFO" "Finished configuring bridge network for node: $CURRENT_NODE"
        #############################################################################
        # install containerD
        log "INFO" "Installing containerD on node: $CURRENT_NODE"
        ssh  -q ${CURRENT_NODE} '
            sudo dnf install -y yum-utils  >/dev/null 2>&1
            sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo  >/dev/null 2>&1
            sudo dnf install containerd.io -y  >/dev/null 2>&1
        '
        log "INFO" "Finished installing containerD on node: $CURRENT_NODE"
        #############################################################################
        log "INFO" "Enabling containerD NRI with systemD and cgroups: on node: $CURRENT_NODE"
        ssh -q ${CURRENT_NODE} '
            CONFIG_FILE=/etc/containerd/config.toml

            #  pause version mismatch:
            echo "Reseting containerD config to default."
            containerd config default | sudo tee $CONFIG_FILE >/dev/null 2>&1


            echo "Backup the original config file"
            cp -f -n $CONFIG_FILE ${CONFIG_FILE}.bak

            echo "Configuring containerD for our cluster"
            sudo sed -i "/\[plugins.\"io.containerd.nri.v1.nri\"\]/,/^\[/{
                s/disable = true/disable = false/;
                s/disable_connections = true/disable_connections = false/;
                s|plugin_config_path = \".*\"|plugin_config_path = \"/etc/nri/conf.d\"|;
                s|plugin_path = \".*\"|plugin_path = \"/opt/nri/plugins\"|;
                s|plugin_registration_timeout = \".*\"|plugin_registration_timeout = \"15s\"|;
                s|plugin_request_timeout = \".*\"|plugin_request_timeout = \"12s\"|;
                s|socket_path = \".*\"|socket_path = \"/var/run/nri/nri.sock\"|;
            }" "$CONFIG_FILE"

            sudo sed -i "s/SystemdCgroup = false/SystemdCgroup = true/g" "$CONFIG_FILE"
            sudo sed -i "s|sandbox_image = \"registry.k8s.io/pause:3.8\"|sandbox_image = \"registry.k8s.io/pause:3.10\"|" "$CONFIG_FILE"

            sudo sed -i "s|root = \"/var/lib/containerd\"|root = \"/mnt/longhorn-1/var/lib/containerd\"|" "$CONFIG_FILE"

            sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
            sudo chown -R root:root /etc/nri /opt/nri

            echo "Starting and enablingS containerD"
            sudo systemctl enable containerd
            sudo systemctl daemon-reload
            sudo systemctl restart containerd

            sleep 10
            # Check if the containerd service is active
            if systemctl is-active --quiet containerd.service; then
                echo "ContainerD configuration updated successfully."
            else
                echo "ContainerD configuration failed, containerd service is not running..."
                exit 1
            fi
        '
        log "INFO" "Finished enabling containerD NRI: on node: $CURRENT_NODE"
        #############################################################################
        log "INFO" "Installing GO on node: $CURRENT_NODE"
        install_go $CURRENT_NODE $GO_VERSION $TINYGO_VERSION
        log "INFO" "Finished installing GO on node: $CURRENT_NODE"
        #############################################################################
        log "INFO" "Installing Helm on node: $CURRENT_NODE"
        install_helm $CURRENT_NODE
        add_bashcompletion $CURRENT_NODE helm
        log "INFO" "Finished installing Helm on node: $CURRENT_NODE"
        #############################################################################
        log "INFO" "Configuring containerd for node: $CURRENT_NODE"
        configure_containerD $CURRENT_NODE $HTTP_PROXY $HTTPS_PROXY $NO_PROXY $PAUSE_VERSION $SUDO_GROUP
        log "INFO" "Finished configuration of containerd for node: $CURRENT_NODE"
    done
}


########################################################################
install_kubetools () {
    #########################################################
    # cilium must be reinstalled if kubelet is reinstalled
    sudo cilium uninstall >/dev/null 2>&1 || true
    #########################################################
    # Fetch Latest version from kube release....
    if [ "$(echo "$FETCH_LATEST_KUBE" | tr '[:upper:]' '[:lower:]')" = "true" ]; then
        log "INFO" "Fetching latest kuberentes version from stable-1..."
        # Fetch the latest stable full version (e.g., v1.32.2)
        K8S_MINOR_VERSION=$(curl -L -s https://dl.k8s.io/release/stable-1.txt)
        #########################################################
        # Extract only the major.minor version (e.g., 1.32)
        K8S_MAJOR_VERSION=$(echo $K8S_MINOR_VERSION | cut -d'.' -f1,2)
    fi
    # ensure that the vars are set either from latest version or .env
    if [ -z "$K8S_MAJOR_VERSION" ] || [ -z $K8S_MINOR_VERSION ]; then
        log "ERROR" "K8S_MAJOR_VERSION and/or K8S_MINOR_VERSION have not been set on .env file"
        exit 2
    fi
    #########################################################
    # Update Kubernetes repository to the latest minor version
    K8S_REPO_FILE="/etc/yum.repos.d/kubernetes.repo"
    K8S_REPO_CONTENT="""
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v$K8S_MAJOR_VERSION/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v$K8S_MAJOR_VERSION/rpm/repodata/repomd.xml.key
exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni
"""
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        #########################################################
        log "INFO" "sending k8s repo version: ${K8S_MAJOR_VERSION} to target node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} "echo '$K8S_REPO_CONTENT' | sudo tee $K8S_REPO_FILE" >/dev/null 2>&1
        #########################################################
        log "INFO" "updating repos on target node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} "sudo dnf update -y >/dev/null 2>&1"
        #########################################################
        log "INFO" "Removing prior installed versions on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes  >/dev/null 2>&1
        """
        #########################################################
        log "INFO" "installing k8s tools on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf install -y kubelet-${K8S_MINOR_VERSION} kubeadm-${K8S_MINOR_VERSION} kubectl-${K8S_MINOR_VERSION} --disableexcludes=kubernetes  >/dev/null 2>&1
            sudo systemctl enable --now kubelet  >/dev/null 2>&1
        """
        #########################################################
        log "INFO" "Adding Kubeadm bash completion"
        add_bashcompletion ${CURRENT_NODE} kubeadm
        add_bashcompletion ${CURRENT_NODE} kubectl
        #########################################################
    done
    #########################################################
    echo "Kubernetes prerequisites setup completed successfully."
    #########################################################
}


deploy_hostsfile () {
    ################################################################
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        log "INFO" "installing tools for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf update -y  >/dev/null 2>&1
            sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools  >/dev/null 2>&1
            sudo pip install yq  >/dev/null 2>&1
        """
        log "INFO" "Finished installing tools node: ${CURRENT_NODE}"
    done
    #########################################################
    # Convert YAML to JSON using yq
    if ! command_exists yq; then
        log "ERROR" "Error: 'yq' command not found. Please install yq to parse YAML files or run prerequisites..."
        exit 1
    fi
    # Parse YAML file and append node and worker-node details to /etc/hosts
    if ! command_exists jq; then
        log "ERROR" "'jq' command not found. Please install jq to parse JSON files or run prerequisites..."
        exit 1
    fi
    #########################################################
    # Path to the YAML file
    # Extract the 'nodes' array from the YAML and process it with jq
    yq '.nodes' "$NODES_FILE" | jq -r '.[] | "\(.ip) \(.hostname)"' | while read -r line; do
        # Append the entry to the file (e.g., /etc/hosts)
        # Normalize spaces in the input line (collapse multiple spaces/tabs into one)
        normalized_line=$(echo "$line" | sed 's/[[:space:]]\+/ /g')

        # Check if the normalized line already exists in the target file by parsing each line
        exists=false
        while IFS= read -r target_line; do
            # Normalize spaces in the target file line
            normalized_target_line=$(echo "$target_line" | sed 's/[[:space:]]\+/ /g')

            # Compare the normalized lines
            if [[ "$normalized_line" == "$normalized_target_line" ]]; then
                exists=true
                break
            fi
        done < "$HOSTSFILE_PATH"

        # Append the line to the target file if it doesn't exist
        if [ "$exists" = false ]; then
            echo "$line" | sudo tee -a "$HOSTSFILE_PATH" > /dev/null
            log "INFO" "Host added to hosts file: $line"
        else
            log "INFO" "Host already exists: $line"
        fi
    done
    #########################################################
    log "INFO" "Sending hosts file to nodes"
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        log "INFO" "sending hosts file to target node: ${CURRENT_NODE}"
        scp -q $HOSTSFILE_PATH ${CURRENT_NODE}:/tmp

        log "INFO" "Applying changes on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo cp /tmp/hosts ${HOSTSFILE_PATH}
        """
        log "INFO" "Finished modifying hosts fileon node: ${CURRENT_NODE}"
    done
    #############################################################################
}


install_cluster () {
    #########################################################
    log "WARNING" "cilium must be reinstalled as kubelet will be reinstalled"
    sudo cilium uninstall  >/dev/null 2>&1 || true
    #########################################################
    # cleaning prior deployments:
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        ################################################################################################################
        log "INFO" "Cleaning up k8s prior installs for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo kubeadm reset -f >/dev/null 2>&1 || true
            sudo rm -rf $HOME/.kube/* /root/.kube/* /etc/cni/net.d/*  /etc/kubernetes/pki/*
        """
    done
    ##################################################################
    log "INFO" "starting reseting host persistent volumes mounts"
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        log "INFO" "Reseting volumes on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo rm -rf "${EXTRAVOLUMES_ROOT}"/*

            sudo mkdir -p "${EXTRAVOLUMES_ROOT}"/cilium/hubble-relay
            sudo mkdir -p "${EXTRAVOLUMES_ROOT}"/cilium/hubble-relay
        """
    done
    log "INFO" "finished reseting host persistent volumes mounts"
    ####################################################################
    log "INFO" "generating kubeadm init config file"
    envsubst < init-config-template.yaml > init-config.yaml
    # Kubeadm init logic
    KUBE_ADM_COMMAND="sudo kubeadm "
    ####################################################################
    KUBE_ADM_COMMAND="$KUBE_ADM_COMMAND init --config init-config.yaml --skip-phases=addon/kube-proxy "

    # Simulate Kubeadm init or worker-node node join
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "Initializing dry-run for control plane node init..."
        KUBE_ADM_COMMAND="$KUBE_ADM_COMMAND --dry-run "
    else
        log "INFO" "Initializing control plane node init..."
    fi

    log "INFO" "    with command: $KUBE_ADM_COMMAND"
    # KUBEADM_INIT_OUTPUT=$(eval "$KUBE_ADM_COMMAND 2>&1")
    LOGS_DIR=./kubeadm_init_errors.log
    sudo touch ${LOGS_DIR}
    sudo chmod 666 ${LOGS_DIR}

    KUBEADM_INIT_OUTPUT=$(eval "$KUBE_ADM_COMMAND" 2> "${LOGS_DIR}")

    if [[ $? -ne 0 ]]; then
        log "ERROR" "Error: Failed to run kubeadm init."
        log "ERROR" "$KUBEADM_INIT_OUTPUT"
        exit 1
    fi


    if [ "$DRY_RUN" = true ]; then
        log "INFO" "Control plane dry-run initialized without errors."
        return 0
    else
        log "INFO" "Control plane initialized successfully."
        # Copy kubeconfig for kubectl access
        mkdir -p $HOME/.kube
        sudo cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config
        sudo chown $(id -u):$(id -g) $HOME/.kube/config

        log "INFO" "unintaing the control-plane node"
        kubectl taint nodes $NODE_1 node-role.kubernetes.io/control-plane:NoSchedule- >/dev/null 2>&1
        kubectl taint nodes $NODE_1 node.kubernetes.io/not-ready:NoSchedule- >/dev/null 2>&1
        log "INFO" "sleeping for 30s to wait for Kubernetes control-plane node setup completion..."
        sleep 30
    fi
    log "INFO" "Finished deploying control-plane node."
}


install_cilium () {
    #########################################################
    log "WARNING" "cilium must be reinstalled as kubelet will be reinstalled"
    sudo cilium uninstall >/dev/null 2>&1 || true
    ###############################################################################################################
    log "INFO" "Ensuring that kube-proxy is not installed"
    kubectl -n kube-system delete ds kube-proxy >/dev/null 2>&1 || true
    # Delete the configmap as well to avoid kube-proxy being reinstalled during a Kubeadm upgrade (works only for K8s 1.19 and newer)
    kubectl -n kube-system delete cm kube-proxy >/dev/null 2>&1 || true
    # Run on each node with root permissions:
    sudo iptables-save | grep -v KUBE | sudo iptables-restore  >/dev/null 2>&1
    ################################################################################################################
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        ################################################################################################################
        log "INFO" "setting public interface: ${PUBLIC_INGRESS_INTER} rp_filter to 1"
        log "INFO" "setting cluster interface: ${CONTROLPLANE_INGRESS_INTER} rp_filter to 2"
        ssh -q ${CURRENT_NODE} """
            sudo sysctl -w net.ipv4.conf.${PUBLIC_INGRESS_INTER}.rp_filter=1
            sudo sysctl -w net.ipv4.conf.$CONTROLPLANE_INGRESS_INTER.rp_filter=2
            sudo sysctl --system > /dev/null 2>&1
        """

        ################################################################################################################
        CILIUM_CLI_VERSION=$(curl --silent https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)

        log "INFO" "installing cilium cli version: $CILIUM_CLI_VERSION"
        ssh -q ${CURRENT_NODE} """
            cd /tmp

            CLI_ARCH=amd64
            if [ "\$\(uname -m\)" = "aarch64" ]; then CLI_ARCH=arm64; fi

            echo "CLI_ARCH for node: ${CURRENT_NODE} is: \${CLI_ARCH}"

            curl -s -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-\${CLI_ARCH}.tar.gz{,.sha256sum}

            sha256sum --check cilium-linux-\${CLI_ARCH}.tar.gz.sha256sum
            sudo tar xzvfC cilium-linux-\${CLI_ARCH}.tar.gz /usr/local/bin
            rm cilium-linux-*
        """
        add_bashcompletion ${CURRENT_NODE}  cilium
        log "INFO" "Finished installing cilium cli"
    done
    ################################################################################################################
    log "INFO" "Adding cilium chart"
    helm repo add cilium https://helm.cilium.io/ --force-update >/dev/null 2>&1
    helm repo update >/dev/null 2>&1
    ################################################################################################################
    ################################################################################################################
    # cleaning up cilium and maglev tables
    # EXPERIMENTAL ONLY AND STILL UNDER TESTING....
    # echo "Started cleanup completed!"
    # cilium_cleanup
    # echo "Cilium cleanup completed!"
    ################################################################################################################
    log "INFO" "Installing cilium version: '${CILIUM_VERSION}' using cilium cli"
    log "INFO" "Cilium native routing subnet is: ${CONTROLPLANE_SUBNET}"
    HASH_SEED=$(head -c12 /dev/urandom | base64 -w0)
    log "INFO" "Cilium maglev hashseed is: ${HASH_SEED}"

    cilium install --version $CILIUM_VERSION \
        --set ipv4NativeRoutingCIDR=${CONTROLPLANE_SUBNET} \
        --set k8sServiceHost=auto \
        --values ./cilium/values.yaml \
        --set maglev.hashSeed="${HASH_SEED}" 2>&1 || true
        # TODO add nodes count here....
        # --set k8sServiceHost=10.96.0.1 \
        # --set k8sServicePort=443 \
    ################################################################################################################
    # sleep 30
    # kubectl delete pods -A --all

    # kubectl -n kube-system delete pod etcd-$NODE_1
    # kubectl -n kube-system delete pod kube-apiserver-$NODE_1
    # kubectl -n kube-system delete pod kube-controller-manager-$NODE_1
    # kubectl -n kube-system delete pod kube-scheduler-$NODE_1
    # kubectl -n kube-system get deployments,statefulsets,daemonsets -o name | xargs -I {} kubectl -n kube-system rollout restart {}
    sleep 30
    ################################################################################################################
    # echo "Applying custom cilium ingress."
    # kubectl apply -f cilium/ingress.yaml
    log "INFO" "Removing default cilium ingress."
    kubectl delete svc -n kube-system cilium-ingress >/dev/null 2>&1 || true
    ################################################################################################################
    sleep 30
    ################################################################################################################
    log "INFO" "restarting cilium."
    kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator  >/dev/null 2>&1 || true
    sleep 45

    log "INFO" "waiting for cilium to go up (5minutes timeout)"
    cilium status --wait >/dev/null 2>&1 || true
    ################################################################################################################
    log "INFO" "Apply LB IPAM"
    kubectl apply -f cilium/loadbalancer-ip-pool.yaml
    ################################################################################################################
    log "INFO" "Finished installing cilium"
    ################################################################################################################
}


join_cluster () {
    # TODO: for control-plane nodes:
    log "INFO" "Generating join command"
    JOIN_COMMAND_WORKERS=$(kubeadm token create --print-join-command)
    JOIN_COMMAND_CP="${JOIN_COMMAND} --control-plane"

    # for i in $(seq "2" "$((2 + NODES_COUNT - 1))"); do
    for i in $(seq 2 "$((2 + NODES_COUNT - 2))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        log "INFO" "sending cluster config to target node: ${CURRENT_NODE}"
        sudo cat /etc/kubernetes/admin.conf | ssh -q ${CURRENT_NODE} """
            sudo tee -p /etc/kubernetes/admin.conf > /dev/null
            sudo chmod 600 /etc/kubernetes/admin.conf
            mkdir -p $HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config >/dev/null 2>&1
            sudo chown $(id -u):$(id -g) $HOME/.kube/config
        """

        # log "INFO" "sending PKI cert to target node: ${CURRENT_NODE}"
        # sudo cat /etc/kubernetes/pki/ca.crt | ssh -q ${CURRENT_NODE} "sudo tee /etc/kubernetes/pki/ca.crt > /dev/null && sudo chmod 644 /etc/kubernetes/pki/ca.crt"
        # log "INFO" "updating certs"
        # ssh -q ${CURRENT_NODE} "sudo update-ca-trust"

        log "INFO" "initiating cluster join for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo rm -rf /etc/kubernetes/kubelet.conf /etc/kubernetes/pki/*
            echo "executing command: $JOIN_COMMAND_WORKERS"
            eval sudo ${JOIN_COMMAND_WORKERS} >/dev/null 2>&1
        """
        log "INFO" "Finished joining cluster for node: ${CURRENT_NODE}"
    done
}



install_longhorn_prerequisites() {
    ##################################################################
    log "INFO" "installing required utilities for longhorn"
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        log "INFO" "installing longhorn prerequisites on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf update >/dev/null 2>&1
            sudo dnf install curl jq nfs-utils cryptsetup \
                device-mapper iscsi-initiator-utils -y >/dev/null 2>&1
        """
    done
    log "INFO" "Finished installing required utilities for longhorn"
    ##################################################################
    log "INFO" "Creating namespace: ${LONGHORN_NS} for longhorn"
    kubectl create ns $LONGHORN_NS >/dev/null 2>&1 || true
    #################################################################
    log "INFO" "install NFS/iSCSI on the cluster"
    # REF: https://github.com/longhorn/longhorn/tree/master/deploy/prerequisite
    #
    ERROR_RAISED=0
    for service in "nfs" "iscsi"; do
        log "INFO" "Started installation of ${service} on all nodes"
        kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml >/dev/null 2>&1 || true

        upper_service=$(echo ${service} | awk '{print toupper($0)}')
        TIMEOUT=180  # 3 minutes in seconds
        START_TIME=$(date +%s)
        while true; do
            # Wait for the pods to be in Running state
            log "INFO" "Waiting for Longhorn ${upper_service} installation pods to be in Running state..."
            sleep 30
            log "INFO" "Finished sleeping..."
            log "INFO" "Getting pods from namespace: '${LONGHORN_NS}'"
            PODS=$(kubectl -n $LONGHORN_NS get pod 2>/dev/null || true)
            log "INFO" "Finished getting pods from namespace: '${LONGHORN_NS}'"
            # Check if PODS is empty
            if [ -z "$PODS" ]; then
                log "WARNING" "No matching pods found for: 'longhorn-${service}-installation'"
                continue
            fi
            PODS=$(echo $PODS | grep longhorn-${service}-installation)
            RUNNING_COUNT=$(echo "$PODS" | grep -c "Running")
            TOTAL_COUNT=$(echo "$PODS" | wc -l)

            log "INFO" "Running Longhorn ${upper_service} install containers: ${RUNNING_COUNT}/${TOTAL_COUNT}"
            if [[ $RUNNING_COUNT -eq $TOTAL_COUNT ]]; then
                break
            fi

            CURRENT_TIME=$(date +%s)
            ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

            if [[ $ELAPSED_TIME -ge $TIMEOUT ]]; then
                log "ERROR" "Timeout reached. Exiting..."
                exit 1
            fi
        done

        current_retry=0
        max_retries=3
        while true; do
            current_retry=$((current_retry + 1))
            log "INFO" "Checking Longhorn ${upper_service} setup completion... try N: ${current_retry}"
            all_pods_up=1
            # Get the logs of the service installation container
            for POD_NAME in $(kubectl -n $LONGHORN_NS get pod | grep longhorn-${service}-installation | awk '{print $1}' || true); do
                LOGS=$(kubectl -n $LONGHORN_NS logs $POD_NAME -c ${service}-installation || true)
                if echo "$LOGS" | grep -q "${service} install successfully"; then
                    log "INFO" "Longhorn ${upper_service} installation successful in pod $POD_NAME"
                else
                    log "INFO" "Longhorn ${upper_service} installation failed or incomplete in pod $POD_NAME"
                    all_pods_up=0
                fi
            done

            if [ $all_pods_up -eq 1 ]; then
                break
            fi
            sleep 30
            if [ $current_retry -eq $max_retries ]; then
                log "ERROR" "Reached maximum retry count: ${max_retries}. Exiting..."
                ERROR_RAISED=1
                break
            fi
        done
        kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml  >/dev/null 2>&1 || true
    done

    if [ $ERROR_RAISED -eq 1 ]; then
        exit 1
    fi
    log "INFO" "Finished installing NFS/iSCSI on the cluster."
    ##################################################################
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        ##################################################################
        log "INFO" "Checking if the containerd service is active on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} '
            if systemctl is-active --quiet iscsid; then
                echo "iscsi deployed successfully."
            else
                echo "iscsi service is not running..."
                exit 1
            fi
        '
        log "INFO" "Finished checking if the containerd service is active on node: ${CURRENT_NODE}"
        ##################################################################
        log "INFO" "Ensure kernel support for NFS v4.1/v4.2: on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} '
            for ver in 1 2; do
                if $(cat /boot/config-`uname -r`| grep -q "CONFIG_NFS_V4_${ver}=y"); then
                    echo NFS v4.${ver} is supported
                else
                    echo ERROR: NFS v4.${ver} is not supported
                    exit $ver
                fi
            done
        '
        ##################################################################
        log "INFO" "enabling iscsi_tcp & dm_crypt on node: ${CURRENT_NODE}"
        # Check if the module is already in the file
        ssh -q ${CURRENT_NODE} '
            # Ensure the iscsi_tcp module loads automatically on boot
            MODULE_FILE="/etc/modules"
            MODULE_NAME="iscsi_tcp"

            if ! grep -q "^${MODULE_NAME}$" ${MODULE_FILE}; then
                echo "${MODULE_NAME}" | sudo tee -a ${MODULE_FILE}
                echo "Added ${MODULE_NAME} to ${MODULE_FILE}"
            else
                echo "${MODULE_NAME} is already present in ${MODULE_FILE}"
            fi

            # Load the iscsi_tcp module
            sudo modprobe iscsi_tcp
            echo "Loaded ${MODULE_NAME} module"

            # Enable dm_crypt
            sudo modprobe dm_crypt
            echo "Loaded dm_crypt module"
        '
        log "INFO" "Finished enabling iscsi_tcp & dm_crypt on node: ${CURRENT_NODE}"
        ##################################################################
        log "INFO" "Started installing Longhorn-cli on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            set -e  # Exit on error
            set -o pipefail  # Fail if any piped command fails
            if command -v longhornctl &> /dev/null; then
                echo "longhornctl not found. Installing..."
                CLI_ARCH=amd64
                if [ "\$\(uname -m\)" = "aarch64" ]; then CLI_ARCH=arm64; fi
                cd /tmp

                # curl -sSfL -o longhornctl https://github.com/longhorn/cli/releases/download/\${LONGHORN_VERSION}/longhornctl-linux-\${CLI_ARCH}

                url=https://github.com/longhorn/cli/releases/download/${LONGHORN_VERSION}/longhornctl-linux-\${CLI_ARCH}

                # Check if the URL exists
                if curl --output /dev/null --silent --head --fail \$url; then
                    echo Downloading longhornctl from source
                    curl -sSfL -o /tmp/longhornctl \${url}

                    echo Moving longhornctl to /usr/local/bin
                    sudo mv /tmp/longhornctl /usr/local/bin/

                    echo Making longhornctl executable
                    sudo chmod +x /usr/local/bin/longhornctl

                    echo Creating symbolic link to /usr/bin
                    sudo ln -sf /usr/local/bin/longhornctl /usr/bin
                    echo longhornctl installed successfully.
                else
                    echo failed to download longhornctl from url: \${url}
                    exit 1
                fi
            else
                echo "longhornctl is already installed."
            fi
        """
        log "INFO" "Finished installing Longhorn-cli on node: ${CURRENT_NODE}"

    done
    ##################################################################
    log "INFO" "Running the environment check script on the cluster..."
    url=https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/scripts/environment_check.sh

    if curl --output /dev/null --silent --head --fail $url; then
        curl -sSfL -o /tmp/environment_check.sh ${url}
        sudo chmod +x /tmp/environment_check.sh

        OUTPUT=$(/tmp/environment_check.sh)

        # Print the output
        log "INFO" "$OUTPUT"
        # Check for errors in the output
        if echo "$OUTPUT" | grep -q '\[ERROR\]'; then
            log "ERROR" "Errors found in the environment check:"
            echo "$OUTPUT" | grep '\[ERROR\]'
            exit
        else
            log "INFO" "No errors found in the environment check."
        fi
    else
        log "ERROR" "failed to download environment_check from url: ${url}"
        exit 1
    fi
    log "INFO" "Finished Running the environment check script on the cluster..."
    ##################################################################
    ##################################################################
    log "INFO" "Check the prerequisites and configurations for Longhorn:"
    log "INFO" "currently preflight doesnt support almalinux"
    #  so if on almalinx; run os-camo o, alll nodes prior to check preflight
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        log "INFO" "sending camo script to target node: ${CURRENT_NODE}"
        scp -q ./longhorn/os-camo.sh ${CURRENT_NODE}:/tmp/
        log "INFO" "Executing camofoulage on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo chmod +x /tmp/os-camo.sh
            /tmp/os-camo.sh camo
        """
    done
    ##################################################################
    OUTPUT=$(longhornctl check preflight 2>&1)
    log "INFO" "Started checking the longhorn preflight pre installation"
    kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer  >/dev/null 2>&1 || true
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        log "ERROR" "Errors found in the environment check:"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        log "INFO" "No errors found during the longhornctl preflight environment check."
    fi
    log "INFO" "Finished checking the preflight of longhorn"
    ##################################################################
    log "INFO" "Installing the preflight of longhorn"
    OUTPUT=$(longhornctl install preflight 2>&1)
    kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer  >/dev/null 2>&1 || true
    # Print the output
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        log "ERROR" "Errors found during the in longhornctl install preflight"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        log "INFO" "No errors found in the environment check."
    fi
    log "INFO" "Finished installing the preflight of longhorn"
    ##################################################################
    # check the preflight again after install:
    log "INFO" "Started checking the longhorn preflight post installation"
    OUTPUT=$(longhornctl check preflight 2>&1)
    kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer >/dev/null 2>&1 || true
    # Print the output
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        log "ERROR" "Errors found in the environment check:"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        log "INFO" "No errors found during the longhornctl preflight environment check."
    fi
    log "INFO" "Finished checking the longhorn preflight post installation"
    ##################################################################
    # revert camo:
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        log "INFO" "Resetting camofoulage on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} /tmp/os-camo.sh revert
    done
    #################################################################
    log "INFO" "Finished installing required utilities for longhorn"
}



install_longhorn () {
    ##################################################################
    log "INFO" "adding longhorn repo to Helm"
    helm repo add longhorn https://charts.longhorn.io --force-update > /dev/null 2>&1 || true
    helm repo update > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "uninstalling and ensuring the cluster is cleaned from longhorn"
    kubectl delete -n longhorn-system ds/longhorn-manager ds/longhorn-nfs-installation deployments/longhorn-ui deployments/longhorn-driver-deployer  jobs/longhorn-uninstall >/dev/null 2>&1 || true

    helm uninstall -n $LONGHORN_NS longhorn > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "deleting longhorn NS"
    kubectl delete ns $LONGHORN_NS --now=true & > /dev/null 2>&1 || true

    kubectl get namespace "${LONGHORN_NS}" -o json \
    | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
    | kubectl replace --raw /api/v1/namespaces/${LONGHORN_NS}/finalize -f - > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "Creating certmanager NS: '$LONGHORN_NS'"
    kubectl create ns $LONGHORN_NS > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "Started deploying longhorn in ns $LONGHORN_NS"
    output=$(helm install longhorn longhorn/longhorn  \
        --namespace $LONGHORN_NS  \
        --version ${LONGHORN_VERSION} -f ./longhorn/values.yaml 2>&1)

    # Check if the Helm install command was successful
    if [ ! $? -eq 0 ]; then
        log "ERROR" "Failed to install Longhorn:\n\t${output}"
        exit 1
    fi
    log "INFO" "Finished deploying longhorn in ns $LONGHORN_NS"
    ##################################################################
    # Wait for the pods to be running
    log "INFO" "Waiting for Longhorn pods to be running..."
    sleep 70  # approximate time for longhorn to boostrap
    current_retry=0
    max_retries=3
    while true; do
        current_retry=$((current_retry + 1))
        if [ $current_retry -gt $max_retries ]; then
            log "ERROR" "Reached maximum retry count. Exiting."
            exit 1
        fi
        log "INFO" "Checking Longhorn chart deployment completion... try N: $current_retry"
        PODS=$(kubectl -n $LONGHORN_NS get pods --no-headers | grep -v 'Running\|Completed' || true)
        if [ -z "$PODS" ]; then
            log "INFO" "All Longhorn pods are running."
            break
        else
            log "INFO" "Waiting for pods to be ready..."
        fi
        sleep 60
    done
    ##################################################################
    log "INFO" "Applying longhorn HTTPRoute for ingress."
    kubectl apply -f longhorn/http-routes.yaml
    ##################################################################
    log "INFO" "Finished deploying Longhorn on the cluster."
}

install_gateway_CRDS () {
    # this hits a bug described here: https://github.com/cilium/cilium/issues/38420
    # log "INFO" "Installing Gateway API version: ${GATEWAY_VERSION} from the standard channel"
    # kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_VERSION}/standard-install.yaml

    # using experimental CRDS channel
    log "INFO" "Installing Gateway API version: ${GATEWAY_VERSION} from the experimental channel"
    kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_VERSION}/experimental-install.yaml
    # kubectl rollout restart -n kube-system deployment cilium-operator

    # log "INFO" "restarting cilium."
    # kubectl rollout restart -n kube-system ds/cilium-envoy deployment/cilium-operator  >/dev/null 2>&1 || true
    # sleep 30
    log "INFO" "Installing Gateway API Experimental TLSRoute from the Experimental channel"
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/${GATEWAY_VERSION}/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml
    ################################################################################################################################################################
    log "INFO" "Applying hubble-ui HTTPRoute for ingress."
    kubectl apply -f cilium/http-routes.yaml
    ################################################################################################################################################################
}

################################################################################################################################################################
install_gateway () {
    # prerequisites checks:
    # REF: https://docs.cilium.io/en/v1.17/network/servicemesh/gateway-api/gateway-api/#installation
    log "INFO" "ensuring prerequisites are met for Gateway API"
    # Check the value of enable-l7-proxy
    config_check "cilium config view" "kube-proxy-replacement" "true"
    config_check "cilium config view" "enable-l7-proxy" "true"
    log "INFO" "Finished checking prerequisites for Gateway API"

    log "INFO" "Started deploying TLS cert for TLS-HTTPS Gateway API"
    mkdir -p cilium/certs/
    SECRET_NAME=shared-tls
    CERT_FILE="cilium/certs/${SECRET_NAME}.crt"
    KEY_FILE="cilium/certs/${SECRET_NAME}.key"

    log "INFO" "Generate self-signed certificate and key"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $KEY_FILE -out $CERT_FILE -subj "/CN=${CLUSTER_DNS_DOMAINS}"

    log "INFO" "Creating rancher Kubernetes TLS secret"
    kubectl create secret tls ${SECRET_NAME} --cert=$CERT_FILE --key=$KEY_FILE --namespace=kube-system
    log "INFO" "Finished deploying TLS cert for TLS-HTTPS Gateway API"

    log "INFO" "Started deploying Gateway API"
    kubectl apply -f cilium/http-gateway.yaml
    log "INFO" "Finished deploying Gateway API"

    log "INFO" "restarting cilium."
    kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator  >/dev/null 2>&1 || true
    sleep 45
}







install_vault () {
    ##################################################################
    helm repo add hashicorp https://helm.releases.hashicorp.com --force-update
    helm repo update



    helm install vault hashicorp/vault -n $VAULT_NS \
        --create-namespace --version $VAULT_VERSION \
        -f vault/values.yaml
    ##################################################################

}



install_rancher () {
    ##################################################################
    log "INFO" "adding rancher repo to helm"
    helm repo add rancher-${RANCHER_BRANCH} https://releases.rancher.com/server-charts/${RANCHER_BRANCH} > /dev/null 2>&1 || true
    helm repo update > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "uninstalling and ensuring the cluster is cleaned from rancher"
    helm uninstall -n $RANCHER_NS rancher > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "deleting rancher NS"
    kubectl delete ns $RANCHER_NS --now=true & > /dev/null 2>&1 || true

    kubectl get namespace "${RANCHER_NS}" -o json \
    | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
    | kubectl replace --raw /api/v1/namespaces/${RANCHER_NS}/finalize -f - > /dev/null 2>&1 || true
    ##################################################################
    log "INFO" "Creating rancher NS: '$RANCHER_NS'"
    kubectl create ns $RANCHER_NS > /dev/null 2>&1 || true
    ##################################################################
    log "WARNING" "Warning: Currently rancher supports kubeVersion up to 1.31.0"
    log "WARNING" "initiating workaround to force the install..."

    DEVEL=""
    if [ ${RANCHER_BRANCH} == "alpha" ]; then
        DEVEL="--devel"
    fi
    # helm install rancher rancher-${RANCHER_BRANCH}/rancher \
    # helm install rancher ./rancher/rancher-${RANCHER_VERSION}.tar.gz \


    log "INFO" "Started deploying rancher on the cluster"
    helm install rancher rancher-${RANCHER_BRANCH}/rancher ${DEVEL} \
        --namespace ${RANCHER_NS} \
        --set hostname=${RANCHER_FQDN} \
        --set bootstrapPassword=${RANCHER_ADMIN_PASS}  \
        --version ${RANCHER_VERSION}  \
        -f rancher/values.yaml > /dev/null 2>&1

    # kubectl -n $RANCHER_NS rollout status deploy/rancher
    log "INFO" "Finished deploying rancher on the cluster"

    admin_url="https://rancher.pfs.pack/dashboard/?setup=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}')"
    log "INFO" "Access the admin panel at: $admin_url"

    admin_password=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}{{ "\n" }}')
    log "INFO" "Admin bootstrap password is: ${admin_password}"
    ##################################################################
    log "INFO" "Applying rancher HTTPRoute for ingress."
    kubectl apply -f rancher/http-routes.yaml
}



install_certmanager () {
    ##################################################################
    # install cert-manager cli:
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        #####################################################################################
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        #####################################################################################
        log "INFO" "starting certmanager cli install for node: $CURRENT_NODE"
        ssh -q ${CURRENT_NODE} """
            set -e  # Exit on error
            set -o pipefail  # Fail if any piped command fails
            OS=\$(go env GOOS)
            ARCH=\$(go env GOARCH)
            curl -fsSL -o cmctl https://github.com/cert-manager/cmctl/releases/download/v${CERTMANAGER_CLI_VERSION}/cmctl_\${OS}_\${ARCH}
            chmod +x cmctl
            sudo mv cmctl /usr/bin
            sudo ln -sf /usr/bin /usr/local/bin
        """
        add_bashcompletion $CURRENT_NODE cmctl
        log "INFO" "Finished certmanager cli install for node: $CURRENT_NODE"
    done
    ##################################################################
    # deploy cert-manager:
    helm repo add jetstack https://charts.jetstack.io --force-update > /dev/null 2>&1 || true
    helm repo update > /dev/null 2>&1 || true

    log "INFO" "Started installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    helm install cert-manager jetstack/cert-manager  \
        --version ${CERTMANAGER_VERSION} \
        --namespace ${CERTMANAGER_NS} \
        --create-namespace \
        -f certmanager/values.yaml
    log "INFO" "Finished installing cert-manger on namespace: '${CERTMANAGER_NS}'"

    ##################################################################
    # test certmanager:
    # Needs to be automated....
    # kubectl apply -f certmanager/test-resources.yaml

    # # Check the status, grep through the event types
    # kubectl describe certificate -n cert-manager-test
    # kubectl get secrets -n cert-manager-test

    # # Clean up the test resources.
    # kubectl delete -f certmanager/test-resources.yaml


    # --cluster-resource-namespace=
}


free_space () {
    sudo journalctl --vacuum-time=2d
    sudo rm -rf /var/log/*.log
    sudo yum autoremove -y
}
################################################################################################################################################################
deploy_hostsfile

if [ "$PREREQUISITES" = true ]; then
    log "INFO" "Executing cluster prerequisites installation and checks"
    prerequisites_requirements
else
    log "INFO" "Cluster prerequisites have been skipped"
fi


install_kubetools

install_cluster

install_gateway_CRDS

install_cilium

install_gateway

join_cluster


install_certmanager


install_rancher

install_longhorn_prerequisites
install_longhorn

# install_vault


#  2>&1 || true
################################################################################################################################################################
# in dev:




# NAMESPACE=longhorn-system

# NAMESPACE=kube-system
# SERVICE=longhorn-frontend
# SERVICE_PORT=80


# kubectl --namespace ${NAMESPACE} run ${SERVICE}-tunnel -it --image=alpine/socat --tty --rm --expose=true --port=${SERVICE_PORT} tcp-listen:${SERVICE_PORT},fork,reuseaddr tcp-connect:${SERVICE}:${SERVICE_PORT}



# next steps:
# replace ingress class with gateway api
#https://docs.cilium.io/en/v1.17/network/servicemesh/gateway-api/gateway-api/#installation
# https://gateway-api.sigs.k8s.io/


# tls passthrough:
# When doing TLS Passthrough, backends will see Cilium Envoy’s IP address as the source of the forwarded TLS streams.
# https://docs.cilium.io/en/v1.17/network/servicemesh/gateway-api/gateway-api/#tls-passthrough-and-source-ip-visibility

