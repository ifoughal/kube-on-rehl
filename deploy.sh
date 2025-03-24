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
################################################################################################################################################################
# import library function
. library.sh
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
        --with-prerequisites)
            PREREQUISITES=true
            echo "Will install cluster prerequisites, manual nodes reboot is required."
            shift
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




################################################################################################################################################################
prerequisites_requirements() {
    #########################################################################################
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        #####################################################################################
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
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
        # sudo sed -i '/ swap / s/^/#/' /etc/fstab
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
        echo "Enabling containerD NRI with systemD and cgroups: on node: $CURRENT_NODE"
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
        echo "Finished enabling containerD NRI: on node: $CURRENT_NODE"
        #############################################################################
        echo "Installing GO on node: $CURRENT_NODE"
        install_go $CURRENT_NODE $GO_VERSION $TINYGO_VERSION
        echo "Finished installing GO on node: $CURRENT_NODE"
        #############################################################################
        echo "Installing Helm on node: $CURRENT_NODE"
        install_helm $CURRENT_NODE
        add_bashcompletion $CURRENT_NODE helm
        echo "Finished installing Helm on node: $CURRENT_NODE"
        #############################################################################
        echo "Configuring containerd for node: $CURRENT_NODE"
        configure_containerD $CURRENT_NODE $HTTP_PROXY $HTTPS_PROXY $NO_PROXY $PAUSE_VERSION $SUDO_GROUP
        echo "Finished configuration of containerd for node: $CURRENT_NODE"
    done
}


########################################################################
install_kubetools () {
    #########################################################
    # cilium must be reinstalled if kubelet is reinstalled
    sudo cilium uninstall --wait  >/dev/null 2>&1 || true
    #########################################################
    # Fetch Latest version from kube release....
    if [ "$(echo "$FETCH_LATEST_KUBE" | tr '[:upper:]' '[:lower:]')" = "true" ]; then
        echo "Fetching latest kuberentes version from stable-1..."
        # Fetch the latest stable full version (e.g., v1.32.2)
        K8S_MINOR_VERSION=$(curl -L -s https://dl.k8s.io/release/stable-1.txt)
        #########################################################
        # Extract only the major.minor version (e.g., 1.32)
        K8S_MAJOR_VERSION=$(echo $K8S_MINOR_VERSION | cut -d'.' -f1,2)
    fi
    # ensure that the vars are set either from latest version or .env
    if [ -z "$K8S_MAJOR_VERSION" ] || [ -z $K8S_MINOR_VERSION ]; then
        echo "K8S_MAJOR_VERSION and/or K8S_MINOR_VERSION have not been set on .env file"
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
        echo "sending k8s repo version: ${K8S_MAJOR_VERSION} to target node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} "echo '$K8S_REPO_CONTENT' | sudo tee $K8S_REPO_FILE" >/dev/null 2>&1

        echo "updating repos on target node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} "sudo dnf update -y >/dev/null 2>&1"

        #########################################################
        echo "Removing prior installed versions on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes >/dev/null 2>&1
        """
        #########################################################
        echo "installing k8s tools on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf install -y kubelet-${K8S_MINOR_VERSION} kubeadm-${K8S_MINOR_VERSION} kubectl-${K8S_MINOR_VERSION} --disableexcludes=kubernetes >/dev/null 2>&1
            sudo systemctl enable --now kubelet

        """
        #########################################################
        echo "Adding Kubeadm bash completion"
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
        echo "installing tools for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf update -y
            sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools
            sudo pip install yq
        """
        echo "Finished installing tools node: ${CURRENT_NODE}"
    done
    #########################################################
    # Convert YAML to JSON using yq
    if ! command_exists yq; then
        echo "Error: 'yq' command not found. Please install yq to parse YAML files or run prerequisites..."
        exit 1
    fi
    # Parse YAML file and append node and worker-node details to /etc/hosts
    if ! command_exists jq; then
        echo "Error: 'jq' command not found. Please install jq to parse JSON files or run prerequisites..."
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
            echo "Host added: $line"
        else
            echo "Already exists: $line"
            echo "Host already exists: $line"
        fi
    done
    #########################################################
    echo "Sending hosts file to nodes"
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        echo "sending hosts file to target node: ${CURRENT_NODE}"
        scp -q $HOSTSFILE_PATH ${CURRENT_NODE}:/tmp

        echo "Applying changes on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo cp /tmp/hosts ${HOSTSFILE_PATH}
        """
        echo "Finished modifying hosts fileon node: ${CURRENT_NODE}"
    done
    #############################################################################
}





install_cluster () {
    #########################################################
    # cilium must be reinstalled if kubelet is reinstalled
    sudo cilium uninstall --wait  >/dev/null 2>&1 || true
    #########################################################
    # cleaning prior deployments:
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        ################################################################################################################
        echo "Cleaning up k8s prior installs for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo cilium uninstall --wait
            sudo kubeadm reset -f
            sudo rm -rf $HOME/.kube/* /root/.kube/* /etc/cni/net.d/*  /etc/kubernetes/pki/*
        """
    done
    # Kubeadm init logic
    KUBE_ADM_COMMAND="sudo kubeadm "

    ####################################################################
    KUBE_ADM_COMMAND="$KUBE_ADM_COMMAND init --control-plane-endpoint=${CURRENT_HOSTNAME} --skip-phases=addon/kube-proxy "

    # Simulate Kubeadm init or worker-node node join
    if [ "$DRY_RUN" = true ]; then
        echo "Initializing dry-run for control plane node init..."
        KUBE_ADM_COMMAND="$KUBE_ADM_COMMAND --dry-run "
    else
        echo "Initializing control plane node init..."
    fi

    echo "    with command: $KUBE_ADM_COMMAND"
    # KUBEADM_INIT_OUTPUT=$(eval "$KUBE_ADM_COMMAND 2>&1")
    LOGS_DIR=/var/log/kubeadm_init_errors.log
    sudo touch ${LOGS_DIR}
    sudo chmod 666 ${LOGS_DIR}

    KUBEADM_INIT_OUTPUT=$(eval "$KUBE_ADM_COMMAND" 2> "${LOGS_DIR}")

    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to run kubeadm init."
        echo "$KUBEADM_INIT_OUTPUT"
        exit 1
    fi


    if [ "$DRY_RUN" = true ]; then
        echo "Control plane dry-run initialized without errors."
    else
        echo "Control plane initialized successfully."
        # Copy kubeconfig for kubectl access
        mkdir -p $HOME/.kube
        sudo cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config
        sudo chown $(id -u):$(id -g) $HOME/.kube/config
    fi

    echo "unintaing the control-plane node"
    kubectl taint nodes $NODE_1 node-role.kubernetes.io/control-plane:NoSchedule-
    kubectl taint nodes $NODE_1 node.kubernetes.io/not-ready:NoSchedule-
    echo "sleeping for 30s to wait for Kubernetes control-plane node setup completion..."
    sleep 30
}





install_cilium () {
    ################################################################################################################
    # if kube-proxy has been installed:
    echo "Ensuring that kube-proxy is not installed"
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
        echo "setting public interface: ${PUBLIC_INGRESS_INTER} rp_filter to 1"
        echo "setting cluster interface: ${CONTROLPLANE_INGRESS_INTER} rp_filter to 2"
        ssh -q ${CURRENT_NODE} """
            sudo sysctl -w net.ipv4.conf.${PUBLIC_INGRESS_INTER}.rp_filter=1
            sudo sysctl -w net.ipv4.conf.$CONTROLPLANE_INGRESS_INTER.rp_filter=2
            sudo sysctl --system > /dev/null 2>&1
        """

        ################################################################################################################
        CILIUM_CLI_VERSION=$(curl --silent https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)

        echo "installing cilium cli version: $CILIUM_CLI_VERSION"

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
        echo "Finished installing cilium cli"
    done
    ################################################################################################################
    echo "Adding cilium chart"
    helm repo add cilium https://helm.cilium.io/ --force-update
    helm repo update
    ################################################################################################################
    ################################################################################################################
    # cleaning up cilium and maglev tables
    # EXPERIMENTAL ONLY AND STILL UNDER TESTING....
    # echo "Started cleanup completed!"
    # cilium_cleanup
    # echo "Cilium cleanup completed!"
    ################################################################################################################
    echo "Installing cilium version: '${CILIUM_VERSION}' using cilium cli "
    echo "Cilium native routing subnet is: ${CONTROLPLANE_SUBNET}"
    cilium install --version $CILIUM_VERSION \
        --set ipv4NativeRoutingCIDR=${CONTROLPLANE_SUBNET} \
        --set k8sServiceHost=auto \
        --values ./cilium/values.yaml \
        --set maglev.hashSeed=$(head -c12 /dev/urandom | base64 -w0)
        # TODO add nodes count here....
        # --set k8sServiceHost=10.96.0.1 \
        # --set k8sServicePort=443 \

    # sleep 30
    # kubectl delete pods -A --all

    # kubectl -n kube-system delete pod etcd-$NODE_1
    # kubectl -n kube-system delete pod kube-apiserver-$NODE_1
    # kubectl -n kube-system delete pod kube-controller-manager-$NODE_1
    # kubectl -n kube-system delete pod kube-scheduler-$NODE_1
    # kubectl -n kube-system get deployments,statefulsets,daemonsets -o name | xargs -I {} kubectl -n kube-system rollout restart {}
    sleep 30
    ################################################################################################################
    echo "Applying custom cilium ingress."
    kubectl apply -f cilium/ingress.yaml
    echo "Removing default cilium ingress."
    kubectl delete svc -n kube-system cilium-ingress
    ################################################################################################################
    sleep 30
    ################################################################################################################
    kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator
    sleep 50
    kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator
    echo "waiting for cilium to go up"
    cilium status --wait >/dev/null 2>&1
    ################################################################################################################
    echo "Finished installing cilium"
}




join_cluster () {
    # TODO: for control-plane nodes:
    echo "Generating join command"
    JOIN_COMMAND_WORKERS=$(kubeadm token create --print-join-command)
    JOIN_COMMAND_CP="${JOIN_COMMAND} --control-plane"



    # for i in $(seq "2" "$((2 + NODES_COUNT - 1))"); do
    for i in $(seq 2 "$((2 + NODES_COUNT - 2))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}



        echo "sending cluster config to target node: ${CURRENT_NODE}"
        sudo cat /etc/kubernetes/admin.conf | ssh -q ${CURRENT_NODE} """
            sudo tee -p /etc/kubernetes/admin.conf > /dev/null
            sudo chmod 600 /etc/kubernetes/admin.conf
            mkdir -p $HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config >/dev/null 2>&1
            sudo chown $(id -u):$(id -g) $HOME/.kube/config
        """

        # echo "sending PKI cert to target node: ${CURRENT_NODE}"
        # sudo cat /etc/kubernetes/pki/ca.crt | ssh -q ${CURRENT_NODE} "sudo tee /etc/kubernetes/pki/ca.crt > /dev/null && sudo chmod 644 /etc/kubernetes/pki/ca.crt"
        # echo "updating certs"
        # ssh -q ${CURRENT_NODE} "sudo update-ca-trust"

        echo "initiating cluster join for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo rm -rf /etc/kubernetes/kubelet.conf /etc/kubernetes/pki/*
            echo "executing command: $JOIN_COMMAND_WORKERS"
            eval sudo ${JOIN_COMMAND_WORKERS}
        """
        echo "Finished joining cluster for node: ${CURRENT_NODE}"
    done
}



install_longhorn_prerequisites() {
    ##################################################################
    echo "installing required utilities for longhorn"
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        echo "installing longhorn prerequisites on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo dnf update >/dev/null 2>&1
            sudo dnf install curl jq nfs-utils cryptsetup \
                device-mapper iscsi-initiator-utils -y >/dev/null 2>&1
        """
    done
    echo "Finished installing required utilities for longhorn"
    ##################################################################
    echo "Creating namespace: ${LONGHORN_NS} for longhorn"
    kubectl create ns $LONGHORN_NS >/dev/null 2>&1 || true
    #################################################################
    echo "install NFS/iSCSI on the cluster"
    # REF: https://github.com/longhorn/longhorn/tree/master/deploy/prerequisite
    #
    ERROR_RAISED=0
    for service in "nfs" "iscsi"; do
        echo "Started installation of ${service} on all nodes"
        kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml

        upper_service=$(echo ${service} | awk '{print toupper($0)}')
        TIMEOUT=180  # 3 minutes in seconds
        START_TIME=$(date +%s)
        while true; do
            # Wait for the pods to be in Running state
            echo "Waiting for Longhorn ${upper_service} installation pods to be in Running state..."
            sleep 10

            PODS=$(kubectl -n $LONGHORN_NS get pod | grep longhorn-${service}-installation)
            RUNNING_COUNT=$(echo "$PODS" | grep -c "Running")
            TOTAL_COUNT=$(echo "$PODS" | wc -l)

            echo "Running Longhorn ${upper_service} install containers: ${RUNNING_COUNT}/${TOTAL_COUNT}"
            if [[ $RUNNING_COUNT -eq $TOTAL_COUNT ]]; then
                break
            fi

            CURRENT_TIME=$(date +%s)
            ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

            if [[ $ELAPSED_TIME -ge $TIMEOUT ]]; then
                echo "Timeout reached. Exiting script."
                exit 1
            fi
        done


        current_retry=0
        max_retries=3
        while true; do
            current_retry=$((current_retry + 1))
            echo "Checking Longhorn ${upper_service} setup completion... try N: ${current_retry}"
            all_pods_up=1
            # Get the logs of the service installation container
            for POD_NAME in $(kubectl -n $LONGHORN_NS get pod | grep longhorn-${service}-installation | awk '{print $1}'); do
                LOGS=$(kubectl -n $LONGHORN_NS logs $POD_NAME -c ${service}-installation)
                if echo "$LOGS" | grep -q "${service} install successfully"; then
                    echo "Longhorn ${upper_service} installation successful in pod $POD_NAME"
                else
                    echo "Longhorn ${upper_service} installation failed or incomplete in pod $POD_NAME"
                    all_pods_up=0
                fi
            done

            if [ $all_pods_up -eq 1 ]; then
                break
            fi
            sleep 30
            if [ $current_retry -eq $max_retries ]; then
                echo "Reached maximum retry count: ${max_retries}. Exiting."
                ERROR_RAISED=1
                break
            fi
        done
        kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml
    done

    if [ $ERROR_RAISED -eq 1 ]; then
        exit 1
    fi
    echo "Finished installing NFS/iSCSI on the cluster."
    ##################################################################
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        ##################################################################
        echo "Checking if the containerd service is active on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} '
            if systemctl is-active --quiet iscsid; then
                echo "iscsi deployed successfully."
            else
                echo "iscsi service is not running..."
                exit 1
            fi
        '
        echo "Finished checking if the containerd service is active on node: ${CURRENT_NODE}"
        ##################################################################
        echo "Ensure kernel support for NFS v4.1/v4.2: on node: ${CURRENT_NODE}"
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

        echo "enabling iscsi_tcp & dm_crypt on node: ${CURRENT_NODE}"
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
        echo "Finished enabling iscsi_tcp & dm_crypt on node: ${CURRENT_NODE}"
        ##################################################################
        echo "Started installing Longhorn-cli on node: ${CURRENT_NODE}"
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
        echo "Finished installing Longhorn-cli on node: ${CURRENT_NODE}"

    done
    ##################################################################
    echo "Running the environment check script on the cluster..."
    url=https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/scripts/environment_check.sh

    if curl --output /dev/null --silent --head --fail $url; then
        curl -sSfL -o /tmp/environment_check.sh ${url}
        sudo chmod +x /tmp/environment_check.sh

        OUTPUT=$(/tmp/environment_check.sh)

        # Print the output
        echo "$OUTPUT"
        # Check for errors in the output
        if echo "$OUTPUT" | grep -q '\[ERROR\]'; then
            echo "Errors found in the environment check:"
            echo "$OUTPUT" | grep '\[ERROR\]'
            exit
        else
            echo "No errors found in the environment check."
        fi
    else
        echo failed to download environment_check from url: ${url}
        exit 1
    fi
    echo "Finished Running the environment check script on the cluster..."
    ##################################################################
    ##################################################################
    echo "Check the prerequisites and configurations for Longhorn:"
    echo "currently preflight doesnt support almalinux"
    #  so if on almalinx; run os-camo o, alll nodes prior to check preflight
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        echo "sending camo script to target node: ${CURRENT_NODE}"
        scp -q ./longhorn/os-camo.sh ${CURRENT_NODE}:/tmp/
        echo "Executing camofoulage on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            sudo chmod +x /tmp/os-camo.sh
            /tmp/os-camo.sh camo
        """
    done
    ##################################################################
    OUTPUT=$(longhornctl check preflight 2>&1)
    echo "Started checking the longhorn preflight pre installation"
    kubectl delete -n default daemonsets.apps longhorn-preflight-checker >/dev/null 2>&1 || true
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        echo "Errors found in the environment check:"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        echo "No errors found during the longhornctl preflight environment check."
    fi
    echo "Finished checking the preflight of longhorn"
    ##################################################################
    echo "Installing the preflight of longhorn"
    OUTPUT=$(longhornctl install preflight 2>&1)
    kubectl delete -n default daemonsets.apps longhorn-preflight-checker >/dev/null 2>&1 || true
    # Print the output
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        echo "Errors found during the in longhornctl install preflight"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        echo "No errors found in the environment check."
    fi
    echo "Finished installing the preflight of longhorn"
    ##################################################################
    # check the preflight again after install:
    echo "Started checking the longhorn preflight post installation"
    OUTPUT=$(longhornctl check preflight 2>&1)
    kubectl delete -n default daemonsets.apps longhorn-preflight-checker >/dev/null 2>&1 || true
    # Print the output
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        echo "Errors found in the environment check:"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        echo "No errors found during the longhornctl preflight environment check."
    fi
    echo "Finished checking the longhorn preflight post installation"
    ##################################################################
    # revert camo:
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        echo "Resetting camofoulage on node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} /tmp/os-camo.sh revert
    done
    #################################################################
}



install_longhorn () {
    ##################################################################
    echo "adding longhorn repo to Helm"
    helm repo add longhorn https://charts.longhorn.io --force-update
    helm repo update
    ##################################################################
    # TODO on all nodes:
    # for i in 1 2 3; do
    #     NODE_VAR="NODE_$i"
    #     CURRENT_NODE=${!NODE_VAR}
    #     echo "Resetting volumes on node: ${CURRENT_NODE}"
    #     ssh -q ${CURRENT_NODE} "sudo rm -rf /mnt/longhorn-1/*"
    # done
    ##################################################################
    echo "Started deploying longhorn in ns $LONGHORN_NS"
    output=$(helm install longhorn longhorn/longhorn  \
        --namespace $LONGHORN_NS  \
        --version ${LONGHORN_VERSION} -f ./longhorn/values.yaml 2>&1)

    # Check if the Helm install command was successful
    if [ ! $? -eq 0 ]; then
        echo -e "Failed to install Longhorn:\n\t${output}"
        exit 1
    fi
    echo "Finished deploying longhorn in ns $LONGHORN_NS"
    ##################################################################
    # Wait for the pods to be running
    echo "Waiting for Longhorn pods to be running..."
    sleep 70  # approximate time for longhorn to boostrap
    current_retry=0
    max_retries=3
    while true; do
        current_retry=$((current_retry + 1))
        if [ $current_retry -gt $max_retries ]; then
            echo "Reached maximum retry count. Exiting."
            exit 1
        fi
        echo "Checking Longhorn chart deployment completion... try N: $current_retry"
        PODS=$(kubectl -n $LONGHORN_NS get pods --no-headers | grep -v 'Running\|Completed')
        if [ -z "$PODS" ]; then
            echo "All Longhorn pods are running."
            break
        else
            echo "Waiting for pods to be ready..."
        fi
        sleep 60
    done
    ##################################################################
}

################################################################################################################################################################
# deploy_hostsfile

# # if [ "$PREREQUISITES" = true ]; then
# #     echo "Executing cluster prerequisites installation and checks"
# #     # prerequisites_requirements
# #     install_cilium_prerequisites
# # else
# #     echo "Cluster prerequisites have been skipped"
# # fi


# install_kubetools


# install_cluster


# install_cilium

join_cluster
################################################################################################################################################################
# in dev:

install_longhorn_prerequisites

install_longhorn

