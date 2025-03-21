#!/bin/bash


################################################################################################################################################################
# Initialize variables
CURRENT_HOSTNAME=$(eval hostname)
NODE_TYPE=""
DRY_RUN=false
PREREQUISITES=false
NODES_FILE=hosts_file.yaml
HOSTSFILE_PATH="/etc/hosts"

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
    # cleaning prior deployments:
    for i in $(seq "$NODE_OFFSET" "$((NODE_OFFSET + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        echo "Cleaning up k8s prior installs for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
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
        --values ./cilium/values.yaml # \
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



    for i in $(seq "2" "$((2 + NODES_COUNT - 1))"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}



        echo "sending cluster config to target node: ${CURRENT_NODE}"
        sudo cat /etc/kubernetes/admin.conf | ssh -q ${CURRENT_NODE} """
            sudo tee /etc/kubernetes/admin.conf > /dev/null
            sudo chmod 600 /etc/kubernetes/admin.conf
            mkdir -p $HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config
            sudo chown $(id -u):$(id -g) $HOME/.kube/config
        """

        # echo "sending PKI cert to target node: ${CURRENT_NODE}"
        # sudo cat /etc/kubernetes/pki/ca.crt | ssh -q ${CURRENT_NODE} "sudo tee /etc/kubernetes/pki/ca.crt > /dev/null && sudo chmod 644 /etc/kubernetes/pki/ca.crt"
        # echo "updating certs"
        # ssh -q ${CURRENT_NODE} "sudo update-ca-trust"

        echo "initiating cluster join for node: ${CURRENT_NODE}"
        ssh -q ${CURRENT_NODE} """
            echo "executing command: $JOIN_COMMAND_WORKERS"
            eval sudo ${JOIN_COMMAND_WORKERS}
        """
        echo "Finished joining cluster for node: ${CURRENT_NODE}"
    done
}



################################################################################################################################################################
deploy_hostsfile

if [ "$PREREQUISITES" = true ]; then
    echo "Executing cluster prerequisites installation and checks"
    # prerequisites_requirements
    install_cilium_prerequisites
else
    echo "Cluster prerequisites have been skipped"
fi


install_kubetools


install_cluster


install_cilium


join_cluster
