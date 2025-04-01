#!/bin/bash

LONGHORN_LOGS="./logs/longhorn.log"
VAULT_LOGS=./logs/vault.log
CILIUM_LOGS=./logs/cilium.log
KUBEADMINIT_LOGS=./logs/kubeadm_init_errors.log

mkdir -p ./logs

sudo touch ${LONGHORN_LOGS}
sudo chmod 666 ${LONGHORN_LOGS}

sudo touch ${CILIUM_LOGS}
sudo chmod 666 ${CILIUM_LOGS}


sudo touch ${VAULT_LOGS}
sudo chmod 666 ${VAULT_LOGS}

sudo touch ${KUBEADMINIT_LOGS}
sudo chmod 666 ${KUBEADMINIT_LOGS}
################################################################################################################################################################
# Initialize variables
NODE_TYPE=""
DRY_RUN=false
PREREQUISITES=false
INVENTORY=inventory.yaml
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
VERBOSE=false
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
        # -c|--control-plane-hostname)
        #     CONTROLPLANE_HOSTNAME="$2"
        #     shift 2
        #     ;;
        -i|--inventory)
            INVENTORY="$2"
            shift 2
            ;;
        --with-prerequisites)
            PREREQUISITES=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            echo "Dry run mode: No changes will be made."
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --inventory <str OPTIONAL>  [--dry-run] "
            exit 1
            ;;
    esac
done

################################################################################################################################################################
# Validate that required arguments are provided
if [ -z "$INVENTORY" ]; then
    log "ERROR" "Missing required arguments."
    log "ERROR" "$0 --nodes-file <INVENTORY>  [--dry-run]"
    exit 1
fi


# Ensure the YAML file exists
if [ ! -f "$INVENTORY" ]; then
    log "ERROR" "Error: Node YAML file '$INVENTORY' not found."
    exit 1
fi

# if [ -z "$NODE_OFFSET" ] ; then
#     log "ERROR" "NODE_OFFSET was not found/set in env file"
#     exit 1
# fi

# if [ -z "$NODES_LAST" ]; then
#     log "ERROR" "NODES_LAST was not found/set in env file"
#     exit 1
# fi



if [ "$VERBOSE" = true ]; then
    VERBOSE_1=""
    VERBOSE_2=""
else
    VERBOSE=false
    VERBOSE_1=" 1> /dev/null "
    VERBOSE_2=">/dev/null 2>&1"
fi

log "INFO" "VERBOSE set to: $VERBOSE"


CLUSTER_NODES=$(yq .hosts "$INVENTORY")


deploy_hostsfile () {
    #########################################################
    # Path to the YAML file
    # Extract the 'nodes' array from the YAML and process it with jq
    # yq '.nodes["control_plane_nodes"]' "$INVENTORY" | jq -r '.[] | "\(.ip) \(.hostname)"' | while read -r line; do
    log "INFO" "installing required packages to deploy the cluster"
    eval "sudo dnf update -y  ${VERBOSE_1}"
    eval "sudo dnf upgrade -y  ${VERBOSE_1}"
    eval "sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools ${VERBOSE_1}"
    eval "sudo pip install yq  ${VERBOSE_2}"
    log "INFO" "Finished installing required packages to deploy the cluster"
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
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        #########################################################
        hostname=$(echo "$node" | jq -r '.hostname')
        ip=$(echo "$node" | jq -r '.ip')
        role=$(echo "$node" | jq -r '.role')
        #########################################################
        # Append the entry to the file (e.g., /etc/hosts)
        # Normalize spaces in the input line (collapse multiple spaces/tabs into one)
        line="$ip         $hostname"
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
        ################################################################
        log "INFO" "Setting hostname for '$role node': ${hostname}"
        ssh -q ${hostname} <<< """
            sudo hostnamectl set-hostname "$hostname"
            CURRENT_HOSTNAME=$(eval hostname)
            log "INFO" "Hostname set to \$CURRENT_HOSTNAME" ${VERBOSE_1}
        """
        log "INFO" "Finished setting hostname for '$role node': ${hostname}"
        ################################################################
        log "INFO" "installing tools for '$role node': ${hostname}"

        ssh -q ${hostname} <<< """
            sudo dnf update -y  ${VERBOSE_1}
            sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools ${VERBOSE_1}
            sudo pip install yq  ${VERBOSE_2}
        """
        log "INFO" "Finished installing tools node: ${hostname}"
        #########################################################
        log "INFO" "sending hosts file to target node: ${hostname}"
        scp -q $HOSTSFILE_PATH ${hostname}:/tmp

        log "INFO" "Applying changes on node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo cp /tmp/hosts ${HOSTSFILE_PATH}
        """
        log "INFO" "Finished modifying hosts file on node: ${hostname}"
        #########################################################
    done
}


reset_cluster () {
    log "INFO" "Started restting cluster"
    # #########################################################
    # log "INFO" "uninstalling Cilium from cluster..."
    # eval "sudo cilium uninstall ${VERBOSE_2}" || true
    # sleep 15
    # log "INFO" "Finished uninstalling Cilium from cluster..."
    #########################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        #########################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        #########################################################
        log "INFO" "Cleaning up k8s prior installs for node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo kubeadm reset -f ${VERBOSE_2} || true
            sudo rm -rf \
                \$HOME/.kube/* \
                /root/.kube/* \
                /etc/cni/net.d/* \
                /etc/kubernetes/* \
        """
        log "INFO" "Finished Cleaning up k8s prior installs for node: ${hostname}"
        #########################################################
        log "INFO" "Reseting volumes on node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo rm -rf "${EXTRAVOLUMES_ROOT}"/*

            sudo mkdir -p "${EXTRAVOLUMES_ROOT}"/cilium/hubble-relay
            sudo mkdir -p "${EXTRAVOLUMES_ROOT}"/cilium/hubble-relay
        """
        log "INFO" "finished reseting host persistent volumes mounts on node: ${hostname}"
    done
    #########################################################
    log "INFO" "Finished restting cluster"
}


prerequisites_requirements() {
    #############################################################################
    log "INFO" "Started cluster prerequisites installation and checks"
    #########################################################################################
    log "WARNING" "Will install cluster prerequisites, manual nodes reboot is required."
    #########################################################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        #########################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        #####################################################################################
        log "INFO" "Starting optimising dnf for node: $hostname"
        optimize_dnf $hostname
        log "INFO" "Finished optimising dnf for node: $hostname"
        #####################################################################################
        log "INFO" "starting gid and uid configuration for node: $hostname"
        log "INFO" "Check if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP"
        ssh -q ${hostname} <<< """
            bash -c '''
                if echo '$SUDO_PASSWORD' | sudo -S grep -q \"^%$SUDO_GROUP[[:space:]]\\+ALL=(ALL)[[:space:]]\\+NOPASSWD:ALL\" /etc/sudoers.d/10_sudo_users_groups; then
                    echo \"Visudo entry for $SUDO_GROUP is appended correctly.\" ${VERBOSE_1}
                else
                    echo \"Visudo entry for $SUDO_GROUP is not found.\" ${VERBOSE_1}
                    echo '$SUDO_PASSWORD' | sudo -S bash -c \"\"\"echo %$SUDO_GROUP       ALL\=\\\(ALL\\\)       NOPASSWD\:ALL >> /etc/sudoers.d/10_sudo_users_groups \"\"\"
                fi
            '''
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while configuring visudo on node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finsihed checking if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP"
        #####################################################################################
        log "INFO" "Check if the groups exists with the specified GIDs for node: ${hostname}"
        ssh  -q ${hostname} """
            if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
                echo "'${SUDO_GROUP}' Group exists." ${VERBOSE_1}
            else
                echo "'${SUDO_GROUP}' Group does not exist, creating..."
                echo "$SUDO_PASSWORD" | sudo -S groupadd ${SUDO_GROUP} ${VERBOSE_1}
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while configuring sudo group on node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished checking the sudoer groups with the specified GIDs for node: ${hostname}"
        #####################################################################################
        log "INFO" "Check if the user '${SUDO_USERNAME}' exists for node: ${hostname}"
        ssh -q ${hostname} <<< """
            if id "$SUDO_USERNAME" &>/dev/null; then
                echo "User $SUDO_USERNAME exists." ${VERBOSE_1}
                echo "$SUDO_PASSWORD" | sudo -S  bash -c \"\"\"usermod -aG wheel,$SUDO_GROUP -s /bin/bash -m -d /home/$SUDO_USERNAME "$SUDO_USERNAME" \"\"\"
            else
                echo "User $SUDO_USERNAME does not exist." ${VERBOSE_1}
                echo "$SUDO_PASSWORD" | sudo -S bash -c \"\"\"useradd -m -s /bin/bash -G wheel,$SUDO_GROUP "$SUDO_USERNAME" \"\"\"
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while configuring user on node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished check if the user '${SUDO_USERNAME}' exists for node: ${hostname}"

        echo end of test
        exit 1
        #####################################################################################
        if [ ! -z $SUDO_NEW_PASSWORD ]; then
            log "INFO" "setting password for user '${SUDO_USERNAME}' for node: ${hostname}"
            ssh  -q ${hostname} << EOF
echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $SUDO_USERNAME:$SUDO_NEW_PASSWORD | chpasswd"
EOF
            # Check if the SSH command failed
            if [ $? -ne 0 ]; then
                log "ERROR" "Error occurred while setting new sudo password for node ${hostname}. Exiting script."
                exit 1  # This will stop the script execution
            fi
            log "INFO" "Finished setting password for user '${SUDO_USERNAME}' for node: ${hostname}"
        fi
        #####################################################################################
        log "INFO" "Configuring repos on target node: $hostname"
        configure_repos $hostname
        log "INFO" "Finished configuring repos on target node: $hostname"
        #####################################################################################
        log "INFO" "Check if the kernel is recent enough for node: ${hostname}"
        ssh  -q ${hostname} """
            # Check if the kernel is recent enough
            kernel_version=\$(uname -r)
            echo "Kernel version: \$kernel_version" ${VERBOSE_1}
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
            log "ERROR" "Error occurred while checking kernel version node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished installing kernet tools node: ${hostname}"
        ################################################################################################################################################################
        log "INFO" "Checking eBPF support for node: ${hostname}"
        ssh  -q ${hostname} """
            # Check if bpftool is installed
            if ! command -v bpftool &> /dev/null; then
                echo "bpftool not found. Installing..." ${VERBOSE_1}
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
            log "ERROR" "Error occurred while configuring eBPF for node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished checking eBPF support for node: ${hostname}"
        #####################################################################################
        # Ensure that bpf is mounted
        log "INFO" "Checking if bpf is mounted for node: ${hostname}"
        ssh  -q ${hostname} """
            mount_output=\$(mount | grep /sys/fs/bpf)
            echo mount_output: \$mount_output ${VERBOSE_1}
            if [[ -n "\$mount_output" ]]; then
                echo "bpf is mounted: \$mount_output" ${VERBOSE_1}
            else
                echo "Error ebpf is not mounted. You may need to mount it manually."
                exit 1
            fi
        """
        log "INFO" "Finished checking if bpf is mounted for node: ${hostname}"
        #####################################################################################
        #
        # # /etc/environment proxy:
        # # Call the function
        # TODO
        # update_path
        #################################################################
        log "INFO" "Disabling swap for node: ${hostname}"
        ssh  -q ${hostname} """
            sudo swapoff -a
            sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
        """
        # sudo sed -i '/ swap / s/^/#/' /etc/fstab
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while disabling swap node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished Disabling swap for node: ${hostname}"
        #################################################################
        log "INFO" "Disable SELinux temporarily and modify config for persistence"
        ssh  -q ${hostname} """
            if sudo setenforce 0 2>/dev/null; then
                echo "SELinux set to permissive mode temporarily." ${VERBOSE_1}
            else
                echo "ERROR: Failed to set SELinux to permissive mode. It may already be disabled."
                exit 1
            fi

            if sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config; then
                echo "SELinux configuration updated."  ${VERBOSE_1}
            else
                echo "Error: Failed to update SELinux configuration."
                exit 1
            fi

            if sestatus | sed -n '/Current mode:[[:space:]]*permissive/!q'; then
                echo "SELinux is permissive" ${VERBOSE_1}
            else
                echo "ERROR: SELinux is not permissive"
                exit 1
            fi
        """

        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            log "ERROR" "Error occurred while configuring SELinux node ${hostname}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        log "INFO" "Finished disabling SELinux temporarily and modify config for persistence"
        #################################################################*
        #TODO
        # update_firewall $hostname
        #############################################################################
        log "INFO" "Configuring bridge network for node: $hostname"
        ssh  -q ${hostname} """
            sudo echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/containerd.conf > /dev/null
            sudo modprobe overlay
            sudo modprobe br_netfilter


            params=(
                "net.bridge.bridge-nf-call-iptables=1"
                "net.ipv4.ip_forward=1"
                "net.bridge.bridge-nf-call-ip6tables=1"
            )

            # File to update
            file="/etc/sysctl.d/k8s.conf"

            # Loop through each parameter
            for param in "\${params[@]}"; do
                key=\$(echo "\$param" | cut -d= -f1)
                value=\$(echo "\$param" | cut -d= -f2)

                # Use sed to ensure the parameter is in the file with the correct value
                sudo sed -i "/^\$key=/d" "\$file"
                echo "\$param" | sudo tee -a "\$file" > /dev/null
            done
            sudo sysctl --system ${VERBOSE_1}
        """
        log "INFO" "Finished configuring bridge network for node: $hostname"
        ############################################################################
        log "INFO" "Installing containerD on node: $hostname"
        ssh  -q ${hostname} '
            sudo dnf install -y yum-utils  >/dev/null 2>&1
            sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo  >/dev/null 2>&1
            sudo dnf install containerd.io -y  >/dev/null 2>&1
        '
        log "INFO" "Finished installing containerD on node: $hostname"
        # #############################################################################
        # log "INFO" "Enabling containerD NRI with systemD and cgroups on node: $hostname"
        # ssh -q ${hostname} <<< """
        #     CONFIG_FILE=/etc/containerd/config.toml

        #     # Pause version mismatch:
        #     echo "Resetting containerD config to default." ${VERBOSE_1}
        #     containerd config default | sudo tee \$CONFIG_FILE >/dev/null

        #     echo "Backing up the original config file" ${VERBOSE_1}
        #     cp -f -n \$CONFIG_FILE \${CONFIG_FILE}.bak

        #     echo "Configuring containerD for our cluster" ${VERBOSE_1}
        #     sudo sed -i '/\[plugins\\.\"io\\.containerd\\.nri\\.v1\\.nri\"\]/,/^\[/{
        #         s/disable = true/disable = false/;
        #         s/disable_connections = true/disable_connections = false/;
        #         s|plugin_config_path = ".*"|plugin_config_path = \"/etc/nri/conf.d\"|;
        #         s|plugin_path = ".*"|plugin_path = \"/opt/nri/plugins\"|;
        #         s|plugin_registration_timeout = ".*"|plugin_registration_timeout = \"15s\"|;
        #         s|plugin_request_timeout = ".*"|plugin_request_timeout = \"12s\"|;
        #         s|socket_path = ".*"|socket_path = \"/var/run/nri/nri.sock\"|;
        #     }' "\$CONFIG_FILE"


        #     sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' "\$CONFIG_FILE"
        #     sudo sed -i 's|sandbox_image = \"registry.k8s.io/pause:3.8\"|sandbox_image = \"registry.k8s.io/pause:3.10\"|' "\$CONFIG_FILE"

        #     # sudo sed -i 's|root = \"/var/lib/containerd\"|root = \"/mnt/longhorn-1/var/lib/containerd\"|' "$CONFIG_FILE"

        #     sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
        #     sudo chown -R root:root /etc/nri /opt/nri

        #     echo "Starting and enabling containerD" ${VERBOSE_1}
        #     sudo systemctl enable containerd
        #     sudo systemctl daemon-reload
        #     sudo systemctl restart containerd

        #     sleep 10
        #     # Check if the containerd service is active
        #     if systemctl is-active --quiet containerd.service; then
        #         echo "ContainerD configuration updated successfully." ${VERBOSE_1}
        #     else
        #         echo "ERROR: ContainerD configuration failed, containerd service is not running..."
        #         exit 1
        #     fi
        # """
        # log "INFO" "Finished enabling containerD NRI: on node: $hostname"
        # #############################################################################
        # log "INFO" "Installing GO on node: $hostname"
        # install_go $hostname $GO_VERSION $TINYGO_VERSION
        # log "INFO" "Finished installing GO on node: $hostname"
        # #############################################################################
        # log "INFO" "Installing Helm on node: $hostname"
        # install_helm $hostname
        # add_bashcompletion $hostname helm
        # log "INFO" "Finished installing Helm on node: $hostname"
        # #############################################################################
        # log "INFO" "Configuring containerd for node: $hostname"
        # configure_containerD $hostname $HTTP_PROXY $HTTPS_PROXY $NO_PROXY $PAUSE_VERSION $SUDO_GROUP
        # log "INFO" "Finished configuration of containerd for node: $hostname"
        # #############################################################################
    done
    #############################################################################
    log "INFO" "Finished cluster prerequisites installation and checks"
}


########################################################################
install_kubetools () {
    #########################################################
    # cilium must be reinstalled if kubelet is reinstalled
    eval "sudo cilium uninstall ${VERBOSE_2}" || true
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
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}
        #########################################################
        log "INFO" "sending k8s repo version: ${K8S_MAJOR_VERSION} to target node: ${hostname}"
        ssh -q ${hostname} <<< "echo '$K8S_REPO_CONTENT' | sudo tee $K8S_REPO_FILE" > /dev/null
        #########################################################
        log "INFO" "updating repos on target node: ${hostname}"
        ssh -q ${hostname} <<< "sudo dnf update -y >/dev/null 2>&1"
        #########################################################
        log "INFO" "Removing prior installed versions on node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes   ${VERBOSE_1}
            sudo rm -rf /etc/kubernetes
        """
        #########################################################
        log "INFO" "installing k8s tools on node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf install -y kubelet-${K8S_MINOR_VERSION} kubeadm-${K8S_MINOR_VERSION} kubectl-${K8S_MINOR_VERSION} --disableexcludes=kubernetes   ${VERBOSE_1}
            sudo systemctl enable --now kubelet ${VERBOSE_2}
        """
        #########################################################
        log "INFO" "Adding Kubeadm bash completion"
        add_bashcompletion ${hostname} kubeadm
        add_bashcompletion ${hostname} kubectl
        #########################################################
    done
    #########################################################
    log "INFO" "Kubernetes prerequisites setup completed successfully."
    #########################################################
}



install_cluster () {
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
    KUBEADM_INIT_OUTPUT=$(eval "$KUBE_ADM_COMMAND"  2>&1 || true)

    if echo $(echo "$KUBEADM_INIT_OUTPUT" | tr '[:upper:]' '[:lower:]') | grep "error"; then
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
        kubectl taint nodes $CONTROL_PLANE_HOST node-role.kubernetes.io/control-plane:NoSchedule- >/dev/null 2>&1
        kubectl taint nodes $CONTROL_PLANE_HOST node.kubernetes.io/not-ready:NoSchedule- >/dev/null 2>&1
        log "INFO" "sleeping for 30s to wait for Kubernetes control-plane node setup completion..."
        sleep 30
    fi
    log "INFO" "Finished deploying control-plane node."
}





install_cilium_prerequisites () {
    #########################################################
    log "WARNING" "cilium must be reinstalled as kubelet will be reinstalled"
    eval "sudo cilium uninstall ${VERBOSE_2}" || true
    ###############################################################################################################
    log "INFO" "Ensuring that kube-proxy is not installed"
    eval "kubectl -n kube-system delete ds kube-proxy ${VERBOSE_2}" || true
    # Delete the configmap as well to avoid kube-proxy being reinstalled during a Kubeadm upgrade (works only for K8s 1.19 and newer)
    eval "kubectl -n kube-system delete cm kube-proxy ${VERBOSE_2}" || true
    # Run on each node with root permissions:
    # eval "$(sudo iptables-save | grep -v KUBE | sudo iptables-restore)  ${VERBOSE_1}

    ################################################################################################################
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}
        ################################################################################################################
        # free_space $hostname
        ################################################################################################################
        log "INFO" "setting public interface: ${PUBLIC_INGRESS_INTER} rp_filter to 1"
        log "INFO" "setting cluster interface: ${CONTROLPLANE_INGRESS_INTER} rp_filter to 2"
        ssh -q ${hostname} <<< """
            sudo sysctl -w net.ipv4.conf.${PUBLIC_INGRESS_INTER}.rp_filter=1 ${VERBOSE_1}
            sudo sysctl -w net.ipv4.conf.$CONTROLPLANE_INGRESS_INTER.rp_filter=2 ${VERBOSE_1}
            sudo sysctl --system ${VERBOSE_1}
        """
        ################################################################################################################
        CILIUM_CLI_VERSION=$(curl --silent https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)

        log "INFO" "installing cilium cli version: $CILIUM_CLI_VERSION"
        ssh -q ${hostname} <<< """
            cd /tmp

            CLI_ARCH=amd64
            if [ "\$\(uname -m\)" = "aarch64" ]; then CLI_ARCH=arm64; fi

            # echo "CLI_ARCH for node: ${hostname} is: \${CLI_ARCH}"

            curl -s -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-\${CLI_ARCH}.tar.gz{,.sha256sum}

            sha256sum --check cilium-linux-\${CLI_ARCH}.tar.gz.sha256sum ${VERBOSE_1}
            sudo tar xzvfC cilium-linux-\${CLI_ARCH}.tar.gz /usr/local/bin ${VERBOSE_1}
            rm cilium-linux-*
        """
        add_bashcompletion ${hostname}  cilium
        log "INFO" "Finished installing cilium cli"
    done
    ################################################################################################################
    helm_chart_prerequisites "cilium" "https://helm.cilium.io" "$CILIUM_NS" "false" "false"
    ################################################################################################################
    # # cleaning up cilium and maglev tables
    # # EXPERIMENTAL ONLY AND STILL UNDER TESTING....
    # # echo "Started cleanup completed!"
    # # cilium_cleanup
    # # echo "Cilium cleanup completed!"
    # ################################################################################################################
}


install_cilium () {
    ################################################################################################################
    log "INFO" "Cilium native routing subnet is: ${CONTROLPLANE_SUBNET}"
    HASH_SEED=$(head -c12 /dev/urandom | base64 -w0)
    log "INFO" "Cilium maglev hashseed is: ${HASH_SEED}"

    log "INFO" "Installing cilium version: '${CILIUM_VERSION}' using cilium cli"
    OUTPUT=$(cilium install --version $CILIUM_VERSION \
        --set ipv4NativeRoutingCIDR=${CONTROLPLANE_SUBNET} \
        --set k8sServiceHost=auto \
        --values ./cilium/values.yaml \
        --set operator.replicas=${REPLICAS} \
        --set hubble.relay.replicas=${REPLICAS} \
        --set hubble.ui.replicas=${REPLICAS} \
        --set maglev.hashSeed="${HASH_SEED}"  \
        --set encryption.enabled=true \
        --set encryption.nodeEncryption=true \
        --set encryption.type=wireguard \
        2>&1 || true)

    if echo $OUTPUT | grep "Error"; then
        log "ERROR" "$OUTPUT"
        exit 1
    fi
    sleep 30
    ################################################################################################################
    # echo "Applying custom cilium ingress."
    # kubectl apply -f cilium/ingress.yaml
    log "INFO" "Removing default cilium ingress."
    kubectl delete svc -n kube-system cilium-ingress >/dev/null 2>&1 || true
    ################################################################################################################
    sleep 30
    # log "INFO" "waiting for cilium to go up (5minutes timeout)"
    # cilium status --wait >/dev/null 2>&1 || true
    ################################################################################################################
    log "INFO" "Apply LB IPAM"
    eval "kubectl apply -f cilium/loadbalancer-ip-pool.yaml ${VERBOSE_1}"
    ################################################################################################################
    sleep 180
    log "INFO" "restarting cilium."
    eval "kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator ${VERBOSE_1}" || true
    ################################################################################################################
    log "INFO" "Finished installing cilium"
    ################################################################################################################
}


join_cluster () {
    # TODO: for control-plane nodes:
    log "INFO" "Generating join command"
    JOIN_COMMAND_WORKERS=$(kubeadm token create --print-join-command)
    JOIN_COMMAND_CP="${JOIN_COMMAND} --control-plane"

    # for i in $(seq 2 "$((2 + NODES_LAST - 2))"); do
    for i in $(seq 2 "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}

        log "INFO" "sending cluster config to target node: ${hostname}"
        sudo cat /etc/kubernetes/admin.conf | ssh -q ${hostname} <<< """
            sudo tee -p /etc/kubernetes/admin.conf > /dev/null
            sudo chmod 600 /etc/kubernetes/admin.conf
            mkdir -p $HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config >/dev/null 2>&1
            sudo chown $(id -u):$(id -g) $HOME/.kube/config
        """

        # log "INFO" "sending PKI cert to target node: ${hostname}"
        # sudo cat /etc/kubernetes/pki/ca.crt | ssh -q ${hostname} <<< "sudo tee /etc/kubernetes/pki/ca.crt > /dev/null && sudo chmod 644 /etc/kubernetes/pki/ca.crt"
        # log "INFO" "updating certs"
        # ssh -q ${hostname} <<< "sudo update-ca-trust"

        log "INFO" "initiating cluster join for node: ${hostname}"
        ssh -q ${hostname} <<< """
            # echo "executing command: $JOIN_COMMAND_WORKERS"
            eval sudo ${JOIN_COMMAND_WORKERS} >/dev/null 2>&1 || true
        """
        log "INFO" "Finished joining cluster for node: ${hostname}"
    done
}



install_longhorn_prerequisites() {
    ##################################################################
    log "INFO" "Ensuring that 'noexec' is unset for '/var' on cluster nodes."

    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}

        log "INFO" "Ensuring that 'noexec' is unset for '/var' on node: '${hostname}'"
        ssh -q ${hostname} '
            # Backup the current /etc/fstab file
            sudo cp /etc/fstab /etc/fstab.bak

            # Remove 'noexec' from the mount options for /var only
            sudo sed -i '\''s|\(^/dev/[^[:space:]]\+\s\+/var\s\+[^[:space:]]\+\s\+[^[:space:]]*\),noexec|\1|'\'' /etc/fstab

            # Remount the /var filesystem to apply changes
            sudo mount -o remount /var
        '
        log "INFO" "Finished Ensuring that 'noexec' is unset for '/var' on node: '${hostname}'"
    done
    log "INFO" "Finished ensuring that 'noexec' is unset for '/var'  on cluster nodes."
    ##################################################################
    log "INFO" "installing required utilities for longhorn"
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}

        log "INFO" "installing longhorn prerequisites on node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf update -y ${VERBOSE_2}
            sudo dnf install curl jq nfs-utils cryptsetup \
                device-mapper iscsi-initiator-utils -y ${VERBOSE_2}
        """
    done
    log "INFO" "Finished installing required utilities for longhorn"
    ##################################################################
    log "INFO" "Creating namespace: ${LONGHORN_NS} for longhorn"
    # kubectl create ns $LONGHORN_NS >/dev/null 2>&1 || true
    helm_chart_prerequisites "longhorn" " https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"



    echo end of test
    exit 1
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
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}
        ##################################################################
        log "INFO" "Checking if the containerd service is active on node: ${hostname}"
        ssh -q ${hostname} '
            if systemctl is-active --quiet iscsid; then
                echo "iscsi deployed successfully."
            else
                echo "iscsi service is not running..."
                exit 1
            fi
        '
        log "INFO" "Finished checking if the containerd service is active on node: ${hostname}"
        ##################################################################
        log "INFO" "Ensure kernel support for NFS v4.1/v4.2: on node: ${hostname}"
        ssh -q ${hostname} '
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
        log "INFO" "enabling iscsi_tcp & dm_crypt on node: ${hostname}"
        # Check if the module is already in the file
        ssh -q ${hostname} '
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
        log "INFO" "Finished enabling iscsi_tcp & dm_crypt on node: ${hostname}"
        ##################################################################
        log "INFO" "Started installing Longhorn-cli on node: ${hostname}"
        ssh -q ${hostname} <<< """
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
        log "INFO" "Finished installing Longhorn-cli on node: ${hostname}"

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
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}

        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}
        log "INFO" "sending camo script to target node: ${hostname}"
        scp -q ./longhorn/os-camo.sh ${hostname}:/tmp/
        log "INFO" "Executing camofoulage on node: ${hostname}"
        ssh -q ${hostname} <<< """
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
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}

        log "INFO" "Resetting camofoulage on node: ${hostname}"
        ssh -q ${hostname} /tmp/os-camo.sh revert
    done
    #################################################################
    log "INFO" "Finished installing required utilities for longhorn"
}


# create_namespace() {
#     local namespace=$1
#     local max_retries=5
#     local attempt=1

#     while [ $attempt -le $max_retries ]; do
#         kubectl create ns "$namespace" ${VERBOSE_1}
#         if [ $? -eq 0 ]; then
#             echo "Namespace '$namespace' created successfully."
#             break
#         else
#             echo "Attempt $attempt/$max_retries failed to create namespace '$namespace'. Retrying in 10 seconds..."
#             attempt=$((attempt + 1))
#             sleep 10
#         fi
#     done

#     if [ $attempt -gt $max_retries ]; then
#         echo "Failed to create namespace '$namespace' after $max_retries attempts."
#     fi
# }


install_longhorn () {
    ##################################################################
    helm_chart_prerequisites "longhorn" " https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"
    ##################################################################
    log "INFO" "Started deploying longhorn in ns $LONGHORN_NS"
    output=$(helm install longhorn longhorn/longhorn  \
        --namespace $LONGHORN_NS  \
        --version ${LONGHORN_VERSION} \
        -f ./longhorn/values.yaml \
        --set defaultSettings.defaultReplicaCount=${REPLICAS} \
        --set persistence.defaultClassReplicaCount=${REPLICAS} \
        --set csi.attacherReplicaCount=${REPLICAS} \
        --set csi.provisionerReplicaCount=${REPLICAS} \
        --set csi.resizerReplicaCount=${REPLICAS} \
        --set csi.snapshotterReplicaCount=${REPLICAS} \
        --set longhornUI.replicas=${REPLICAS} \
        --set longhornConversionWebhook.replicas=${REPLICAS} \
        --set longhornAdmissionWebhook.replicas=${REPLICAS} \
        --set longhornRecoveryBackend.replicas=${REPLICAS} \
        > "${LONGHORN_LOGS}" 2>&1 || true)

    # Check if the Helm install command was successful
    if [ ! $? -eq 0 ]; then
        log "ERROR" "Failed to install Longhorn:\n\t${output}"
        exit 1
    fi


    echo end of test
    exit 1
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
    eval "kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_VERSION}/experimental-install.yaml ${VERBOSE_1}"
    # kubectl rollout restart -n kube-system deployment cilium-operator

    # log "INFO" "restarting cilium."
    # kubectl rollout restart -n kube-system ds/cilium-envoy deployment/cilium-operator  >/dev/null 2>&1 || true
    # sleep 30
    log "INFO" "Installing Gateway API Experimental TLSRoute from the Experimental channel"
    eval "kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/${GATEWAY_VERSION}/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml ${VERBOSE_1}"
    ################################################################################################################################################################
    log "INFO" "Applying hubble-ui HTTPRoute for ingress."
    eval "kubectl apply -f cilium/http-routes.yaml ${VERBOSE_1}"
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
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $KEY_FILE -out $CERT_FILE -subj "/CN=${CLUSTER_DNS_DOMAINS}" ${VERBOSE_1}

    log "INFO" "Creating rancher Kubernetes TLS secret"
    eval "kubectl create secret tls ${SECRET_NAME} --cert=$CERT_FILE --key=$KEY_FILE --namespace=kube-system  ${VERBOSE_1}"
    log "INFO" "Finished deploying TLS cert for TLS-HTTPS Gateway API"

    log "INFO" "Started deploying Gateway API"
    eval "kubectl apply -f cilium/http-gateway.yaml ${VERBOSE_1}"
    log "INFO" "Finished deploying Gateway API"

    log "INFO" "restarting cilium."
    eval " kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator ${VERBOSE_1}" || true
    sleep 45
}


helm_chart_prerequisites () {
    local CHART_NAME=$1
    local CHART_REPO=$2
    local CHART_NS=$3
    local DELETE_NS=$4
    local CREATE_NS=$5

    ##################################################################
    log "INFO" "adding '$CHART_NAME' repo to Helm"
    eval "helm repo add ${CHART_NAME} $CHART_REPO --force-update ${VERBOSE_1}" || true
    eval helm repo update ${VERBOSE_2} || true
    ##################################################################
    log "INFO" "uninstalling and ensuring the cluster is cleaned from $CHART_NAME"
    # kubectl delete -n $CHART_NS ds/vault-manager ds/vault-nfs-installation deployments/vault-ui deployments/vault-driver-deployer jobs/vault-uninstall >/dev/null 2>&1 || true
    eval "helm uninstall -n $CHART_NS $CHART_NAME ${VERBOSE_2}" || true
    ##################################################################
    if [ "$DELETE_NS" == "true" ] || [ "$DELETE_NS" == "1" ]; then
        log "INFO" "deleting '$CHART_NS' namespace"
        eval "kubectl delete ns $CHART_NS --now=true --ignore-not-found ${VERBOSE_1}"

        output=$(kubectl get ns $CHART_NS --ignore-not-found)

        if [ ! -z "$output"]; then
            log "INFO" "Force deleting '$CHART_NS' namespace"
            kubectl get namespace "$CHART_NS" -o json 2>/dev/null \
            | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
            | kubectl replace --raw /api/v1/namespaces/$CHART_NS/finalize -f - ${VERBOSE_2} || true
            log "INFO" "sleeping for 60 seconds while deleting '$CHART_NS' namespace"
            sleep 60
        fi

    else
        log "INFO" "Skipping NS deletion"
    fi

    if [ "$CREATE_NS" == "true" ] || [ "$CREATE_NS" == "1" ]; then
        ##################################################################
        log "INFO" "Creating '$CHART_NS' chart namespace: '$CHART_NS'"
        eval "kubectl create ns $CHART_NS ${VERBOSE_1}" || true
        # create_namespace

        echo end of test
        exit
        ##################################################################
    else
        log "INFO" "Skipping NS creation"
    fi
}

        # --set server.dataStorage.mountPath="${EXTRAVOLUMES_ROOT}"/vault/data \
        # --set server.auditStorage.mountPath="${EXTRAVOLUMES_ROOT}"/vault/audit \

install_vault () {
    ##################################################################
    helm_chart_prerequisites "hashicorp" " https://helm.releases.hashicorp.com" "$VAULT_NS" "true" "true"
    ##################################################################
    log "INFO" "Installing hashicorp vault Helm chart"
    helm install vault hashicorp/vault -n $VAULT_NS \
        --create-namespace --version $VAULT_VERSION \
        -f vault/values.yaml \
        --set injector.replicas=${REPLICAS} \
        --set server.ha.replicas=${REPLICAS} \
        > "${VAULT_LOGS}" 2>&1 || true
    ##################################################################
}



install_rancher () {
    helm_chart_prerequisites "rancher-${RANCHER_BRANCH}" "https://releases.rancher.com/server-charts/${RANCHER_BRANCH}" "$RANCHER_NS" "true" "true"

    # ##################################################################
    # log "INFO" "adding rancher repo to helm"
    # helm repo add rancher-${RANCHER_BRANCH} https://releases.rancher.com/server-charts/${RANCHER_BRANCH} ${VERBOSE_1} || true
    # helm repo update ${VERBOSE_1} || true
    # ##################################################################
    # log "INFO" "uninstalling and ensuring the cluster is cleaned from rancher"
    # helm uninstall -n $RANCHER_NS rancher ${VERBOSE_1} || true
    # ##################################################################
    # log "INFO" "deleting rancher NS"
    # kubectl delete ns $RANCHER_NS --now=true & ${VERBOSE_1} || true

    # kubectl get namespace "${RANCHER_NS}" -o json \
    # | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
    # | kubectl replace --raw /api/v1/namespaces/${RANCHER_NS}/finalize -f - ${VERBOSE_1} || true
    # ##################################################################
    # log "INFO" "Creating rancher NS: '$RANCHER_NS'"
    # kubectl create ns $RANCHER_NS ${VERBOSE_1} || true
    ##################################################################
    log "WARNING" "Warning: Currently rancher supports kubeVersion up to 1.31.0"
    log "WARNING" "initiating workaround to force the install..."

    DEVEL=""
    if [ ${RANCHER_BRANCH} == "alpha" ]; then
        log "WARNING" "Deploying rancher from alpha branch..."
        DEVEL="--devel"
    fi
    # helm install rancher rancher-${RANCHER_BRANCH}/rancher \
    # helm install rancher ./rancher/rancher-${RANCHER_VERSION}.tar.gz \


    log "INFO" "Started deploying rancher on the cluster"
    eval """
        helm install rancher rancher-${RANCHER_BRANCH}/rancher ${DEVEL} \
        --version ${RANCHER_VERSION}  \
        --namespace ${RANCHER_NS} \
        --set hostname=${RANCHER_FQDN} \
        --set bootstrapPassword=${RANCHER_ADMIN_PASS}  \
        --set replicas=${REPLICAS} \
        -f rancher/values.yaml ${VERBOSE_1} \
        ${VERBOSE_1}
    """
    # kubectl -n $RANCHER_NS rollout status deploy/rancher
    log "INFO" "Finished deploying rancher on the cluster"

    admin_url="https://rancher.pfs.pack/dashboard/?setup=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}')"
    log "INFO" "Access the admin panel at: $admin_url"

    admin_password=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}{{ "\n" }}')
    log "INFO" "Admin bootstrap password is: ${admin_password}"
    ##################################################################
    log "INFO" "Applying rancher HTTPRoute for ingress."
    kubectl apply -f rancher/http-routes.yaml
    ##################################################################
    sleep 150
    log "INFO" "Removing completed pods"
    kubectl delete pods -n ${RANCHER_NS} --field-selector=status.phase=Succeeded
    ##################################################################
    log "INFO" "Rancher installation completed."

}



install_certmanager () {
    ##################################################################
    # install cert-manager cli:
    for i in $(seq "$NODE_OFFSET" "$NODES_LAST"); do
        #####################################################################################
        NODE_VAR="NODE_$i"
        hostname=${!NODE_VAR}
        #####################################################################################
        log "INFO" "starting certmanager cli install for node: $hostname"
        ssh -q ${hostname} <<< """
            set -e  # Exit on error
            set -o pipefail  # Fail if any piped command fails
            OS=\$(go env GOOS)
            ARCH=\$(go env GOARCH)
            curl -fsSL -o cmctl https://github.com/cert-manager/cmctl/releases/download/v${CERTMANAGER_CLI_VERSION}/cmctl_\${OS}_\${ARCH}
            chmod +x cmctl
            sudo mv cmctl /usr/bin
            sudo ln -sf /usr/bin /usr/local/bin
        """
        add_bashcompletion $hostname cmctl
        log "INFO" "Finished certmanager cli install for node: $hostname"
    done
    ##################################################################
    # deploy cert-manager:
    helm_chart_prerequisites "jetstack" "https://charts.jetstack.io" "$CERTMANAGER_NS" "true" "true"
    ##################################################################
    log "INFO" "Started installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    helm install cert-manager jetstack/cert-manager  \
        --version ${CERTMANAGER_VERSION} \
        --namespace ${CERTMANAGER_NS} \
        --create-namespace \
        --set replicaCount=${REPLICAS} \
        --set webhook.replicaCount=${REPLICAS} \
        --set cainjector.replicaCount=${REPLICAS} \
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


################################################################################################################################################################

# deploy_hostsfile

RESETED=0
if [ "$PREREQUISITES" = true ]; then
    # reset_cluster
    RESETED=1
    prerequisites_requirements
    echo end of test
    exit
else
    log "INFO" "Cluster prerequisites have been skipped"
fi


echo end of test
exit

if [ $RESETED -eq 0 ]; then
    reset_cluster
fi

# install_kubetools

# install_cluster

# install_gateway_CRDS

# install_cilium_prerequisites

# install_cilium

# join_cluster

# install_gateway

# install_certmanager


# install_rancher

# install_longhorn_prerequisites
# install_longhorn

# install_vault

log "INFO" "deployment finished"


# ./deploy.sh --control-plane-hostname lorionstrm02vel --nodes-file hosts_file.yaml --with-prerequisites



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

