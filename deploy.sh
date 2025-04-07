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
VERBOSE_LEVEL=0
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
CONTROLPLANE_ADDRESS=$(eval ip -o -4 addr show $CONTROLPLANE_INGRESS_INTER | awk '{print $4}' | cut -d/ -f1)  # 192.168.66.129
CONTROLPLANE_SUBNET=$(echo $CONTROLPLANE_ADDRESS | awk -F. '{print $1"."$2"."$3".0/24"}')
################################################################################################################################################################

# set -e  # Enable immediate exit on error
# set -o pipefail  # Fail if any piped command fails


RESET_CLUSTER_ARG=0
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
        -r|--reset)
            RESET_CLUSTER_ARG=1
            shift
            ;;
        -v)
            VERBOSE_LEVEL=1
            shift
            ;;
        -vv)
            VERBOSE_LEVEL=2
            shift
            ;;
        -vvv)
            VERBOSE_LEVEL=3
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

#########################################################
# init log
sudo cp ./log /usr/local/bin/log
sudo chmod +x /usr/local/bin/log
################################################################################################################################################################
# Validate that required arguments are provided
if [ -z "$INVENTORY" ]; then
    log "deploy.sh" "ERROR" "Missing required arguments."
    log "deploy.sh" "ERROR" "$0 --inventory <INVENTORY>  [--dry-run]"
    exit 1
fi

# Ensure the YAML file exists
if [ ! -f "$INVENTORY" ]; then
    log "deploy.sh" "ERROR" "Error: inventory YAML file '$INVENTORY' not found."
    exit 1
fi
#########################################################
# import library function
. library.sh
#########################################################
# by default, all shell stdout commands info is suppressed
alias debug_log="/usr/local/bin/log -s -l DEBUG"  # by default, silence debug logs for verbose 0 and 1

# Ensure the alias is available in the current shell
shopt -s expand_aliases

if [ $VERBOSE_LEVEL -eq 0 ]; then
    VERBOSE="> /dev/null 2>&1"
# on level 1; we allow error outputs.
elif [ $VERBOSE_LEVEL -eq 1 ]; then
    VERBOSE="1> /dev/null"
else
    alias debug_log="/usr/local/bin/log -l DEBUG"  # by default, silence debug logs for verbose 0 and 1
    # on level 2; we allow info and error outputs.
    if [ $VERBOSE_LEVEL -eq 2 ]; then
        VERBOSE=""
    # unsilence debug logs
    # on level 3-5; we verbose the executed commands.
    elif [ $VERBOSE_LEVEL -eq 3 ]; then
        VERBOSE="-v"
    elif [ $VERBOSE_LEVEL -eq 4 ]; then
        VERBOSE="-vv"
    elif [ $VERBOSE_LEVEL -eq 5 ]; then
        VERBOSE="-vvv"
    fi
fi

#########################################################
log -f "deploy.sh" "VERBOSE_LEVEL set to: $VERBOSE_LEVEL"

log -f "deploy.sh" "Started loading inventory file: $INVENTORY"
CLUSTER_NODES=$(yq .hosts "$INVENTORY")
log -f "deploy.sh" "Finished loading inventory file: $INVENTORY"
################################################################################################################################################################
# ERROR CODES:
#   1xxx: cilium errors
#       1001: cilium status errors
#

debug_log=$(alias | grep -E "^alias debug_log=" | head -n 1)


deploy_hostsfile () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    # Path to the YAML file
    # Extract the 'nodes' array from the YAML and process it with jq
    # yq '.nodes["control_plane_nodes"]' "$INVENTORY" | jq -r '.[] | "\(.ip) \(.hostname)"' | while read -r line; do
    log -f ${CURRENT_FUNC} "installing required packages to deploy the cluster"
    eval "sudo dnf update -y  ${VERBOSE}"
    eval "sudo dnf upgrade -y  ${VERBOSE}"
    eval "sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools ${VERBOSE}"
    eval "sudo pip install yq  >/dev/null 2>&1"
    log -f ${CURRENT_FUNC} "Finished installing required packages to deploy the cluster"
   ##################################################################
    # Convert YAML to JSON using yq
    if ! command_exists yq; then
        log -f ${CURRENT_FUNC} "ERROR" "Error: 'yq' command not found. Please install yq to parse YAML files or run prerequisites..."
        exit 1
    fi
    # Parse YAML file and append node and worker-node details to /etc/hosts
    if ! command_exists jq; then
        log -f ${CURRENT_FUNC} "ERROR" "'jq' command not found. Please install jq to parse JSON files or run prerequisites..."
        exit 1
    fi
   ##################################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
       ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
       ##################################################################
        # Append the entry to the file (e.g., /etc/hosts)
        # Normalize spaces in the input line (collapse multiple spaces/tabs into one)
        local line="$ip         $hostname"
        local normalized_line=$(echo "$line" | sed 's/[[:space:]]\+/ /g')

        # Check if the normalized line already exists in the target file by parsing each line
        local exists=false
        while IFS= read -r target_line; do
            # Normalize spaces in the target file line
            normalized_target_line=$(echo "$target_line" | sed 's/[[:space:]]\+/ /g')

            # Compare the normalized lines
            if [[ "$normalized_line" == "$normalized_target_line" ]]; then
                local exists=true
                break
            fi
        done < "$HOSTSFILE_PATH"

        # Append the line to the target file if it doesn't exist
        if [ "$exists" = "false" ]; then
            echo "$line" | sudo tee -a "$HOSTSFILE_PATH" > /dev/null
            debug_log -f ${CURRENT_FUNC} "Host added to hosts file: $line"
        else
            debug_log -f ${CURRENT_FUNC} "Host already exists: $line"
        fi
        ################################################################
        log -f ${CURRENT_FUNC} "Setting hostname for '$role node': ${hostname}"
        ssh -q ${hostname} <<< """
            sudo hostnamectl set-hostname "$hostname"
            CURRENT_HOSTNAME=$(eval hostname)
        """
        log -f ${CURRENT_FUNC} "Finished setting hostname for '$role node': ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "installing tools for '$role node': ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf update -y  ${VERBOSE}
            sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools ${VERBOSE}
            sudo pip install yq >/dev/null 2>&1
        """
        log -f ${CURRENT_FUNC} "Finished installing tools node: ${hostname}"
       ##################################################################
        log -f ${CURRENT_FUNC} "sending hosts file to target node: ${hostname}"
        scp -q $HOSTSFILE_PATH ${hostname}:/tmp

        log -f ${CURRENT_FUNC} "Applying changes for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo cp /tmp/hosts ${HOSTSFILE_PATH}
        """
        log -f ${CURRENT_FUNC} "Finished modifying hosts file for ${role} node: ${hostname}"
       ##################################################################
    done
}


reset_cluster () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started reseting cluster"
    # ##################################################################
    log -f ${CURRENT_FUNC} "Started uninstalling Cilium from cluster..."
    eval "sudo cilium uninstall > /dev/null 2>&1" || true
    sleep 15
    log -f ${CURRENT_FUNC} "Finished uninstalling Cilium from cluster..."
   ##################################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
       ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
       ##################################################################
        log -f ${CURRENT_FUNC} "Started resetting k8s ${role} node node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo kubeadm reset -f > /dev/null 2>&1 || true
            sudo rm -rf \
                \$HOME/.kube/* \
                /root/.kube/* \
                /etc/cni/net.d/* \
                /etc/kubernetes/* \
        """
        log -f ${CURRENT_FUNC} "Finished resetting k8s ${role} node node: ${hostname}"
       ##################################################################
        log -f ${CURRENT_FUNC} "Reseting volumes for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo rm -rf "${EXTRAVOLUMES_ROOT}"/*

            sudo mkdir -p "${EXTRAVOLUMES_ROOT}"/cilium/hubble-relay
            sudo mkdir -p "${EXTRAVOLUMES_ROOT}"/cilium/hubble-relay
        """
        log -f ${CURRENT_FUNC} "finished reseting host persistent volumes mounts for ${role} node: ${hostname}"
    done
   ##################################################################
    log -f ${CURRENT_FUNC} "Finished reseting cluster"
}


prerequisites_requirements() {
    #########################################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #########################################################################################
    local error_raised=0
    #########################################################################################
    log -f ${CURRENT_FUNC}  "Started cluster prerequisites installation and checks"
    #########################################################################################
    log -f ${CURRENT_FUNC} "WARNING" "Will install cluster prerequisites, manual nodes reboot is required."
    #########################################################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
       #####################################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        #####################################################################################
        log -f ${CURRENT_FUNC} "Deploying logger function for ${role} node: ${hostname}"
        scp -q ./log $hostname:/tmp/
        ssh -q $hostname <<< """
            sudo mv /tmp/log /usr/local/bin/log
            sudo chmod +x /usr/local/bin/log
        """
        log -f ${CURRENT_FUNC} "Finished deploying logger function for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Configuring repos for ${role} node: ${hostname}"
        configure_repos $hostname
        log -f ${CURRENT_FUNC} "Finished configuring repos for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Starting dnf optimisations for ${role} node: ${hostname}"
        optimize_dnf $hostname "${VERBOSE}"
        log -f ${CURRENT_FUNC} "Finished dnf optimisations for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Started gid and uid visudo configuration for ${role} node: ${hostname}"

        local log_prefix=$(date +"\033[0;32m%Y-%m-%d %H:%M:%S,%3N ")
        ssh -q ${hostname} <<< """
            bash -c '''
                if echo '$SUDO_PASSWORD' | sudo -S grep -q \"^%$SUDO_GROUP[[:space:]]\\+ALL=(ALL)[[:space:]]\\+NOPASSWD:ALL\" /etc/sudoers.d/10_sudo_users_groups; then
                    echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - Visudo entry for $SUDO_GROUP is appended correctly.\" ${VERBOSE}
                else
                    echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - Visudo entry for $SUDO_GROUP is not found, appending...\" ${VERBOSE}
                    echo '$SUDO_PASSWORD' | sudo -S bash -c \"\"\"echo %$SUDO_GROUP       ALL\=\\\(ALL\\\)       NOPASSWD\:ALL >> /etc/sudoers.d/10_sudo_users_groups \"\"\"
                fi
            '''
        """
        log -f ${CURRENT_FUNC} "Finished gid and uid visudo configuration for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Check if the groups exists with the specified GIDs for ${role} node: ${hostname}"
        local log_prefix=$(date +"\033[0;32m%Y-%m-%d %H:%M:%S,%3N")
        ssh -q ${hostname} <<< """
            if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
                echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - '${SUDO_GROUP}' Group exists.\" ${VERBOSE}
            else
                echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - '${SUDO_GROUP}' Group does not exist, creating...\"  ${VERBOSE}
                echo "$SUDO_PASSWORD" | sudo -S groupadd ${SUDO_GROUP} 1> /dev/null
            fi
        """
        log -f ${CURRENT_FUNC} "Finished checking the sudoer groups with the specified GIDs for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Check if the user '${SUDO_USERNAME}' exists for ${role} node: ${hostname}"
        local log_prefix=$(date +"\033[0;32m%Y-%m-%d %H:%M:%S,%3N")
        ssh -q ${hostname} <<< """
            if id "$SUDO_USERNAME" &>/dev/null; then
                echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - User $SUDO_USERNAME exists.\" ${VERBOSE}
                echo "$SUDO_PASSWORD" | sudo -S  bash -c \"\"\"usermod -aG wheel,$SUDO_GROUP -s /bin/bash -m -d /home/$SUDO_USERNAME "$SUDO_USERNAME" \"\"\"
            else
                echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - User $SUDO_USERNAME does not exist.\" ${VERBOSE}
                echo "$SUDO_PASSWORD" | sudo -S bash -c \"\"\"useradd -m -s /bin/bash -G wheel,$SUDO_GROUP "$SUDO_USERNAME" \"\"\"
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring user on node ${hostname}..."
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Finished check if the user '${SUDO_USERNAME}' exists for ${role} node: ${hostname}"
        #####################################################################################
        if [ ! -z $SUDO_NEW_PASSWORD ]; then
            log -f ${CURRENT_FUNC} "setting password for user '${SUDO_USERNAME}' for ${role} node: ${hostname}"
            ssh -q ${hostname} << EOF
echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $SUDO_USERNAME:$SUDO_NEW_PASSWORD | chpasswd"
EOF
            # Check if the SSH command failed
            if [ $? -ne 0 ]; then
                error_raised=1
                log -f ${CURRENT_FUNC} "ERROR" "Error occurred while setting new sudo password for node ${hostname}."
                continue  # continue to next node and skip this one
            fi
            log -f ${CURRENT_FUNC} "Finished setting password for user '${SUDO_USERNAME}' for ${role} node: ${hostname}"
        fi
        #####################################################################################
        log -f ${CURRENT_FUNC}"Started checking if the kernel is recent enough for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            log -f kernel-version \"checking if the kernel is recent enough...\" ${VERBOSE}
            kernel_version=\$(uname -r)
            log -f kernel-version \"Kernel version: '\$kernel_version'\" ${VERBOSE}

            # Compare kernel versions
            if [[ \$(printf '%s\n' \"$recommended_rehl_version\" \"\$kernel_version\" | sort -V | head -n1) == \"$recommended_rehl_version\" ]]; then
                log -f kernel-version \"Kernel version is sufficient.\" ${VERBOSE}
            else
                log -f kernel-version \"ERROR\" \"${log_prefix_error} Kernel version is below the recommended version $recommended_rehl_version for ${role} node: ${hostname}\"
                exit 1
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Kernel mismatch for ${role} node ${hostname}."
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Finished checking if the kernel is recent enough for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Checking eBPF support for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            # Check if bpftool is installed
            if ! command -v bpftool &> /dev/null; then
                log -f ${CURRENT_FUNC} 'bpftool not found. Installing...' ${VERBOSE}
                sudo dnf install -y bpftool  >/dev/null 2>&1

                # Verify installation
                if ! command -v bpftool &> /dev/null; then
                    log -f ${CURRENT_FUNC} 'ERROR' 'Failed to install bpftool.'
                    exit 1
                fi
            fi
            # # Run bpftool feature check
            # log -f bpf-check 'Running bpftool feature check...'
            # sudo modprobe bpf
            # sudo modprobe bpfilter
            # # Re-check eBPF features
            # features=\$\(sudo bpftool feature\)
            # if check_ebpf_enabled; then
            #     log -f bpf-check 'eBPF has been successfully enabled.'
            # else
            #     log -f bpf-check 'ERROR' 'Failed to enable eBPF.'
            #     exit 1
            # fi
        """
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred checking eBPF support for ${role} node: ${hostname}"
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Finished checking eBPF support for ${role} node: ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Checking if bpf is mounted for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            mount_output=\$(mount | grep /sys/fs/bpf)
            log -f ${CURRENT_FUNC} \"mount_output: \$mount_output\"

            if [[ -n '\$mount_output' ]]; then
                log -f ${CURRENT_FUNC} \"bpf is mounted: \$mount_output\"
            else
                log -f ${CURRENT_FUNC} 'ERROR' 'ebpf is not mounted. You may need to mount it manually.'
                exit 1
            fi
        """
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred checking eBPF mount for ${role} node: ${hostname}"
            continue # continue to next node...
        fi
        log -f ${CURRENT_FUNC} "Finished checking if bpf is mounted for ${role} node: ${hostname}"
        ###################################################################################
        log -f $CURRENT_FUNC "Started updating env variables for ${role} node: ${hostname}"
        update_path ${hostname}
        log -f $CURRENT_FUNC "Finished updating env variables for ${role} node: ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "Started disabling swap for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo swapoff -a
            sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
        """
        # sudo sed -i '/ swap / s/^/#/' /etc/fstab
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while disabling swap node ${hostname}..."
            continue # continue to next node...
        fi
        log -f ${CURRENT_FUNC} "Finished Disabling swap for ${role} node: ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "Disable SELinux temporarily and modify config for persistence for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            if sudo setenforce 0 2>/dev/null; then
                log -f \"${CURRENT_FUNC}\" 'SELinux set to permissive mode temporarily.' ${VERBOSE}
            else
                log -f \"${CURRENT_FUNC}\" 'ERROR' 'Failed to set SELinux to permissive mode. It may already be disabled.'
                exit 1
            fi

            if sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config; then
                log -f \"${CURRENT_FUNC}\" 'SELinux configuration updated.'  ${VERBOSE}
            else
                log -f \"${CURRENT_FUNC}\" 'ERROR' 'Failed to update SELinux configuration.'
                exit 2
            fi

            if sestatus | sed -n '/Current mode:[[:space:]]*permissive/!q'; then
                log -f \"${CURRENT_FUNC}\" 'SELinux is permissive' ${VERBOSE}
            else
                log -f 'ERROR' 'SELinux is not permissive'
                exit 3
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring SELinux for for ${role} node: ${hostname}"
            continue # continue to next node...
        fi
        log -f ${CURRENT_FUNC} "Finished disabling SELinux temporarily and modify config for persistence for ${role} node: ${hostname}"
        ################################################################*
#         # TODO
#         # update_firewall $hostname
        ############################################################################
        log -f ${CURRENT_FUNC} "Configuring bridge network for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo echo -e 'overlay\nbr_netfilter' | sudo tee /etc/modules-load.d/containerd.conf > /dev/null
            sudo modprobe overlay
            sudo modprobe br_netfilter

            params=(
                'net.bridge.bridge-nf-call-iptables=1'
                'net.ipv4.ip_forward=1'
                'net.bridge.bridge-nf-call-ip6tables=1'
            )

            # File to update
            file='/etc/sysctl.d/k8s.conf'

            # Loop through each parameter
            for param in \"\${params[@]}\"; do
                key=\$(echo \"\$param\" | cut -d= -f1)
                value=\$(echo \"\$param\" | cut -d= -f2)

                # Use sed to ensure the parameter is in the file with the correct value
                sudo sed -i \"/^\$key=/d\" \"\$file\"
                echo \"\$param\" | sudo tee -a \"\$file\" > /dev/null
            done
            sudo sysctl --system ${VERBOSE}
        """
        log -f ${CURRENT_FUNC} "Finished configuring bridge network for ${role} node: ${hostname}"
        ############################################################################
        log -f ${CURRENT_FUNC} "Installing containerD for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf install -y yum-utils ${VERBOSE}
            sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo  ${VERBOSE}
            sudo dnf install containerd.io -y ${VERBOSE}
        """
        log -f ${CURRENT_FUNC} "Finished installing containerD for ${role} node: ${hostname}"
        ############################################################################
        log -f ${CURRENT_FUNC} "Enabling containerD NRI with systemD and cgroups for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            CONFIG_FILE='/etc/containerd/config.toml'

            # Pause version mismatch:
            log -f ${CURRENT_FUNC} 'Resetting containerD config to default.' ${VERBOSE}
            containerd config default | sudo tee \$CONFIG_FILE >/dev/null

            log -f ${CURRENT_FUNC} 'Backing up the original config file' ${VERBOSE}
            cp -f -n \$CONFIG_FILE \${CONFIG_FILE}.bak

            log -f ${CURRENT_FUNC} 'Configuring containerD for our cluster' ${VERBOSE}
            sudo sed -i '/\[plugins\\.\"io\\.containerd\\.nri\\.v1\\.nri\"\]/,/^\[/{
                s/disable = true/disable = false/;
                s/disable_connections = true/disable_connections = false/;
                s|plugin_config_path = ".*"|plugin_config_path = \"/etc/nri/conf.d\"|;
                s|plugin_path = ".*"|plugin_path = \"/opt/nri/plugins\"|;
                s|plugin_registration_timeout = ".*"|plugin_registration_timeout = \"15s\"|;
                s|plugin_request_timeout = ".*"|plugin_request_timeout = \"12s\"|;
                s|socket_path = ".*"|socket_path = \"/var/run/nri/nri.sock\"|;
            }' "\$CONFIG_FILE"


            sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' \$CONFIG_FILE
            sudo sed -i 's|sandbox_image = \"registry.k8s.io/pause:3.8\"|sandbox_image = \"registry.k8s.io/pause:3.10\"|' \$CONFIG_FILE

            # sudo sed -i 's|root = \"/var/lib/containerd\"|root = \"/mnt/longhorn-1/var/lib/containerd\"|' $CONFIG_FILE

            sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
            sudo chown -R root:root /etc/nri /opt/nri

            log -f ${CURRENT_FUNC} 'Starting and enabling containerD' ${VERBOSE}
            sudo systemctl enable containerd
            sudo systemctl daemon-reload
            sudo systemctl restart containerd

            sleep 10
            # Check if the containerd service is active
            if systemctl is-active --quiet containerd.service; then
                log -f ${CURRENT_FUNC} 'ContainerD configuration updated successfully.' ${VERBOSE}
            else
                log -f ${CURRENT_FUNC} 'ERROR' 'ContainerD configuration failed, containerd service is not running...'
                exit 1
            fi
        """
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while enabling containerD NRI with systemD and cgroups for ${role} node: ${hostname}"
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Finished containerD NRI with systemD and cgroups for ${role} node: ${hostname}"
        #############################################################################
        log -f ${CURRENT_FUNC} "Installing GO on node: $hostname"
        install_go $hostname $GO_VERSION $TINYGO_VERSION
        log -f ${CURRENT_FUNC} "Finished installing GO on node: $hostname"
        #############################################################################
        log -f ${CURRENT_FUNC} "Installing Helm on node: $hostname"
        install_helm $hostname
        add_bashcompletion $hostname helm
        log -f ${CURRENT_FUNC} "Finished installing Helm on node: $hostname"
        #############################################################################
        log -f ${CURRENT_FUNC} "Configuring containerd for ${role} node: ${hostname}"
        configure_containerD $hostname $HTTP_PROXY $HTTPS_PROXY $NO_PROXY $PAUSE_VERSION $SUDO_GROUP
        log -f ${CURRENT_FUNC} "Finished configuration of containerd for ${role} node: ${hostname}"
        #############################################################################
    done
    #############################################################################
    if [ $error_raised -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished cluster prerequisites installation and checks"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the cluster prerequisites installation and checks"
    fi
}


install_kubetools () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
   ##################################################################
    log -f ${CURRENT_FUNC} "WARNING" "cilium must be reinstalled as kubelet will be reinstalled"
    eval "sudo cilium uninstall > /dev/null 2>&1" || true
   ##################################################################
    # Fetch Latest version from kube release....
    if [ "$(echo "$FETCH_LATEST_KUBE" | tr '[:upper:]' '[:lower:]')" = "true" ]; then
        log -f ${CURRENT_FUNC} "Fetching latest kuberentes version from stable-1..."
        # Fetch the latest stable full version (e.g., v1.32.2)
        K8S_MINOR_VERSION=$(curl -L -s https://dl.k8s.io/release/stable-1.txt)
       ##################################################################
        # Extract only the major.minor version (e.g., 1.32)
        K8S_MAJOR_VERSION=$(echo $K8S_MINOR_VERSION | cut -d'.' -f1,2)
    fi
    # ensure that the vars are set either from latest version or .env
    if [ -z "$K8S_MAJOR_VERSION" ] || [ -z $K8S_MINOR_VERSION ]; then
        log -f ${CURRENT_FUNC} "ERROR" "K8S_MAJOR_VERSION and/or K8S_MINOR_VERSION have not been set on .env file"
        return 2
    fi
   ##################################################################
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
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "sending k8s repo version: ${K8S_MAJOR_VERSION} to target node: ${hostname}"
        ssh -q ${hostname} <<< """
            echo '$K8S_REPO_CONTENT' | sudo tee $K8S_REPO_FILE > /dev/null
        """
        ##################################################################
        log -f ${CURRENT_FUNC} "updating repos on target node: ${hostname}"
        ssh -q ${hostname} <<< "
            sudo dnf update -y ${VERBOSE}
        "
        ##################################################################
        log -f ${CURRENT_FUNC} "Removing prior installed versions for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes ${VERBOSE}
            sudo rm -rf /etc/kubernetes
        """
        ##################################################################
        log -f ${CURRENT_FUNC} "installing k8s tools for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf install -y kubelet-${K8S_MINOR_VERSION} kubeadm-${K8S_MINOR_VERSION} kubectl-${K8S_MINOR_VERSION} --disableexcludes=kubernetes ${VERBOSE}
            sudo systemctl enable --now kubelet > /dev/null 2>&1
        """
        ##################################################################
        log -f ${CURRENT_FUNC} "Adding Kubeadm bash completion"
        add_bashcompletion ${hostname} kubeadm $VERBOSE
        add_bashcompletion ${hostname} kubectl $VERBOSE
        ##################################################################
    done
   ##################################################################
    log -f ${CURRENT_FUNC} "Kubernetes prerequisites setup completed successfully."
   ##################################################################
}


install_cluster () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "generating kubeadm init config file"
    envsubst < init-config-template.yaml > init-config.yaml
    ####################################################################
    log -f ${CURRENT_FUNC} "sending kubeadm init config file to main control-plane: ${CONTROL_PLANE_HOST}"
    scp -q ./init-config.yaml ${CONTROL_PLANE_HOST}:/tmp/
    ####################################################################
    # Kubeadm init logic
    KUBE_ADM_COMMAND="sudo kubeadm init --config /tmp/init-config.yaml --skip-phases=addon/kube-proxy "
    ####################################################################
    # Simulate Kubeadm init or worker-node node join
    if [ "$DRY_RUN" = true ]; then
        log -f ${CURRENT_FUNC} "Initializing dry-run for control plane node init..."
        KUBE_ADM_COMMAND="$KUBE_ADM_COMMAND --dry-run "
    else
        log -f ${CURRENT_FUNC} "Initializing control plane node init..."
    fi
    ####################################################################
    log -f ${CURRENT_FUNC} "    with command: $KUBE_ADM_COMMAND"
    ####################################################################
    ssh -q $CONTROL_PLANE_HOST <<< """
        ####################################################################
        # set -e  # Exit on error
        ####################################################################
        KUBEADM_INIT_OUTPUT=\$(eval $KUBE_ADM_COMMAND  2>&1 || true)

        if echo \$(echo \"\$KUBEADM_INIT_OUTPUT\" | tr '[:upper:]' '[:lower:]') | grep 'error'; then
            log -f \"${CURRENT_FUNC}\" 'ERROR' \"\$KUBEADM_INIT_OUTPUT\"
            return 1
        fi
        ####################################################################
        if [ \"$DRY_RUN\" = true ]; then
            log -f \"${CURRENT_FUNC}\" 'Control plane dry-run initialized without errors.'
        else
            log -f \"${CURRENT_FUNC}\" 'Control plane initialized successfully.'
            # Copy kubeconfig for kubectl access
            mkdir -p \$HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf \$HOME/.kube/config
            sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config

            log -f \"${CURRENT_FUNC}\" 'unintaing the control-plane node'
            kubectl taint nodes $CONTROL_PLANE_HOST node-role.kubernetes.io/control-plane:NoSchedule- >/dev/null 2>&1
            kubectl taint nodes $CONTROL_PLANE_HOST node.kubernetes.io/not-ready:NoSchedule- >/dev/null 2>&1
            log -f \"${CURRENT_FUNC}\" \"sleeping for 30s to wait for Kubernetes control-plane node: ${CONTROL_PLANE_HOST} setup completion...\"
            sleep 5
        fi
        ####################################################################
    """
    ####################################################################

    if [ $? -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished deploying control-plane node."
    else
        return 1
    fi
    ####################################################################
}


install_gateway_CRDS () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    # this hits a bug described here: https://github.com/cilium/cilium/issues/38420
    # log -f ${CURRENT_FUNC} "Installing Gateway API version: ${GATEWAY_VERSION} from the standard channel"
    # kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_VERSION}/standard-install.yaml

    log -f ${CURRENT_FUNC} "sending http-routes.yaml file to control plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./cilium/http-routes.yaml ${CONTROL_PLANE_HOST}:/tmp/

    # using experimental CRDS channel
    log -f ${CURRENT_FUNC} "Installing Gateway API version: ${GATEWAY_VERSION} from the experimental channel"

    ssh -q $CONTROL_PLANE_HOST <<< """
        # set -e  # Exit on error
        eval \"kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_VERSION}/experimental-install.yaml ${VERBOSE}\"

        log -f \"${CURRENT_FUNC}\" 'Installing Gateway API Experimental TLSRoute from the Experimental channel'

        eval \"kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/${GATEWAY_VERSION}/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml ${VERBOSE}\"

        log -f \"${CURRENT_FUNC}\" 'Applying hubble-ui HTTPRoute for ingress.'
        eval \"kubectl apply -f /tmp/http-routes.yaml ${VERBOSE}\"
    """
}


install_cilium_prerequisites () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    log -f ${CURRENT_FUNC} "INFO" "Started installing cilium prerequisites"
   ##################################################################
    log -f ${CURRENT_FUNC} "INFO" "cilium must be reinstalled as kubelet will be reinstalled"
    ssh -q $CONTROL_PLANE_HOST <<< """
        eval \"sudo cilium uninstall > /dev/null 2>&1\" || true
        log -f \"${CURRENT_FUNC}\" 'Ensuring that kube-proxy is not installed'
        eval \"kubectl -n kube-system delete ds kube-proxy > /dev/null 2>&1\" || true
        # Delete the configmap as well to avoid kube-proxy being reinstalled during a Kubeadm upgrade (works only for K8s 1.19 and newer)
        eval \"kubectl -n kube-system delete cm kube-proxy > /dev/null 2>&1\" || true
        log -f \"${CURRENT_FUNC}\" 'waiting 30seconds for cilium to be uninstalled'
        sleep 30
    """
    ##################################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        # free_space $hostname
        ##################################################################
        log -f ${CURRENT_FUNC} "setting public interface: ${PUBLIC_INGRESS_INTER} rp_filter to 1"
        log -f ${CURRENT_FUNC} "setting cluster interface: ${CONTROLPLANE_INGRESS_INTER} rp_filter to 2"
        ssh -q ${hostname} <<< """
            # set -e
            sudo sysctl -w net.ipv4.conf.${PUBLIC_INGRESS_INTER}.rp_filter=1 ${VERBOSE}
            sudo sysctl -w net.ipv4.conf.$CONTROLPLANE_INGRESS_INTER.rp_filter=2 ${VERBOSE}
            sudo sysctl --system ${VERBOSE}
        """
        ##################################################################
        CILIUM_CLI_VERSION=$(curl --silent https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)

        log -f ${CURRENT_FUNC} "installing cilium cli version: $CILIUM_CLI_VERSION"
        ssh -q ${hostname} <<< """
            # set -e
            cd /tmp

            CLI_ARCH=amd64
            if [ \"\$\(uname -m\)\" = 'aarch64' ]; then CLI_ARCH=arm64; fi

            curl -s -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-\${CLI_ARCH}.tar.gz{,.sha256sum}

            sha256sum --check cilium-linux-\${CLI_ARCH}.tar.gz.sha256sum ${VERBOSE}
            sudo tar xzvfC cilium-linux-\${CLI_ARCH}.tar.gz /usr/local/bin ${VERBOSE}
            rm cilium-linux-*
        """
        add_bashcompletion ${hostname}  cilium $VERBOSE
        log -f ${CURRENT_FUNC} "Finished installing cilium cli"
    done
    ##################################################################
    helm_chart_prerequisites "cilium" "https://helm.cilium.io" "$CILIUM_NS" "false" "false"
    ##################################################################
    # # cleaning up cilium and maglev tables
    # # EXPERIMENTAL ONLY AND STILL UNDER TESTING....
    # # echo "Started cleanup completed!"
    # # cilium_cleanup
    # # echo "Cilium cleanup completed!"
    # ##################################################################
    log -f ${CURRENT_FUNC} "INFO" "Finished installing cilium prerequisites"
}


install_cilium () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #############################################################
    log -f ${CURRENT_FUNC} "Started installing cilium"
    #############################################################
    log -f ${CURRENT_FUNC} "Cilium native routing subnet is: ${CONTROLPLANE_SUBNET}"
    HASH_SEED=$(head -c12 /dev/urandom | base64 -w0)
    log -f ${CURRENT_FUNC} "Cilium maglev hashseed is: ${HASH_SEED}"
    #############################################################
    log -f ${CURRENT_FUNC} "sending cilium values to control plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./cilium/values.yaml ${CONTROL_PLANE_HOST}:/tmp/
    #############################################################
    log -f ${CURRENT_FUNC} "sending lb ip pool to control plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./cilium/loadbalancer-ip-pool.yaml ${CONTROL_PLANE_HOST}:/tmp/
    #############################################################
    log -f ${CURRENT_FUNC} "Installing cilium version: '${CILIUM_VERSION}' using cilium cli"
    ssh -q $CONTROL_PLANE_HOST <<< """
        # set -e
        #############################################################
        OUTPUT=\$(cilium install --version $CILIUM_VERSION \
            --set ipv4NativeRoutingCIDR=${CONTROLPLANE_SUBNET} \
            --set k8sServiceHost=auto \
            --values /tmp/values.yaml \
            --set operator.replicas=${REPLICAS} \
            --set hubble.relay.replicas=${REPLICAS} \
            --set hubble.ui.replicas=${REPLICAS} \
            --set maglev.hashSeed="${HASH_SEED}"  \
            --set encryption.enabled=true \
            --set encryption.nodeEncryption=true \
            --set encryption.type=wireguard \
            2>&1 || true)

        if echo \$OUTPUT | grep 'Error'; then
            log -f \"${FUNCNAME[0]}\" 'ERROR' $OUTPUT
            return 1
        fi
        #############################################################
        sleep 30
        log -f \"${FUNCNAME[0]}\" 'Removing default cilium ingress.'
        kubectl delete svc -n kube-system cilium-ingress >/dev/null 2>&1 || true
        #############################################################
        log -f \"${FUNCNAME[0]}\" 'Apply LB IPAM on cluster'
        eval \"kubectl apply -f /tmp/loadbalancer-ip-pool.yaml ${VERBOSE}\"
        #############################################################
        sleep 30
        #############################################################
    """





    log -f ${CURRENT_FUNC} "Finished installing cilium"
    #############################################################
}


join_cluster () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    # TODO: for control-plane nodes:
    log -f ${CURRENT_FUNC} "Generating join command from control-plane node: ${CONTROL_PLANE_HOST}"

    JOIN_COMMAND_WORKER=$(ssh -q $CONTROL_PLANE_HOST <<< "kubeadm token create --print-join-command""")
    JOIN_COMMAND_CONTROLPLANE="${JOIN_COMMAND_WORKER} --control-plane"

    # for i in $(seq 2 "$((2 + NODES_LAST - 2))"); do
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')

        if [ $hostname == ${CONTROL_PLANE_HOST} ]; then
            log -f ${CURRENT_FUNC} "hostname: ${hostname} "
            continue
        fi

        log -f ${CURRENT_FUNC} "sending cluster config to target ${role} node: ${hostname}"
        sudo cat /etc/kubernetes/admin.conf | ssh -q ${hostname} """
            sudo tee -p /etc/kubernetes/admin.conf > /dev/null

            sudo chmod 600 /etc/kubernetes/admin.conf
            mkdir -p \$HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf \$HOME/.kube/config >/dev/null 2>&1
            sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config
        """

        log -f ${CURRENT_FUNC} "initiating cluster join for ${role} node: ${hostname}"
        if [ $role == "worker" ]; then
            ssh -q ${hostname} <<< """
                eval sudo ${JOIN_COMMAND_WORKER} >/dev/null 2>&1 || true
            """
        elif [ $role == "control-plane" ]; then
            ssh -q ${hostname} <<< """
                eval sudo ${JOIN_COMMAND_CONTROLPLANE} >/dev/null 2>&1 || true
            """
        fi
        log -f ${CURRENT_FUNC} "Finished joining cluster for ${role} node: ${hostname}"
    done



}


install_gateway () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    # prerequisites checks:
    # REF: https://docs.cilium.io/en/v1.17/network/servicemesh/gateway-api/gateway-api/#installation
    log -f ${CURRENT_FUNC} "Started checking prerequisites for Gateway API"
    ##################################################################
    # Check the value of kube-proxy replacement
    config_check ${CONTROL_PLANE_HOST} "cilium config view" "kube-proxy-replacement" "true"
    if [ ! $RETURN_CODE -eq 0 ]; then
        return $RETURN_CODE
    fi
    ##################################################################
    # Check the value of enable-l7-proxy
    config_check ${CONTROL_PLANE_HOST} "cilium config view" "enable-l7-proxy" "true"
    if [ ! $RETURN_CODE -eq 0 ]; then
        return $RETURN_CODE
    fi
    log -f "${CURRENT_FUNC}" "Finished checking prerequisites for Gateway API"
    ##################################################################
    log -f "${CURRENT_FUNC}" "Sending Gateway API config to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./cilium/http-gateway.yaml ${CONTROL_PLANE_HOST}:/tmp/
    ##################################################################
    log -f "${CURRENT_FUNC}" "Started deploying TLS cert for TLS-HTTPS Gateway API on control-plane node: ${CONTROL_PLANE_HOST}"

    CERTS_PATH=/etc/cilium/certs
    GATEWAY_API_SECRET_NAME=shared-tls
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        ##################################################################
        sudo mkdir -p $CERTS_PATH
        sudo chown -R \$USER:\$USER $CERTS_PATH
        CERT_FILE=\"$CERTS_PATH/${GATEWAY_API_SECRET_NAME}.crt\"
        KEY_FILE=\"$CERTS_PATH/${GATEWAY_API_SECRET_NAME}.key\"
        ##################################################################
        log -f \"${CURRENT_FUNC}\" 'Generating self-signed certificate and key'
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout \$KEY_FILE -out \$CERT_FILE -subj \"/CN=${CLUSTER_DNS_DOMAIN}\" > /dev/null 2>&1
        ##################################################################
        log -f \"${CURRENT_FUNC}\" 'deleting previous Gateway API TLS secret'
        eval \"kubectl delete secret  ${GATEWAY_API_SECRET_NAME} --namespace=kube-system > /dev/null 2>&1\"
        log -f \"${CURRENT_FUNC}\" 'Started creating Gateway API TLS secret'
        eval \"kubectl create secret tls ${GATEWAY_API_SECRET_NAME} --cert=\$CERT_FILE --key=\$KEY_FILE --namespace=kube-system  ${VERBOSE}\"
        log -f \"${CURRENT_FUNC}\" 'Finished deploying TLS cert for TLS-HTTPS Gateway API'
        ##################################################################
        log -f \"${CURRENT_FUNC}\" 'Started deploying Gateway API'
        eval \"kubectl apply -f /tmp/http-gateway.yaml ${VERBOSE}\"
        log -f \"${CURRENT_FUNC}\" 'Finished deploying Gateway API'
        ##################################################################
        log -f \"${CURRENT_FUNC}\" 'restarting cilium.'
        eval \"kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator ${VERBOSE}\" || true
    """
    #################################################################
    return 0
}


restart_cilium() {
    #################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #################################################################
    log -f "$CURRENT_FUNC" "Ensuring that cilium replicas scale without errors..."
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        current_retry=0
        max_retries=10
        while true; do
            current_retry=\$((current_retry + 1))
            if [ \$current_retry -gt \$max_retries ]; then
                log -f \"${CURRENT_FUNC}\" 'ERROR' 'Reached maximum retry count for cilium status to go up. Exiting...'
                exit 1001
            fi

            CILIUM_STATUS=\$(cilium status | tr -d '\0')

            if echo "\$CILIUM_STATUS" | grep -qi 'error'; then
                log -f \"${CURRENT_FUNC}\" \"cilium status contains errors... restarting cilium. Try: \$current_retry\"
                eval \"kubectl rollout restart -n kube-system ds/cilium ds/cilium-envoy deployment/cilium-operator > /dev/null 2>&1\" || true
                sleep 60
            else
                log -f \"${CURRENT_FUNC}\" 'Cilium is up and running'
                break
            fi
        done
    """
    return $?
    #################################################################
}


install_certmanager_prerequisites() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    # install cert-manager cli:
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f "${CURRENT_FUNC}" "starting certmanager cli install for ${role} node: $hostname"
        ssh -q ${hostname} <<< """
            OS=\$(go env GOOS)
            ARCH=\$(go env GOARCH)
            curl -fsSL -o cmctl https://github.com/cert-manager/cmctl/releases/download/v${CERTMANAGER_CLI_VERSION}/cmctl_\${OS}_\${ARCH}
            chmod +x cmctl
            sudo mv cmctl /usr/bin
            sudo ln -sf /usr/bin /usr/local/bin

        """
        add_bashcompletion $hostname "cmctl"
        log -f "${CURRENT_FUNC}" "Finished certmanager cli install for ${role} node: $hostname"
        ##################################################################
    done
    ##################################################################
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "cert-manager" "https://charts.jetstack.io" "$CERTMANAGER_NS" "true" "true"
    ##################################################################
    log -f "$CURRENT_FUNC" "Sending certmanager values to control-plane node: ${CONTROL_PLANE_HOST}"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        # create tmp dir for certmanager
        rm -rf /tmp/certmanager &&  mkdir -p /tmp/certmanager
    """
    scp -q ./certmanager/values.yaml $CONTROL_PLANE_HOST:/tmp/certmanager/
    ##################################################################
}


install_certmanager () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f "${CURRENT_FUNC}" "Started installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    # TODO: --set http_proxy --set https_proxy --set no_proxy
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        helm install cert-manager jetstack/cert-manager  \
            --version ${CERTMANAGER_VERSION} \
            --namespace ${CERTMANAGER_NS} \
            --create-namespace \
            --set replicaCount=${REPLICAS} \
            --set webhook.replicaCount=${REPLICAS} \
            --set cainjector.replicaCount=${REPLICAS} \
            -f /tmp/certmanager/values.yaml

        # helm install cert-manager jetstack/cert-manager \
        #     --namespace ${CERTMANAGER_NS} \
        #     --create-namespace \
        #     --set crds.enabled=true
    """
    log -f "${CURRENT_FUNC}" "Finished installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    echo end of test
    exit 1
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


install_longhorn_prerequisites() {
    ##################################################################
    log -f ${CURRENT_FUNC} "Ensuring that 'noexec' is unset for '/var' on cluster nodes."

    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "Ensuring that 'noexec' is unset for '/var' on node: '${hostname}'"
        ssh -q ${hostname} '
            # Backup the current /etc/fstab file
            sudo cp /etc/fstab /etc/fstab.bak

            # Remove 'noexec' from the mount options for /var only
            sudo sed -i '\''s|\(^/dev/[^[:space:]]\+\s\+/var\s\+[^[:space:]]\+\s\+[^[:space:]]*\),noexec|\1|'\'' /etc/fstab

            # Remount the /var filesystem to apply changes
            sudo mount -o remount /var
        '
        log -f ${CURRENT_FUNC} "Finished Ensuring that 'noexec' is unset for '/var' on node: '${hostname}'"
    done
    log -f ${CURRENT_FUNC} "Finished ensuring that 'noexec' is unset for '/var'  on cluster nodes."
    ##################################################################
    log -f ${CURRENT_FUNC} "installing required utilities for longhorn"
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "installing longhorn prerequisites for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf update -y ${VERBOSE}
            sudo dnf install curl jq nfs-utils cryptsetup \
                device-mapper iscsi-initiator-utils -y ${VERBOSE}
        """
    done
    log -f ${CURRENT_FUNC} "Finished installing required utilities for longhorn"
    ##################################################################
    log -f ${CURRENT_FUNC} "Creating namespace: ${LONGHORN_NS} for longhorn"
    # kubectl create ns $LONGHORN_NS >/dev/null 2>&1 || true
    helm_chart_prerequisites "longhorn" " https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"



    echo end of test
    exit 1
    #################################################################
    log -f ${CURRENT_FUNC} "install NFS/iSCSI on the cluster"
    # REF: https://github.com/longhorn/longhorn/tree/master/deploy/prerequisite
    #
    ERROR_RAISED=0
    for service in "nfs" "iscsi"; do
        log -f ${CURRENT_FUNC} "Started installation of ${service} on all nodes"
        kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml >/dev/null 2>&1 || true

        upper_service=$(echo ${service} | awk '{print toupper($0)}')
        TIMEOUT=180  # 3 minutes in seconds
        START_TIME=$(date +%s)
        while true; do
            # Wait for the pods to be in Running state
            log -f ${CURRENT_FUNC} "Waiting for Longhorn ${upper_service} installation pods to be in Running state..."
            sleep 30
            log -f ${CURRENT_FUNC} "Finished sleeping..."
            log -f ${CURRENT_FUNC} "Getting pods from namespace: '${LONGHORN_NS}'"
            PODS=$(kubectl -n $LONGHORN_NS get pod 2>/dev/null || true)
            log -f ${CURRENT_FUNC} "Finished getting pods from namespace: '${LONGHORN_NS}'"
            # Check if PODS is empty
            if [ -z "$PODS" ]; then
                log -f ${CURRENT_FUNC} "WARNING" "No matching pods found for: 'longhorn-${service}-installation'"
                continue
            fi
            PODS=$(echo $PODS | grep longhorn-${service}-installation)
            RUNNING_COUNT=$(echo "$PODS" | grep -c "Running")
            TOTAL_COUNT=$(echo "$PODS" | wc -l)

            log -f ${CURRENT_FUNC} "Running Longhorn ${upper_service} install containers: ${RUNNING_COUNT}/${TOTAL_COUNT}"
            if [[ $RUNNING_COUNT -eq $TOTAL_COUNT ]]; then
                break
            fi

            CURRENT_TIME=$(date +%s)
            ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

            if [[ $ELAPSED_TIME -ge $TIMEOUT ]]; then
                log -f ${CURRENT_FUNC} "ERROR" "Timeout reached. Exiting..."
                exit 1
            fi
        done

        current_retry=0
        max_retries=3
        while true; do
            current_retry=$((current_retry + 1))
            log -f ${CURRENT_FUNC} "Checking Longhorn ${upper_service} setup completion... try N: ${current_retry}"
            all_pods_up=1
            # Get the logs of the service installation container
            for POD_NAME in $(kubectl -n $LONGHORN_NS get pod | grep longhorn-${service}-installation | awk '{print $1}' || true); do
                LOGS=$(kubectl -n $LONGHORN_NS logs $POD_NAME -c ${service}-installation || true)
                if echo "$LOGS" | grep -q "${service} install successfully"; then
                    log -f ${CURRENT_FUNC} "Longhorn ${upper_service} installation successful in pod $POD_NAME"
                else
                    log -f ${CURRENT_FUNC} "Longhorn ${upper_service} installation failed or incomplete in pod $POD_NAME"
                    all_pods_up=0
                fi
            done

            if [ $all_pods_up -eq 1 ]; then
                break
            fi
            sleep 30
            if [ $current_retry -eq $max_retries ]; then
                log -f ${CURRENT_FUNC} "ERROR" "Reached maximum retry count: ${max_retries}. Exiting..."
                ERROR_RAISED=1
                break
            fi
        done
        kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml  >/dev/null 2>&1 || true
    done

    if [ $ERROR_RAISED -eq 1 ]; then
        exit 1
    fi
    log -f ${CURRENT_FUNC} "Finished installing NFS/iSCSI on the cluster."
    ##################################################################
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Checking if the containerd service is active for ${role} node: ${hostname}"
        ssh -q ${hostname} '
            if systemctl is-active --quiet iscsid; then
                echo "iscsi deployed successfully."
            else
                echo "iscsi service is not running..."
                exit 1
            fi
        '
        log -f ${CURRENT_FUNC} "Finished checking if the containerd service is active for ${role} node: ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Ensure kernel support for NFS v4.1/v4.2: for ${role} node: ${hostname}"
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
        log -f ${CURRENT_FUNC} "enabling iscsi_tcp & dm_crypt for ${role} node: ${hostname}"
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
        log -f ${CURRENT_FUNC} "Finished enabling iscsi_tcp & dm_crypt for ${role} node: ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Started installing Longhorn-cli for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            # set -e  # Exit on error
            # set -o pipefail  # Fail if any piped command fails
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
        log -f ${CURRENT_FUNC} "Finished installing Longhorn-cli for ${role} node: ${hostname}"

    done
    ##################################################################
    log -f ${CURRENT_FUNC} "Running the environment check script on the cluster..."
    url=https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/scripts/environment_check.sh

    if curl --output /dev/null --silent --head --fail $url; then
        curl -sSfL -o /tmp/environment_check.sh ${url}
        sudo chmod +x /tmp/environment_check.sh

        OUTPUT=$(/tmp/environment_check.sh)

        # Print the output
        log -f ${CURRENT_FUNC} "$OUTPUT"
        # Check for errors in the output
        if echo "$OUTPUT" | grep -q '\[ERROR\]'; then
            log -f ${CURRENT_FUNC} "ERROR" "Errors found in the environment check:"
            echo "$OUTPUT" | grep '\[ERROR\]'
            exit
        else
            log -f ${CURRENT_FUNC} "No errors found in the environment check."
        fi
    else
        log -f ${CURRENT_FUNC} "ERROR" "failed to download environment_check from url: ${url}"
        exit 1
    fi
    log -f ${CURRENT_FUNC} "Finished Running the environment check script on the cluster..."
    ##################################################################
    ##################################################################
    log -f ${CURRENT_FUNC} "Check the prerequisites and configurations for Longhorn:"
    log -f ${CURRENT_FUNC} "currently preflight doesnt support almalinux"
    #  so if on almalinx; run os-camo o, alll nodes prior to check preflight
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')

        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')
        log -f ${CURRENT_FUNC} "sending camo script to target node: ${hostname}"
        scp -q ./longhorn/os-camo.sh ${hostname}:/tmp/
        log -f ${CURRENT_FUNC} "Executing camofoulage for ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo chmod +x /tmp/os-camo.sh
            /tmp/os-camo.sh camo
        """
    done
    ##################################################################
    OUTPUT=$(longhornctl check preflight 2>&1)
    log -f ${CURRENT_FUNC} "Started checking the longhorn preflight pre installation"
    kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer  >/dev/null 2>&1 || true
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        log -f ${CURRENT_FUNC} "ERROR" "Errors found in the environment check:"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        log -f ${CURRENT_FUNC} "No errors found during the longhornctl preflight environment check."
    fi
    log -f ${CURRENT_FUNC} "Finished checking the preflight of longhorn"
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing the preflight of longhorn"
    OUTPUT=$(longhornctl install preflight 2>&1)
    kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer  >/dev/null 2>&1 || true
    # Print the output
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        log -f ${CURRENT_FUNC} "ERROR" "Errors found during the in longhornctl install preflight"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        log -f ${CURRENT_FUNC} "No errors found in the environment check."
    fi
    log -f ${CURRENT_FUNC} "Finished installing the preflight of longhorn"
    ##################################################################
    # check the preflight again after install:
    log -f ${CURRENT_FUNC} "Started checking the longhorn preflight post installation"
    OUTPUT=$(longhornctl check preflight 2>&1)
    kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer >/dev/null 2>&1 || true
    # Print the output
    # Check for errors in the output
    if echo "$OUTPUT" | grep -q 'level\=error'; then
        log -f ${CURRENT_FUNC} "ERROR" "Errors found in the environment check:"
        echo "$OUTPUT" | grep 'level\=error'
        exit 1
    else
        log -f ${CURRENT_FUNC} "No errors found during the longhornctl preflight environment check."
    fi
    log -f ${CURRENT_FUNC} "Finished checking the longhorn preflight post installation"
    ##################################################################
    # revert camo:
    echo "$CLUSTER_NODES" | jq -c '.[]' | while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "Resetting camofoulage for ${role} node: ${hostname}"
        ssh -q ${hostname} /tmp/os-camo.sh revert
    done
    #################################################################
    log -f ${CURRENT_FUNC} "Finished installing required utilities for longhorn"
}


# create_namespace() {
#     local namespace=$1
#     local max_retries=5
#     local attempt=1

#     while [ $attempt -le $max_retries ]; do
#         kubectl create ns "$namespace" ${VERBOSE}
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
    log -f ${CURRENT_FUNC} "Started deploying longhorn in ns $LONGHORN_NS"
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
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install Longhorn:\n\t${output}"
        exit 1
    fi


    echo end of test
    exit 1
    log -f ${CURRENT_FUNC} "Finished deploying longhorn in ns $LONGHORN_NS"
    ##################################################################
    # Wait for the pods to be running
    log -f ${CURRENT_FUNC} "Waiting for Longhorn pods to be running..."
    sleep 70  # approximate time for longhorn to boostrap
    current_retry=0
    max_retries=3
    while true; do
        current_retry=$((current_retry + 1))
        if [ $current_retry -gt $max_retries ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Reached maximum retry count. Exiting."
            exit 1
        fi
        log -f ${CURRENT_FUNC} "Checking Longhorn chart deployment completion... try N: $current_retry"
        PODS=$(kubectl -n $LONGHORN_NS get pods --no-headers | grep -v 'Running\|Completed' || true)
        if [ -z "$PODS" ]; then
            log -f ${CURRENT_FUNC} "All Longhorn pods are running."
            break
        else
            log -f ${CURRENT_FUNC} "Waiting for pods to be ready..."
        fi
        sleep 60
    done
    ##################################################################
    log -f ${CURRENT_FUNC} "Applying longhorn HTTPRoute for ingress."
    kubectl apply -f longhorn/http-routes.yaml
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished deploying Longhorn on the cluster."
}





        # --set server.dataStorage.mountPath="${EXTRAVOLUMES_ROOT}"/vault/data \
        # --set server.auditStorage.mountPath="${EXTRAVOLUMES_ROOT}"/vault/audit \

install_vault () {
    ##################################################################
    helm_chart_prerequisites "hashicorp" " https://helm.releases.hashicorp.com" "$VAULT_NS" "true" "true"
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing hashicorp vault Helm chart"
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
    # log -f ${CURRENT_FUNC} "adding rancher repo to helm"
    # helm repo add rancher-${RANCHER_BRANCH} https://releases.rancher.com/server-charts/${RANCHER_BRANCH} ${VERBOSE} || true
    # helm repo update ${VERBOSE} || true
    # ##################################################################
    # log -f ${CURRENT_FUNC} "uninstalling and ensuring the cluster is cleaned from rancher"
    # helm uninstall -n $RANCHER_NS rancher ${VERBOSE} || true
    # ##################################################################
    # log -f ${CURRENT_FUNC} "deleting rancher NS"
    # kubectl delete ns $RANCHER_NS --now=true & ${VERBOSE} || true

    # kubectl get namespace "${RANCHER_NS}" -o json \
    # | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
    # | kubectl replace --raw /api/v1/namespaces/${RANCHER_NS}/finalize -f - ${VERBOSE} || true
    # ##################################################################
    # log -f ${CURRENT_FUNC} "Creating rancher NS: '$RANCHER_NS'"
    # kubectl create ns $RANCHER_NS ${VERBOSE} || true
    ##################################################################
    log -f ${CURRENT_FUNC} "WARNING" "Warning: Currently rancher supports kubeVersion up to 1.31.0"
    log -f ${CURRENT_FUNC} "WARNING" "initiating workaround to force the install..."

    DEVEL=""
    if [ ${RANCHER_BRANCH} == "alpha" ]; then
        log -f ${CURRENT_FUNC} "WARNING" "Deploying rancher from alpha branch..."
        DEVEL="--devel"
    fi
    # helm install rancher rancher-${RANCHER_BRANCH}/rancher \
    # helm install rancher ./rancher/rancher-${RANCHER_VERSION}.tar.gz \


    log -f ${CURRENT_FUNC} "Started deploying rancher on the cluster"
    eval """
        helm install rancher rancher-${RANCHER_BRANCH}/rancher ${DEVEL} \
        --version ${RANCHER_VERSION}  \
        --namespace ${RANCHER_NS} \
        --set hostname=${RANCHER_FQDN} \
        --set bootstrapPassword=${RANCHER_ADMIN_PASS}  \
        --set replicas=${REPLICAS} \
        -f rancher/values.yaml ${VERBOSE} \
        ${VERBOSE}
    """
    # kubectl -n $RANCHER_NS rollout status deploy/rancher
    log -f ${CURRENT_FUNC} "Finished deploying rancher on the cluster"

    admin_url="https://rancher.pfs.pack/dashboard/?setup=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}')"
    log -f ${CURRENT_FUNC} "Access the admin panel at: $admin_url"

    admin_password=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}{{ "\n" }}')
    log -f ${CURRENT_FUNC} "Admin bootstrap password is: ${admin_password}"
    ##################################################################
    log -f ${CURRENT_FUNC} "Applying rancher HTTPRoute for ingress."
    kubectl apply -f rancher/http-routes.yaml
    ##################################################################
    sleep 150
    log -f ${CURRENT_FUNC} "Removing completed pods"
    kubectl delete pods -n ${RANCHER_NS} --field-selector=status.phase=Succeeded
    ##################################################################
    log -f ${CURRENT_FUNC} "Rancher installation completed."

}






#################################################################
if [ $RESET_CLUSTER_ARG -eq 1 ]; then
    reset_cluster
fi
#################################################################
if [ "$PREREQUISITES" = true ]; then
    #################################################################
    deploy_hostsfile
    if [ $? -ne 0 ]; then
        log -f "main" "ERROR" "An error occured while updating the hosts files."
        exit 1
    fi
    #################################################################
    prerequisites_requirements
    if [ $? -ne 0 ]; then
        log -f "main" "ERROR" "Failed the prerequisites requirements for the cluster installation."
        exit 1
    fi
    #################################################################
    install_kubetools
    if [ $? -ne 0 ]; then
        log -f "main" "ERROR" "Failed to install kuberenetes required tools for cluster deployment."
    fi
    #################################################################
else
    log "deploy.sh" "INFO" "Cluster prerequisites have been skipped"
fi
#################################################################
install_cluster
if [ $? -ne 0 ]; then
    log -f main "ERROR" "An error occurred while deploying the cluster"
    exit 1
fi
#################################################################
install_gateway_CRDS
if [ $? -ne 0 ]; then
    log -f main "ERROR" "An error occurred while deploying gateway CRDS"
    exit 1
fi
#################################################################
install_cilium_prerequisites
if [ $? -ne 0 ]; then
    log -f main "ERROR" "An error occurred while installing cilium prerequisites"
    exit 1
fi
#################################################################
install_cilium
if [ $? -ne 0 ]; then
    log -f main "ERROR" "An error occurred while installing cilium"
    exit 1
fi
#################################################################
join_cluster
#################################################################
install_gateway
install_gateway_return_code=$?
if [ $? -ne 0 ]; then
    log -f "main" "ERROR" "Failed to deploy ingress gateway API on the cluster, services might be unreachable..."
    exit 1
fi
##################################################################
restart_cilium
if [ $? -ne 0 ]; then
    log -f "main" "ERROR" "Failed to start cilium service."
    exit 1
fi
##################################################################
install_certmanager_prerequisites

install_certmanager
if [ $? -ne 0 ]; then
    log -f "main" "ERROR" "Failed to deploy cert_manager on the cluster, services might be unreachable due to faulty TLS..."
    exit 1
fi
##################################################################
# TODO, status checks and tests
install_rancher

install_longhorn_prerequisites
install_longhorn

install_vault

log "deploy.sh" "INFO" "deployment finished"


# ./deploy.sh --control-plane-hostname lorionstrm02vel --nodes-file hosts_file.yaml --with-prerequisites



#  2>&1 || true
################################################################################################################################################################
# in dev:
# TODO: print default values of helm charts:
# helm show values cilium/cilium > cilium/default-values.yaml


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

