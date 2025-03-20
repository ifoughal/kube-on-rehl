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

################################################################################################################################################################
prerequisites_requirements_checks() {
    #########################################################################################
    echo Check if the groups exist with the specified GIDs
    for i in $(seq 1 "$NODES_COUNT"); do
        #####################################################################################
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}
        #####################################################################################
        echo starting gid and uid configuration for node: $CURRENT_NODE
        echo Check if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP
        ssh "${CURRENT_NODE}" """
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
            echo "Error occurred while configuring node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo Finsihed checking if the visudo entry is appended for SUDO_GROUP: $SUDO_GROUP
        #####################################################################################
        echo "Check if the groups exists with the specified GIDs for node: ${CURRENT_NODE}"
        ssh  ${CURRENT_NODE} """
            if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
                echo "'${SUDO_GROUP}' Group exists."
            else
                echo "'${SUDO_GROUP}' Group does not exist, creating..."
                echo "$SUDO_PASSWORD" | sudo -S groupadd ${SUDO_GROUP}
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished check if the groups exists with the specified GIDs for node: ${CURRENT_NODE}"
        #####################################################################################
        echo "Check if the user '${SUDO_USERNAME}' exists for node: ${CURRENT_NODE}"
        ssh  ${CURRENT_NODE} """
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
            echo "Error occurred while configuring node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished check if the user '${SUDO_USERNAME}' exists for node: ${CURRENT_NODE}"
        #####################################################################################
        if [ ! -z $SUDO_NEW_PASSWORD ]; then
            echo "setting password for user '${SUDO_USERNAME}' for node: ${CURRENT_NODE}"
            ssh  ${CURRENT_NODE} << EOF
echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $SUDO_USERNAME:$SUDO_NEW_PASSWORD | chpasswd"
EOF
            # Check if the SSH command failed
            if [ $? -ne 0 ]; then
                echo "Error occurred while configuring node ${CURRENT_NODE}. Exiting script."
                exit 1  # This will stop the script execution
            fi
            echo "Finished setting password for user '${SUDO_USERNAME}' for node: ${CURRENT_NODE}"
        fi
        #####################################################################################
        echo "Check if the kernel is recent enough for node: ${CURRENT_NODE}"
        ssh  ${CURRENT_NODE} """
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
            echo "Error occurred while configuring node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi
        echo "Finished installing kernet tools node: ${CURRENT_NODE}"

        #####################################################################################

        echo "Checking eBPF support for node: ${CURRENT_NODE}"
        ssh  ${CURRENT_NODE} """
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

            # Run bpftool feature check
            echo "Running bpftool feature check..."
            sudo bpftool feature
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            echo "Error occurred while configuring node ${CURRENT_NODE}. Exiting script."
            exit 1  # This will stop the script execution
        fi


    done




    # # Ensure that bpf is mounted
    # echo "Checking if bpf is mounted..."
    # mount_output=$(mount | grep /sys/fs/bpf)

    # if [[ -n "$mount_output" ]]; then
    #     echo "bpf is mounted: $mount_output"
    # else
    #     echo "bpf is not mounted. You may need to mount it manually."
    #     exit 1
    # fi
    # #################################################################
    # # Check if the groups exist with the specified GIDs
    # SUDO_GROUP=maintainers
    # if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
    #     echo "'${SUDO_GROUP}' Group exists."
    # else
    #     echo "'${SUDO_GROUP}' Group does not exist, creating..."
    #     sudo groupadd ${SUDO_GROUP}
    # fi

    # # Create the user and add to groups
    # # Check if the user exists
    # if id "$SUDO_USERNAME" &>/dev/null; then
    #     echo "User $SUDO_USERNAME exists."
    #     sudo usermod $SUDO_USERNAME -aG wheel,${SUDO_GROUP} -s /bin/bash -m -d /home/$SUDO_USERNAME

    # else
    #     echo "User $SUDO_USERNAME does not exist."
    #     sudo useradd $SUDO_USERNAME -G wheel,${SUDO_GROUP} -s /bin/bash -m
    # fi

    # # Set the password for the user
    # echo "$SUDO_USERNAME:$SUDO_USER_PASSWORD" | sudo chpasswd

    # # Append to visudo

    # # Check if the visudo entry is appended
    # if sudo grep -q "%$SUDO_GROUP       ALL=(ALL)       NOPASSWD:ALL" /etc/sudoers.d/10_sudo_users_groups; then
    #     echo "Visudo entry for $SUDO_GROUP is appended correctly."
    # else
    #     echo "Visudo entry for $SUDO_GROUP is not found."
    #     sudo bash -c "echo '%$SUDO_GROUP       ALL=(ALL)       NOPASSWD:ALL' >> /etc/sudoers.d/10_sudo_users_groups"
    # fi
    # #################################################################
    # # /etc/environment proxy:
    # # Call the function
    # update_path
    # #################################################################
    # # Disable swap space on All Nodes
    # sudo swapoff -a
    # sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab

    # #################################################################*
    # # Disable SELinux temporarily and modify config for persistence
    # if sudo setenforce 0 2>/dev/null; then
    #     echo "SELinux set to permissive mode temporarily."
    # else
    #     echo "Warning: Failed to set SELinux to permissive mode. It may already be disabled."
    # fi

    # if sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config; then
    #     echo "SELinux configuration updated."
    # else
    #     echo "Error: Failed to update SELinux configuration."
    #     exit 1
    # fi

    # if $(sestatus |grep -q "Current mode:                   permissive"); then
    #     echo SELinux set to permissive.
    # else
    #     echo ERROR, failed to set SELinux set to permissive.
    #     exit 1
    # fi
    # #################################################################*
    # update_firewall
    # #############################################################################
    # # bridge network
    # sudo echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/containerd.conf
    # sudo modprobe overlay
    # sudo modprobe br_netfilter

    # sudo echo -e "net.bridge.bridge-nf-call-iptables = 1\nnet.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-ip6tables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
    # sudo sysctl --system
    # #############################################################################
    # # install containerD
    # sudo dnf install -y yum-utils
    # sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    # sudo dnf install containerd.io -y
    # #############################################################################
    # # enable containerD NRI:
    # CONFIG_FILE="/etc/containerd/config.toml"

    # # Backup the original config file
    # cp -f -n $CONFIG_FILE "${CONFIG_FILE}.bak"

    # # Use sed to edit the config file
    # sudo sed -i '/\[plugins."io.containerd.nri.v1.nri"\]/,/^$/{
    #     s/disable = true/disable = false/
    #     s/disable_connections = true/disable_connections = false/
    #     s|plugin_config_path = ".*"|plugin_config_path = "/etc/nri/conf.d"|
    #     s|plugin_path = ".*"|plugin_path = "/opt/nri/plugins"|
    #     s|plugin_registration_timeout = ".*"|plugin_registration_timeout = "15s"|
    #     s|plugin_request_timeout = ".*"|plugin_request_timeout = "12s"|
    #     s|socket_path = ".*"|socket_path = "/var/run/nri/nri.sock"|
    # }' $CONFIG_FILE

    # sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
    # sudo chown -R root:root /etc/nri /opt/nri
    # #############################################################################
    # # install go:
    # install_go
    # #############################################################################
    # # install_helm
    # install_helm
    # #############################################################################
    # # configuration for containerd
    # configure_containerD
    # # containerd containerd.io 1.7.25 bcc810d6
}

################################################################################################################################################################






















################################################################################################################################################################
prerequisites_requirements_checks




