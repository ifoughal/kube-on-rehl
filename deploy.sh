#!/bin/bash
####################################################################
LONGHORN_LOGS="./logs/longhorn.log"
VAULT_LOGS=./logs/vault.log
CILIUM_LOGS=./logs/cilium.log
KUBEADMINIT_LOGS=./logs/kubeadm_init_errors.log
####################################################################
VERBOSE_LEVEL=0
####################################################################
# Initialize variables
DRY_RUN=false
PREREQUISITES=false
INVENTORY=inventory.yaml
HOSTSFILE_PATH="/etc/hosts"
SUDO_PASSWORD=
STRICT_HOSTKEYS=0
RESET_CLUSTER_ARG=0*
CLUSTER_NODES=
####################################################################
# Recommended kernel version
recommended_rehl_version="4.18"
####################################################################
# Recommended kernel
# reading .env file
. .env
####################################################################
# set -euo pipefail # Exit on error

####################################################################
# Parse command-line arguments manually (including --dry-run)
while [[ $# -gt 0 ]]; do
    case "$1" in
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
        -s|--strist-hostkeys)
            STRICT_HOSTKEYS=1
            shift
            ;;
        -p|--sudo-password)
            SUDO_PASSWORD="$2"
            shift 2
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

####################################################################
log -f "main" "Generating askpass script for sudo commands on the deployer..."
echo "echo ${SUDO_PASSWORD}" > ./askpass.sh
chmod +x ./askpass.sh
####################################################################
mkdir -p ./logs
####################################################################
sudo -A touch ${LONGHORN_LOGS}
sudo -A chmod 666 ${LONGHORN_LOGS}

sudo -A touch ${CILIUM_LOGS}
sudo -A chmod 666 ${CILIUM_LOGS}


sudo -A touch ${VAULT_LOGS}
sudo -A chmod 666 ${VAULT_LOGS}

sudo -A touch ${KUBEADMINIT_LOGS}
sudo -A chmod 666 ${KUBEADMINIT_LOGS}
####################################################################

sudo -A timedatectl set-ntp true > /dev/null 2>&1
sudo -A timedatectl set-timezone $TIMEZONE > /dev/null 2>&1
sudo -A timedatectl status > /dev/null 2>&1
####################################################################
# init log
sudo -A cp ./log /usr/local/bin/log
sudo -A chmod +x /usr/local/bin/log
####################################################################
# Validate that required arguments are provided
if [ -z "$INVENTORY" ]; then
    log -f "main" "ERROR" "Missing required arguments."
    log -f "main" "ERROR" "$0 --inventory <INVENTORY>  [--dry-run]"
    exit 1
fi

# Ensure the YAML file exists
if [ ! -f "$INVENTORY" ]; then
    log -f "main" "ERROR" "Error: inventory YAML file '$INVENTORY' not found."
    exit 1
fi
####################################################################
# import library function
. library.sh
####################################################################
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

####################################################################
log -f "main" "VERBOSE_LEVEL set to: $VERBOSE_LEVEL"
####################################################################

# ERROR CODES:
#   1xxx: cilium errors
#       1001: cilium status errors
#
##################################################################
debug_log=$(alias | grep -E "^alias debug_log=" | head -n 1)
##################################################################
log -f "main" "Appending sudoers entry for $SUDO_GROUP..."
if sudo -A grep -q "^%$SUDO_GROUP[[:space:]]\+ALL=(ALL)[[:space:]]\+NOPASSWD:ALL" /etc/sudoers.d/10_sudo_users_groups; then
    log -f "main" "Visudo entry for $SUDO_GROUP is appended correctly."
else
    log -f "main" "Visudo entry for $SUDO_GROUP is not found, appending..."
    sudo -A bash -c "echo %$SUDO_GROUP       ALL\=\(ALL\)       NOPASSWD\:ALL >> /etc/sudoers.d/10_sudo_users_groups"
fi
##################################################################
if command -v yq; then
    ####################################################################
    log -f "main" "Started loading inventory file: $INVENTORY"
    CLUSTER_NODES=$(yq e -o=json '.hosts' "$INVENTORY")
    log -f "main" "Finished loading inventory file: $INVENTORY"
    ####################################################################
fi
##################################################################


provision_deployer() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    # set -euo pipefail # Exit on error
    # Path to the YAML file
    # Extract the 'nodes' array from the YAML and process it with jq
    # yq '.nodes["control_plane_nodes"]' "$INVENTORY" | jq -r '.[] | "\(.ip) \(.hostname)"' | while read -r line; do
    ##################################################################
    log -f ${CURRENT_FUNC} "configuring almalinux repos."
    if [ "$RESET_REPOS" == "true" ]; then
        log -f ${CURRENT_FUNC} "Resetting repos to default."
        sudo rm -rf /etc/yum.repos.d/*
    fi
    export OS_VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    if [ -z "$OS_VERSION" ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to determine OS version."
        exit 1
    fi

    export ARCH=$(arch)
    envsubst < ./repos/almalinux.repo | sudo tee /etc/yum.repos.d/almalinux.repo 1> /dev/null
    sudo chown root:root /etc/yum.repos.d/*
    sudo chmod 644 /etc/yum.repos.d/*
    ####################################################################
    log -f ${CURRENT_FUNC} "configuring crypto policies for DNF SSL"
    eval "sudo update-crypto-policies --set DEFAULT ${VERBOSE}"
    ####################################################################
    log -f ${CURRENT_FUNC} "updating dnf packages to latest version"
    eval "sudo dnf update -y ${VERBOSE}"
    ####################################################################
    log -f ${CURRENT_FUNC} "upgrading dnf to latest version"
    eval "sudo dnf upgrade -y  ${VERBOSE}"
    ####################################################################
    log -f ${CURRENT_FUNC} "installing required packages to deploy the cluster"
    eval "sudo dnf install -y sshpass python3-pip yum-utils bash-completion git wget bind-utils net-tools lsof ${VERBOSE}"
    log -f ${CURRENT_FUNC} "Finished installing required packages to deploy the cluster"
    ####################################################################
    log -f ${CURRENT_FUNC} "Installing YQ for YAML parsing"
    sudo wget https://github.com/mikefarah/yq/releases/download/v4.45.1/yq_linux_amd64 -O /usr/local/bin/yq
    sudo chmod +x /usr/local/bin/yq

    # eval "sudo pip install yq > /dev/null 2>&1"
    ####################################################################
    log -f ${CURRENT_FUNC} "Started loading inventory file: $INVENTORY"
    CLUSTER_NODES=$(yq e -o=json '.hosts' "$INVENTORY")
    log -f ${CURRENT_FUNC} "Finished loading inventory file: $INVENTORY"
    ####################################################################
    # TODO: MUST BE DONE IN THE CONTROLL PLANE!
    # log -f "main" "WARNING" "TODO: MUST BE DONE IN THE CONTROLL PLANE!"
    # CONTROLPLANE_ADDRESS=$(eval ip -o -4 addr show $CONTROLPLANE_INGRESS_INTER | awk '{print $4}' | cut -d/ -f1)  # 192.168.66.129
    # CONTROLPLANE_SUBNET=$(echo $CONTROLPLANE_ADDRESS | awk -F. '{print $1"."$2"."$3".0/24"}')
    # log -f "main" "WARNING" "EO TODO: MUST BE DONE IN THE CONTROLL PLANE!"
    # #########################################################
    CONTROLPLANE_INGRESS_CLUSTER_INTER=$(echo "$CLUSTER_NODES" | yq e -o=json '.[] | select(.role == "control-plane-leader") | .ingress.cluster_interface' -)
    CONTROLPLANE_INGRESS_PUBLIC_INTER=$(echo "$CLUSTER_NODES" | yq e '.[] | select(.role == "control-plane-leader") | .ingress.public_interface' -)
    CONTROL_PLANE_API_PORT=$(echo "$CLUSTER_NODES" | yq e -o=json '.[] | select(.role == "control-plane-leader") | .API_PORT' -)
    #########################################################
}


deploy_hostsfile () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    hosts_updated=false
    local error_raised=0
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
    hosts_updated=false
    ##################################################################
    local CONFIG_FILE="$HOME/.ssh/config"
    local TARGET_CONFIG_FILE="\$HOME/.ssh/config"
    local TMP_CONFIG_FILE="${CONFIG_FILE}.tmp"
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        # TODO generate ssh config file for each node
        # Ensure config file exists
        touch "$CONFIG_FILE"
        # Define the block to insert/update
        SSH_BLOCK=$(cat <<EOF

Host $hostname
    HostName $ip
    User $SUDO_USERNAME
    IdentityFile ~/.ssh/id_rsa
    PasswordAuthentication no
    Port 22
EOF
        )
        ##################################################################
        # Extract current block (if exists)
        current_block=$(awk -v host="Host $hostname" '
            BEGIN { capture=0 }
            $0 ~ "^Host " {
                if ($0 == host) {
                    capture=1
                    block=$0 ORS
                    next
                } else {
                    capture=0
                }
            }
            capture { block=block $0 ORS }
            END { print block }
        ' "$CONFIG_FILE")
        #####################################################################################
        # Normalize SSH_BLOCK
        local normalized_ssh_block=$(echo "$SSH_BLOCK" | sed '/^\s*$/d' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Normalize current_block
        local normalized_current_block=$(echo "$current_block" | sed '/^\s*$/d' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        #####################################################################################
        if [[ -z "$current_block" ]]; then
            # New host — mark as update needed
            hosts_updated=true
            log -f $CURRENT_FUNC "New host detected: $hostname"
        elif [[ "$normalized_ssh_block" != "$normalized_current_block" ]]; then
            # Host exists but differs — mark as update needed
            hosts_updated=true
            echo SSH_BLOCK: $SSH_BLOCK
            echo current_block: $current_block

            log -f $CURRENT_FUNC "Host: $hostname already exists but differs, updating..."
        fi
        #####################################################################################
        # If the host exists, replace it
        if grep -q "Host $hostname" "$CONFIG_FILE"; then
            # Use awk to remove the old block
            awk -v host="Host $hostname" '
                BEGIN { skip=0 }
                $0 ~ "^Host " {
                    if ($0 == host) {
                        skip=1
                    } else {
                        skip=0
                    }
                }
                skip == 0 { print }
            ' "$CONFIG_FILE" > "$TMP_CONFIG_FILE"

            # Append the updated block
            printf "%s" "$SSH_BLOCK" >> "$TMP_CONFIG_FILE"
            mv "$TMP_CONFIG_FILE" "$CONFIG_FILE"
        else
            # Append new block
            printf "%s" "$SSH_BLOCK" >> "$CONFIG_FILE"
        fi
        #####################################################################################
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
            hosts_updated=true
        else
            debug_log -f ${CURRENT_FUNC} "Host already exists: $line"
        fi
        #####################################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    if [ "$hosts_updated" == true ]; then
        log -f ${CURRENT_FUNC} "SSH config file updated successfully. Relaunch terminal to apply changes."
        exit 0
    else
        log -f ${CURRENT_FUNC} "No changes made to SSH config file."
    fi
    #####################################################################################
    while read -r node; do
        #####################################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local port=$(echo "$node" | jq -r '.port // 22')
        local role=$(echo "$node" | jq -r '.role')
        local user=$(echo "$node" | jq -r '.user')
        local password=$(echo "$node" | jq -r '.password')
        #####################################################################################
        log -f ${CURRENT_FUNC} "Started configuring HTTP/HTTPS Proxy for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            echo '''
                export http_proxy=\"$HTTP_PROXY\"
                export HTTP_PROXY=\"$HTTP_PROXY\"

                export https_proxy=\"$HTTPS_PROXY\"
                export HTTPS_PROXY=\"$HTTPS_PROXY\"

                export no_proxy=\"$no_proxy\"
                export NO_PROXY=\"$no_proxy\"
            ''' | sudo tee /etc/profile.d/proxy.sh > /dev/null

            echo '''
                export http_proxy=\"$HTTP_PROXY\"
                export HTTP_PROXY=\"$HTTP_PROXY\"

                export https_proxy=\"$HTTPS_PROXY\"
                export HTTPS_PROXY=\"$HTTPS_PROXY\"

                export no_proxy=\"$no_proxy\"
                export NO_PROXY=\"$no_proxy\"
            ''' | sudo tee /etc/environment > /dev/null

            sudo sed -i 's/^[[:space:]]\+//' /etc/profile.d/proxy.sh
            sudo sed -i 's/^[[:space:]]\+//' /etc/environment

        """
        ####################################################################################
        # export keys to nodes:
        if [ $STRICT_HOSTKEYS -eq 0 ]; then
            # Remove any existing entry for the host
            ssh-keygen -R "[$ip]:$port" &>/dev/null
            ssh-keygen -R "[$hostname]" &>/dev/null

            log -f $CURRENT_FUNC "Adding SSH fingerprint for $hostname..."
            if ! ssh-keyscan -H "$hostname" >> ~/.ssh/known_hosts 2>/dev/null; then
                log -f $CURRENT_FUNC "ERROR" "Failed to add SSH fingerprint for $hostname."
                error_raised=1
                continue
            fi
            log -f $CURRENT_FUNC "Adding SSH fingerprint for $ip:$port..."
            if ! ssh-keyscan -p $port $ip >> ~/.ssh/known_hosts 2>/dev/null; then
                log -f $CURRENT_FUNC "ERROR" "Failed to add SSH fingerprint for $hostname."
                error_raised=1
                continue
            fi
        fi
        #####################################################################################
        # 1. Check if SSH key exists
        if [[ ! -f "${SSH_KEY}" || ! -f "${SSH_KEY}.pub" ]]; then
            log -f $CURRENT_FUNC "Generating 🔑 SSH key for $role node ${hostname}..."
            ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N "" -C "$USER@$CLUSTER_NAME"
        else
            log -f $CURRENT_FUNC "✅ SSH key already exists: ${SSH_KEY}"
        fi
        #####################################################################################
        log -f ${CURRENT_FUNC} "Exporting ssh-key to $role node ${hostname} using IP..."
        if ! sshpass -p "$password" ssh-copy-id -f -p "$port" -i "${SSH_KEY}.pub" "${user}@${ip}" >/dev/null 2>&1; then
            log -f $CURRENT_FUNC "ERROR" "Failed to copy ssh id for $hostname."
            error_raised=1
            continue
        fi
        log -f ${CURRENT_FUNC} "Exporting ssh-key to $role node ${hostname} using hostname..."
        if ! sshpass -p "$password" ssh-copy-id -f -i "${SSH_KEY}.pub" "$hostname" >/dev/null 2>&1; then
            log -f $CURRENT_FUNC "ERROR" "Failed to copy ssh id for $hostname."
            error_raised=1
            continue
        fi
        log -f ${CURRENT_FUNC} "Finished exporting ssh-key to $role node ${hostname}..."
        #####################################################################################
        log -f ${CURRENT_FUNC} "sending SSH config file to target $role node ${hostname}"
        # scp -q $CONFIG_FILE ${hostname}:/tmp
        output=$(scp -q "$CONFIG_FILE" "${hostname}:/tmp" 2>&1)
        if [ $? -ne 0 ]; then
            echo output: $output
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while sending SSH config file to node ${hostname}..."
            exit 1
            continue  # continue to next node and skip this one
        fi
        # Check if the output contains the SSH key scan prompt
        if echo "$output" | grep -q "The authenticity of host"; then
            echo "Error: SSH key scan prompt detected."
            return 1
        fi
        #####################################################################################
        log -f ${CURRENT_FUNC} "Started gid and uid visudo configuration for ${role} node ${hostname}"

        local log_prefix=$(date +"\033[0;32m%Y-%m-%d %H:%M:%S,%3N ")
        ssh -q ${hostname} <<< """
            bash -c '''
                if echo '$CLUSTER_SUDO_PASSWORD' | sudo -S grep -q \"^%$SUDO_GROUP[[:space:]]\\+ALL=(ALL)[[:space:]]\\+NOPASSWD:ALL\" /etc/sudoers.d/10_sudo_users_groups; then
                    echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - Visudo entry for $SUDO_GROUP is appended correctly.\" ${VERBOSE}
                else
                    echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - Visudo entry for $SUDO_GROUP is not found, appending...\" ${VERBOSE}
                    echo '$CLUSTER_SUDO_PASSWORD' | sudo -S bash -c \"\"\"echo %$SUDO_GROUP       ALL\=\\\(ALL\\\)       NOPASSWD\:ALL >> /etc/sudoers.d/10_sudo_users_groups \"\"\"
                fi
            '''
        """
        log -f ${CURRENT_FUNC} "Finished gid and uid visudo configuration for ${role} node ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Check if the groups exists with the specified GIDs for ${role} node ${hostname}"
        local log_prefix=$(date +"\033[0;32m%Y-%m-%d %H:%M:%S,%3N")
        ssh -q ${hostname} <<< """
            if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
                echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - '${SUDO_GROUP}' Group exists.\" ${VERBOSE}
            else
                echo -e \"$log_prefix - INFO - ${FUNCNAME[0]} - '${SUDO_GROUP}' Group does not exist, creating...\"  ${VERBOSE}
                echo "$SUDO_PASSWORD" | sudo -S groupadd ${SUDO_GROUP} 1> /dev/null
            fi
        """
        log -f ${CURRENT_FUNC} "Finished checking the sudoer groups with the specified GIDs for ${role} node ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Check if the user '${SUDO_USERNAME}' exists for ${role} node ${hostname}"
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
        log -f ${CURRENT_FUNC} "Finished check if the user '${SUDO_USERNAME}' exists for ${role} node ${hostname}"
        #####################################################################################
        if [ ! -z $SUDO_NEW_PASSWORD ]; then
            log -f ${CURRENT_FUNC} "setting password for user '${SUDO_USERNAME}' for ${role} node ${hostname}"
            ssh -q ${hostname} << EOF
echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $SUDO_USERNAME:$SUDO_NEW_PASSWORD | chpasswd"
EOF
            # Check if the SSH command failed
            if [ $? -ne 0 ]; then
                error_raised=1
                log -f ${CURRENT_FUNC} "ERROR" "Error occurred while setting new sudo password for node ${hostname}."
                continue  # continue to next node and skip this one
            fi
            log -f ${CURRENT_FUNC} "Finished setting password for user '${SUDO_USERNAME}' for ${role} node ${hostname}"
        fi
        #####################################################################################
        log -f ${CURRENT_FUNC} "Applying new SSH config for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo cp /tmp/config ${TARGET_CONFIG_FILE}
            sudo chown \$(id -u):\$(id -g) ${TARGET_CONFIG_FILE}
        """
        log -f ${CURRENT_FUNC} "Finished updating SSH config file for ${role} node ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "Setting hostname for '$role node': ${hostname}"
        ssh -q ${hostname} <<< """
            sudo hostnamectl set-hostname "$hostname"
            CURRENT_HOSTNAME=$(eval hostname)
        """
        log -f ${CURRENT_FUNC} "Finished setting hostname for '$role node': ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Deploying logger function for ${role} node ${hostname}"
        scp -q ./log $hostname:/tmp/
        ssh -q $hostname <<< """
            sudo mv /tmp/log /usr/local/bin/log
            sudo chmod +x /usr/local/bin/log
        """
        log -f ${CURRENT_FUNC} "Finished deploying logger function for ${role} node ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Configuring NTP for ${role} node ${hostname}"
        ssh -q $hostname <<< """
            sudo timedatectl set-ntp true > /dev/null 2>&1
            sudo timedatectl set-timezone $TIMEZONE > /dev/null 2>&1
            sudo timedatectl status > /dev/null 2>&1
        """
        #####################################################################################
        log -f ${CURRENT_FUNC} "Configuring repos for ${role} node ${hostname}"
        configure_repos $hostname $role "/etc/yum.repos.d/almalinux.repo"
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring repos for node ${hostname}..."
            continue  # continue to next node and skip this one
        else
            log -f ${CURRENT_FUNC} "repos configured successfully for ${role} node ${hostname}"
        fi
        ####################################################################################
        log -f ${CURRENT_FUNC} "Adjusting NTP with chrony ${role} node ${hostname}"
        ssh -q $hostname <<< """
            sudo dnf install -y chrony > /dev/null 2>&1
            sudo systemctl enable --now chronyd > /dev/null 2>&1
            sudo chronyc makestep > /dev/null 2>&1
        """
        ####################################################################################
        log -f ${CURRENT_FUNC} "Checking NTP sync for ${role} node ${hostname}"

        check_ntp_sync $hostname
        rc=$?
        log -f ${CURRENT_FUNC} "check_ntp_sync returned $rc"

        if [ $rc -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while checking NTP sync for node ${hostname}..."
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "NTP sync check passed for ${role} node ${hostname}"
        log -f ${CURRENT_FUNC} "Finished NTP sync for ${role} node ${hostname}"
        ###############################################################
        log -f ${CURRENT_FUNC} "installing tools for '$role node': ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf update -y  ${VERBOSE}
            sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools lsof ${VERBOSE}
        """
        log -f ${CURRENT_FUNC} "Finished installing tools node: ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "installing yq on '$role node': ${hostname}"
        scp -q /usr/local/bin/yq ${hostname}:/tmp
        ssh -q ${hostname} <<< """
            sudo mv /tmp/yq /usr/local/bin/yq
            sudo chmod +x /usr/local/bin/yq
        """
        log -f ${CURRENT_FUNC} "Finished installing yq on '$role node': ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "sending hosts file to target $role node: ${hostname}"
        scp -q $HOSTSFILE_PATH ${hostname}:/tmp
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while sending hosts file to node ${hostname}..."
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Applying changes for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo cp /tmp/hosts ${HOSTSFILE_PATH}
        """
        log -f ${CURRENT_FUNC} "Finished modifying hosts file for ${role} node ${hostname}"
        ##################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    if [ $error_raised -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished deploying hosts file"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the hosts file deployment"
    fi
}

reset_storage() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started reseting cluster storage"
    ##################################################################
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Reseting volumes for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo rm -rf "${EXTRAVOLUMES_ROOT}"/*
        """
        log -f ${CURRENT_FUNC} "finished reseting host persistent volumes mounts for ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished reseting cluster storage"
}


kill_services_by_port() {
    local current_host=$1
    shift
    local ports=("$@")

    # Check if the port is provided
    if [ -z "$ports" ]; then
        echo "No ports specified."
        return 1
    fi

    for port in $ports; do
        debug_log -f ${CURRENT_FUNC} "Killing processes using port $port on $current_host..."
        ssh -q "$current_host" "sudo lsof -t -i :$port | xargs -r sudo kill -9"
    done
}


reset_cluster () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started reseting cluster"
    ##################################################################
    log -f ${CURRENT_FUNC} "Started uninstalling Cilium from cluster..."
    eval "sudo cilium uninstall --timeout 30 > /dev/null 2>&1" || true

    kubectl delete crds -l app.kubernetes.io/part-of=cilium > /dev/null 2>&1
    kubectl delete validatingwebhookconfigurations cilium-operator > /dev/null 2>&1
    kubectl -n kube-system delete deployment -l k8s-app=cilium-operator > /dev/null 2>&1

    log -f ${CURRENT_FUNC} "Finished uninstalling Cilium from cluster..."
    ##################################################################
    error_raised=0
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Started resetting k8s ${role} node node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo swapoff -a

            log -f ${CURRENT_FUNC} \"Uninstalling Cilium from node ${hostname}\"
            cilium uninstall --wait ${VERBOSE}
            kubectl delete crds -l app.kubernetes.io/part-of=cilium ${VERBOSE}
            kubectl delete validatingwebhookconfigurations cilium-operator ${VERBOSE}

            log -f ${CURRENT_FUNC} \"Reseting kubeadm on node ${hostname}\"
            if command -v kubeadm &> /dev/null; then
                output=\$(sudo kubeadm reset -f 2>&1 )
                if [ \$? -ne 0 ]; then
                    log -f ${CURRENT_FUNC} 'WARNING' \"Error occurred while resetting k8s node ${hostname}...\n\$(printf \"%s\n\" \"\$output\")\"
                elif echo \"\$output\" | grep -qi 'failed\|error'; then
                    log -f ${CURRENT_FUNC} 'WARNING' \"Error occurred while resetting k8s node ${hostname}...\n\$(printf \"%s\n\" \"\$output\")\"
                fi
                echo output: \$output
            fi


            log -f ${CURRENT_FUNC} \"Removing kubernetes hanging pods and containers\"
            for id in \$(sudo crictl pods -q 2>&1); do
                sudo crictl stopp \"\$id\" > /dev/null 2>&1
                sudo crictl rmp \"\$id\" > /dev/null 2>&1
            done

            sudo crictl rm -fa > /dev/null 2>&1 # remove all containers
            sudo crictl rmp -a > /dev/null 2>&1  # remove all pods
            sudo crictl rmi -a > /dev/null 2>&1  # remove all images

            log -f ${CURRENT_FUNC} \"Stopping containerd\"
            sudo systemctl stop containerd > /dev/null 2>&1

            log -f ${CURRENT_FUNC} \"Stopping kubelet\"
            sudo systemctl stop kubelet > /dev/null 2>&1


            log -f ${CURRENT_FUNC} \"removing cilium cgroupv2 mount and deleting cluster directories\"
            sudo umount /var/run/cilium/cgroupv2 > /dev/null 2>&1
            sudo rm -rf \
                \$HOME/.kube \
                /root/.kube \
                /etc/cni/net.d \
                /opt/cni \
                /etc/kubernetes \
                /var/lib/cni \
                /var/lib/kubelet \
                /var/run/kubernetes \
                /var/run/cilium \
                /etc/containerd \
                /var/run/nri \
                /opt/nri \
                /etc/nri \
                /opt/containerd \
                /run/containerd \
                /var/lib/containerd
            log -f ${CURRENT_FUNC} \"reloading systemd daemon and flushing iptables\"
            sudo systemctl daemon-reload
            sudo iptables -F
            sudo iptables -t nat -F
            sudo iptables -t mangle -F
            sudo iptables -X
        """
                # /var/lib/etcd \

        echo end of test
        exit 1

        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while resetting k8s ${role} node ${hostname}..."

            log -f ${CURRENT_FUNC} "Killing processes using kube ports on ${role} node ${hostname}..."
            kill_services_by_port "$hostname" 6443 2379 2380

            # ssh -q ${hostname} <<< """
            #     sudo swapoff -a

            #     for id in \$(sudo crictl pods -q 2>&1); do
            #         sudo crictl stopp \"\$id\" > /dev/null 2>&1
            #         sudo crictl rmp \"\$id\" > /dev/null 2>&1
            #     done
            #     sudo crictl rm -fa > /dev/null 2>&1 # remove all containers
            #     sudo crictl rmp -a > /dev/null 2>&1  # remove all pods
            #     sudo crictl rmi -a > /dev/null 2>&1  # remove all images

            #     sudo rm -rf \
            #         \$HOME/.kube \
            #         /root/.kube \
            #         /etc/cni/net.d \
            #         /opt/cni \
            #         /etc/kubernetes \
            #         /var/lib/etcd \
            #         /var/lib/cni \
            #         /var/lib/kubelet \
            #         /var/run/kubernetes \
            #         /var/run/cilium \
            #         /etc/containerd \
            #         /var/run/nri \
            #         /opt/nri \
            #         /etc/nri \
            #         /opt/containerd \
            #         /run/containerd \
            #         /var/lib/containerd



            #     sudo systemctl daemon-reload
            #     sudo iptables -F
            #     sudo iptables -t nat -F
            #     sudo iptables -t mangle -F
            #     sudo iptables -X
            # """
        fi
        log -f ${CURRENT_FUNC} "Finished resetting k8s ${role} node node: ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Removing prior installed versions of K8S for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes ${VERBOSE}
            sudo dnf remove -y containerd.io ${VERBOSE}

        """
        ##################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    if [ $error_raised -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished resetting cluster nodes"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the cluster nodes reset"
        return 1
    fi
    ##################################################################
}


# policycoreutils iproute  iptables
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
    while read -r node; do
       #####################################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        #####################################################################################
        log -f ${CURRENT_FUNC} "Starting dnf optimisations for ${role} node ${hostname}"
        optimize_dnf $hostname "${VERBOSE}"
        log -f ${CURRENT_FUNC} "Finished dnf optimisations for ${role} node ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Started checking if the kernel is recent enough for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            log -f kernel-version \"checking if the kernel is recent enough...\" ${VERBOSE}
            kernel_version=\$(uname -r)
            log -f kernel-version \"Kernel version: '\$kernel_version'\" ${VERBOSE}

            # Compare kernel versions
            if [[ \$(printf '%s\n' \"$recommended_rehl_version\" \"\$kernel_version\" | sort -V | head -n1) == \"$recommended_rehl_version\" ]]; then
                log -f kernel-version \"Kernel version is sufficient.\" ${VERBOSE}
            else
                log -f kernel-version \"ERROR\" \"${log_prefix_error} Kernel version is below the recommended version $recommended_rehl_version for ${role} node ${hostname}\"
                exit 1
            fi
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Kernel mismatch for ${role} node ${hostname}."
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Finished checking if the kernel is recent enough for ${role} node ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Checking eBPF support for ${role} node ${hostname}"
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
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred checking eBPF support for ${role} node ${hostname}"
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Finished checking eBPF support for ${role} node ${hostname}"
        #####################################################################################
        log -f ${CURRENT_FUNC} "Checking if bpf is mounted for ${role} node ${hostname}"
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
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred checking eBPF mount for ${role} node ${hostname}"
            continue # continue to next node...
        fi
        log -f ${CURRENT_FUNC} "Finished checking if bpf is mounted for ${role} node ${hostname}"
        ###################################################################################
        log -f $CURRENT_FUNC "Started updating env variables for ${role} node ${hostname}"
        update_path ${hostname}
        log -f $CURRENT_FUNC "Finished updating env variables for ${role} node ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "Started disabling swap for ${role} node ${hostname}"
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
        log -f ${CURRENT_FUNC} "Finished Disabling swap for ${role} node ${hostname}"
        ################################################################
        log -f ${CURRENT_FUNC} "Disable SELinux temporarily and modify config for persistence for ${role} node ${hostname}"
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
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring SELinux for for ${role} node ${hostname}"
            continue # continue to next node...
        fi
        log -f ${CURRENT_FUNC} "Finished disabling SELinux temporarily and modify config for persistence for ${role} node ${hostname}"
        ################################################################*
#         # TODO
#         # update_firewall $hostname
        ############################################################################
        log -f ${CURRENT_FUNC} "Configuring bridge network for ${role} node ${hostname}"
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
        log -f ${CURRENT_FUNC} "Finished configuring bridge network for ${role} node ${hostname}"
        ############################################################################
        log -f ${CURRENT_FUNC} "Installing containerD for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            set -euo pipefail # Exit on error
            sudo dnf install -y yum-utils ${VERBOSE}
            sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo  ${VERBOSE}
            sudo dnf install containerd.io -y ${VERBOSE}
        """
        # Check if the SSH command failed
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occured while installing containerD for ${role} node ${hostname}"
            continue # continue to next node...
        fi
        log -f ${CURRENT_FUNC} "Finished installing containerD for ${role} node ${hostname}"
        ############################################################################
        log -f ${CURRENT_FUNC} "Enabling containerD NRI with systemD and cgroups for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            set -euo pipefail # Exit on error

            CONFIG_FILE='/etc/containerd/config.toml'

            # Pause version mismatch:
            log -f ${CURRENT_FUNC} 'Resetting containerD config to default.' ${VERBOSE}
            containerd config default | sudo tee \$CONFIG_FILE >/dev/null

            log -f ${CURRENT_FUNC} 'Backing up the original config file' ${VERBOSE}
            sudo cp -f -n \$CONFIG_FILE \${CONFIG_FILE}.bak

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
            # sudo sed -i 's|sandbox_image = \"registry.k8s.io/pause:\"|sandbox_image = \"registry.k8s.io/pause:$PAUSE_VERSION\"|' \$CONFIG_FILE
            sudo sed -i 's|sandbox_image = \\\"registry.k8s.io/pause:[^\"]*\\\"|sandbox_image = \\\"registry.k8s.io/pause:$PAUSE_VERSION\\\"|' "\$CONFIG_FILE"

            # sudo sed -i 's|root = \"/var/lib/containerd\"|root = \"/mnt/longhorn-1/var/lib/containerd\"|' \$CONFIG_FILE

            sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
            sudo chown -R root:root /etc/nri /opt/nri

            log -f ${CURRENT_FUNC} 'Starting and enabling containerD' ${VERBOSE}
            sudo systemctl enable --now containerd > /dev/null 2>&1
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
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while enabling containerD NRI with systemD and cgroups for ${role} node ${hostname}"
            continue  # continue to next node and skip this one
        else
            log -f ${CURRENT_FUNC} "ContainerD NRI with systemD and cgroups enabled successfully for ${role} node ${hostname}"
        fi
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
        log -f ${CURRENT_FUNC} "Configuring containerd for ${role} node ${hostname}"
        configure_containerD $hostname $PAUSE_VERSION $SUDO_GROUP "$HTTP_PROXY" "$HTTPS_PROXY" "$NO_PROXY"
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring containerd for ${role} node ${hostname}"
            continue  # continue to next node and skip this one
        else
            log -f ${CURRENT_FUNC} "Containerd configured successfully for ${role} node ${hostname}"
        fi
        #############################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    #############################################################################
    if [ $error_raised -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished cluster prerequisites installation and checks"
        return 0
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the cluster prerequisites installation and checks"
        return 1
    fi
}


install_kubetools () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    local error_raised=0
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
    echo error_raised: $error_raised
    ##################################################################
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Removing prior installed versions for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes ${VERBOSE}
            sudo rm -rf /etc/kubernetes
        """
        ##################################################################
        log -f ${CURRENT_FUNC} "installing k8s tools for ${role} node ${hostname}"
        ssh -q ${hostname} bash -s <<< """
            set -euo pipefail  # Exit on error
            sudo dnf install -y kubelet-${K8S_MINOR_VERSION} kubeadm-${K8S_MINOR_VERSION} kubectl-${K8S_MINOR_VERSION} --disableexcludes=kubernetes ${VERBOSE}
            sudo systemctl enable --now kubelet > /dev/null 2>&1
        """
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while installing k8s tools for node ${hostname}..."
            continue  # continue to next node and skip this one
        fi
        ##################################################################
        log -f ${CURRENT_FUNC} "Adding Kubeadm bash completion"
        add_bashcompletion ${hostname} kubeadm $VERBOSE
        add_bashcompletion ${hostname} kubectl $VERBOSE
        ##################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    if [ $error_raised -eq 0 ]; then
       log -f ${CURRENT_FUNC} "Finished installing kubernetes tools"
    else
         log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the kubernetes tools installation"
         return 1
    fi
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
        KUBEADM_INIT_OUTPUT=\$(eval $KUBE_ADM_COMMAND  2>&1 || true)

        if echo \$(echo \"\$KUBEADM_INIT_OUTPUT\" | tr '[:upper:]' '[:lower:]') | grep 'error'; then
            log -f \"${CURRENT_FUNC}\" 'ERROR' \"\$KUBEADM_INIT_OUTPUT\"
            exit 1
        fi
        ####################################################################
        set -e  # Exit on error
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
    while read -r node; do
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
            sudo sysctl -w net.ipv4.conf.$CONTROLPLANE_INGRESS_INTER.rp_filter=2 ${VERBOSE}
            sudo sysctl -w net.ipv4.conf.${PUBLIC_INGRESS_INTER}.rp_filter=1 ${VERBOSE}

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
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
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
    log -f ${CURRENT_FUNC} "Started cilium helm chart prerequisites"
    helm_chart_prerequisites ${CONTROL_PLANE_HOST} "cilium" "https://helm.cilium.io" "$CILIUM_NS" "false" "false"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install cilium helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished cilium helm chart prerequisites"
    ##################################################################
    log -f ${CURRENT_FUNC} "Started installing cilium"
    #############################################################
    # > TODO HERE
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
            --set operator.replicas=1  \
            --set hubble.relay.replicas=1  \
            --set hubble.ui.replicas=1 \
            --set maglev.hashSeed="${HASH_SEED}"  \
            --set encryption.enabled=false \
            --set encryption.nodeEncryption=false \
            --set encryption.type=wireguard \
            --set cleanBpfState=false \
            --set cleanState=false \
            2>&1 || true)

        if echo \$OUTPUT | grep 'Error'; then
            log -f \"${CURRENT_FUNC}\" 'ERROR' \"Failed to deploy cilium \n\toutput:\n\t\$OUTPUT\"
            exit 1
        fi
        cilium install output=\$OUTPUT
        #############################################################
        sleep 30
        log -f \"${FUNCNAME[0]}\" 'Removing default cilium ingress.'
        kubectl delete svc -n kube-system cilium-ingress >/dev/null 2>&1 || true
        #############################################################
        log -f \"${FUNCNAME[0]}\" 'Apply LB IPAM on cluster'
        eval \"kubectl apply -f /tmp/loadbalancer-ip-pool.yaml ${VERBOSE}\"
        #############################################################
    """
    #############################################################
    if [ $? -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished deploying cilium."
    else
        return 1
    fi
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
    while read -r node; do
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

        log -f ${CURRENT_FUNC} "initiating cluster join for ${role} node ${hostname}"
        if [ $role == "worker" ]; then
            ssh -q ${hostname} <<< """
                eval sudo ${JOIN_COMMAND_WORKER} >/dev/null 2>&1 || true
            """
        elif [ $role == "control-plane-replica" ]; then
            ssh -q ${hostname} <<< """
                eval sudo ${JOIN_COMMAND_CONTROLPLANE} >/dev/null 2>&1 || true
            """
        fi
        log -f ${CURRENT_FUNC} "Finished joining cluster for ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################

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
                sleep 180
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
    while read -r node; do
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
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager CRDs from cluster"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/${CERTMANAGER_VERSION}/cert-manager.crds.yaml -n ${CERTMANAGER_NS} > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager CRDs from cluster"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete customresourcedefinitions.apiextensions.k8s.io -A \
            certificaterequests.cert-manager.io \
            certificates.cert-manager.io \
            clusterissuers.cert-manager.io \
            issuers.cert-manager.io \
            orders.acme.cert-manager.io \
            challenges.acme.cert-manager.io \
            > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager RBAC roles from cluster"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete ClusterRole -A \
            cert-manager-cluster-view \
            cert-manager-controller-approve:cert-manager-io \
            cert-manager-controller-certificates \
            cert-manager-controller-certificatesigningrequests \
            cert-manager-controller-challenges \
            cert-manager-controller-clusterissuers \
            cert-manager-controller-ingress-shim \
            cert-manager-controller-issuers \
            cert-manager-controller-orders \
            cert-manager-edit \
            cert-manager-view \
            cert-manager-webhook:subjectaccessreviews \
            > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager RBAC role bindings from cluster"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete ClusterRoleBinding -A \
            cert-manager-controller-approve:cert-manager-io \
            cert-manager-controller-certificates \
            cert-manager-controller-certificatesigningrequests \
            cert-manager-controller-challenges \
            cert-manager-controller-clusterissuers \
            cert-manager-controller-ingress-shim \
            cert-manager-controller-issuers \
            cert-manager-controller-orders \
            cert-manager-webhook:subjectaccessreviews \
            > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager roles from cluster"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete ClusterRole -A \
            cert-manager:leaderelection \
            > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager startup job from cluster"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete -n kube-system jobs.batch cert-manager-startupapicheck \
            > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "Finished installing cert-manager prerequisites"
}


verify_cert_manager_installation() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started testing cert-manager installation"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        TEST_MANIFEST=/tmp/certmanager/test-resources.yaml
        TEST_NS=cert-manager-test
        CERT_NAME=selfsigned-cert
        SECRET_NAME=selfsigned-cert-tls
        TIMEOUT=60

        log -f ${CURRENT_FUNC} 'Applying test certificate manifest...'
        output=\$(kubectl apply -f \${TEST_MANIFEST} 2>&1)
        if [[ \$? -ne 0 ]]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to apply test certificate manifest.\n\t\$output\"
            exit 1
        fi
        log -f ${CURRENT_FUNC} \"Waiting for certificate '\${CERT_NAME}' to become Ready in namespace '\${TEST_NS}'...\"

        end=\$((SECONDS + TIMEOUT))
        while true; do
            status=\$(kubectl get certificate \${CERT_NAME} -n \${TEST_NS} -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' || echo 'null')

            if [[ "\${status}" == \"True\" ]]; then
                log -f ${CURRENT_FUNC} '[✅] Certificate is Ready!'
                break
            fi

            if (( SECONDS >= end )); then
                log -f ${CURRENT_FUNC} 'ERROR' '[❌] Timeout waiting for certificate to be Ready.'
                exit 1
            fi

            echo -n '.'
            sleep 2
        done

        log -f ${CURRENT_FUNC} \"Verifying that the secret '\${SECRET_NAME}' exists...\"
        if kubectl get secret \${SECRET_NAME} -n \${TEST_NS} &>/dev/null; then
            log -f ${CURRENT_FUNC} \"[✅] Secret '\${SECRET_NAME}' found.\"
        else
            log -f ${CURRENT_FUNC} 'ERROR' \"[❌] Secret '\${SECRET_NAME}' not found.\"
            exit 1
        fi

        log -f ${CURRENT_FUNC} '[🎉] cert-manager is functioning correctly!'
    """
    ##################################################################
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished testing cert-manager installation"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to test cert-manager installation"
        return 1
    fi
    ##################################################################
}


install_certmanager () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started cert-manager helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "cert-manager" "https://charts.jetstack.io" "$CERTMANAGER_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install cert-manager helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished cert-manager helm chart prerequisites"
    ##################################################################
    log -f "$CURRENT_FUNC" "Sending certmanager values to control-plane node: ${CONTROL_PLANE_HOST}"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        # create tmp dir for certmanager
        rm -rf /tmp/certmanager &&  mkdir -p /tmp/certmanager
    """
    # scp -q ./certmanager/values.yaml $CONTROL_PLANE_HOST:/tmp/certmanager/
    ##################################################################
    log -f "$CURRENT_FUNC" "Sending certmanager test deployment to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./certmanager/test-resources.yaml $CONTROL_PLANE_HOST:/tmp/certmanager/
    ##################################################################
    log -f "${CURRENT_FUNC}" "Started installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    # TODO: --set http_proxy --set https_proxy --set no_proxy
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        output=\$(helm install cert-manager jetstack/cert-manager  \
            --version ${CERTMANAGER_VERSION} \
            --namespace ${CERTMANAGER_NS} \
            --set namespace=${CERTMANAGER_NS} \
            --set clusterResourceNamespace=${CERTMANAGER_NS} \
            --set global.leaderElection.namespace=${CERTMANAGER_NS} \
            --create-namespace \
            --set replicaCount=${REPLICAS} \
            --set podDisruptionBudget.enabled=true \
            --set webhook.replicaCount=${REPLICAS} \
            --set cainjector.replicaCount=${REPLICAS} \
            --set crds.enabled=true \
            --set crds.keep=true \
            ${VERBOSE} || true)
        # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install cert-manager:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install cert-manager"
        return 1
    fi
    ##################################################################
    # starting cert-manager test to ensure certs distribution
    verify_cert_manager_installation
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished cert-manager installation"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install cert-manager"
        return 1
    fi
}


install_longhorn_prerequisites() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    local error_raised=0
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Ensuring that 'noexec' is unset for '/var' for ${role} node '${hostname}'"
        ssh -q "${hostname}" <<< "
            set -euo pipefail
            # Backup the current /etc/fstab file
            sudo cp /etc/fstab /etc/fstab.bak

            # Remove 'noexec' from the mount options for /var only
            sudo sed -i \"s|\\(^/dev/[^[:space:]]\\+\\s\\+/var\\s\\+[^[:space:]]\\+\\s\\+[^[:space:]]*\\),noexec|\\1|\" /etc/fstab

            # Remount the /var filesystem to apply changes
            sudo mount -o remount /var
        "
        if [ ! $? -eq 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to ensure that 'noexec' is unset for '/var' for ${role} node ${hostname}"
            error_raised=1
            continue
        fi
        log -f ${CURRENT_FUNC} "Finished Ensuring that 'noexec' is unset for '/var' for ${role} node ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Installing required utility packages for longhorn on ${role} node: ${hostname}"
        ssh -q ${hostname} <<< """
            set -euo pipefail
            sudo dnf update -y ${VERBOSE}
            sudo dnf install curl jq nfs-utils cryptsetup \
                device-mapper iscsi-initiator-utils -y ${VERBOSE}
        """
        if [ ! $? -eq 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to install required utility packages for longhorn on ${role} node ${hostname}"
            error_raised=1
            continue
        fi
        log -f ${CURRENT_FUNC} "Finished installing required utility packages for longhorn on ${role} node: ${hostname}"
        ##################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    if [ $error_raised -eq 1 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to ensure prerequisites for one or multiple nodes..."
        return 1
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Started longhorn helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "longhorn" " https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install longhorn helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished longhorn helm chart prerequisites"
    #################################################################
    log -f ${CURRENT_FUNC} "Started NFS/iSCSI installation on the cluster"
    # REF: https://github.com/longhorn/longhorn/tree/master/deploy/prerequisite
    #
    ERROR_RAISED=0
    for service in "nfs" "iscsi"; do
        log -f ${CURRENT_FUNC} "Started installation of ${service} on all nodes"
        ssh -q ${CONTROL_PLANE_HOST} <<< """
            set -euo pipefail
            ########################################################################
            kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml -n $LONGHORN_NS >/dev/null 2>&1 || true
            ########################################################################
            upper_service=\$(echo ${service} | awk '{print toupper(\$0)}')
            TIMEOUT=180  # 3 minutes in seconds
            START_TIME=\$(date +%s)
            while true; do
                # Wait for the pods to be in Running state
                log -f ${CURRENT_FUNC} \"Waiting for Longhorn '\${upper_service}' installation pods to be in Running state...\"
                sleep 30
                log -f ${CURRENT_FUNC} 'Finished sleeping...'
                log -f ${CURRENT_FUNC} \"Getting pods from namespace: '${LONGHORN_NS}'\"
                PODS=\$(kubectl -n $LONGHORN_NS get pod 2>/dev/null || true)
                log -f ${CURRENT_FUNC} \"Finished getting pods from namespace: '${LONGHORN_NS}'\"

                if [ -z \"\$PODS\" ]; then
                    log -f ${CURRENT_FUNC} 'WARNING' \"No matching pods found for: 'longhorn-${service}-installation'\"
                    continue
                fi
                PODS=\$(echo \$PODS | grep longhorn-${service}-installation)
                RUNNING_COUNT=\$(echo \"\$PODS\" | grep -c 'Running')
                TOTAL_COUNT=\$(echo \"\$PODS\" | wc -l)

                log -f ${CURRENT_FUNC} \"Running Longhorn \${upper_service} install containers: \${RUNNING_COUNT}/\${TOTAL_COUNT}\"
                if [[ \$RUNNING_COUNT -eq \$TOTAL_COUNT ]]; then
                    break
                fi

                CURRENT_TIME=\$(date +%s)
                ELAPSED_TIME=\$((CURRENT_TIME - START_TIME))

                if [[ \$ELAPSED_TIME -ge \$TIMEOUT ]]; then
                    log -f ${CURRENT_FUNC} 'ERROR' \"Reached maximum retry count: \${max_retries} for service: ${service} Exiting...\"
                    exit 1
                fi
            done
            ########################################################################
            current_retry=0
            max_retries=3
            while true; do
                current_retry=\$((current_retry + 1))
                log -f ${CURRENT_FUNC} \"Checking Longhorn '\${upper_service}' setup completion... try N: \${current_retry}\"
                all_pods_up=1
                # Get the logs of the service installation container
                for POD_NAME in \$(kubectl -n $LONGHORN_NS get pod | grep longhorn-${service}-installation | awk '{print \$1}' || true); do
                    LOGS=\$(kubectl -n $LONGHORN_NS logs \$POD_NAME -c ${service}-installation || true)
                    if echo \"\$LOGS\" | grep -q \"${service} install successfully\"; then
                        log -f ${CURRENT_FUNC} \"Longhorn \${upper_service} installation successful in pod \$POD_NAME\"
                    else
                        log -f ${CURRENT_FUNC} \"Longhorn \${upper_service} installation failed or incomplete in pod \$POD_NAME\"
                        all_pods_up=0
                    fi
                done

                if [ \$all_pods_up -eq 1 ]; then
                    break
                fi
                sleep 30
                if [ \$current_retry -eq \$max_retries ]; then
                    log -f ${CURRENT_FUNC} \"ERROR\" \"Reached maximum retry count: \${max_retries} for service: ${service} Exiting...\"
                    exit 1
                fi
            done

            kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml  >/dev/null 2>&1 || true
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to install longhorn ${service} on the cluster."
            ERROR_RAISED=1
            continue
        fi
    done
    if [ $ERROR_RAISED -eq 1 ]; then
        for service in "nfs" "iscsi"; do
            ssh -q ${CONTROL_PLANE_HOST} <<< """
                kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml  >/dev/null 2>&1 || true
            """
        done
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished installing NFS/iSCSI on the cluster."
    ##################################################################
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Checking if the containerd service is active for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            set -euo pipefail
            if systemctl is-active --quiet iscsid; then
                log -f ${CURRENT_FUNC} 'iscsi deployed successfully.'
            else
                log -f ${CURRENT_FUNC} \"ERROR\" 'iscsi service is not running...'
                exit 1
            fi
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "iscsi service is not running on node: ${hostname}"
            return 1
        fi
        log -f ${CURRENT_FUNC} "Finished checking if the containerd service is active for ${role} node ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Ensure kernel support for NFS v4.1/v4.2: for ${role} node ${hostname}"
        ssh -q "${hostname}" <<< """
            error_raised=0
            for ver in 1 2; do
                if \$(cat /boot/config-\$(uname -r) | grep -q \"CONFIG_NFS_V4_\${ver}=y\"); then
                    log -f $CURRENT_FUNC \"NFS v4.\${ver} is supported\"
                else
                    log -f $CURRENT_FUNC 'ERROR' \"NFS v4.\${ver} is not supported\"
                    error_raised=1
                fi
            done
            exit \$error_raised
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "NFS v4.1/v4.2 is not supported on node: ${hostname}"
            return 1
        fi
        log -f ${CURRENT_FUNC} "Finished ensuring kernel support for NFS v4.1/v4.2: for ${role} node ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "enabling iscsi_tcp & dm_crypt for ${role} node ${hostname}"
        # Check if the module is already in the file
        ssh -q ${hostname} <<< """
            set -euo pipefail

            # Ensure the iscsi_tcp module loads automatically on boot
            MODULE_FILE='/etc/modules'
            MODULE_NAME='iscsi_tcp'

            if ! grep -q \"^\${MODULE_NAME}\$\" \${MODULE_FILE}; then
                echo \"\${MODULE_NAME}\" | sudo tee -a ${MODULE_FILE}
                log -f ${CURRENT_FUNC} \"Added \${MODULE_NAME} to \${MODULE_FILE}\"
            else
                log -f ${CURRENT_FUNC} \"\${MODULE_NAME} is already present in \${MODULE_FILE}\"
            fi

            # Load the iscsi_tcp module
            sudo modprobe iscsi_tcp
            log -f ${CURRENT_FUNC} \"Loaded \${MODULE_NAME} module\"

            # Enable dm_crypt
            sudo modprobe dm_crypt
            log -f ${CURRENT_FUNC} \"Loaded dm_crypt module\"
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to enable iscsi_tcp & dm_crypt for ${role} node ${hostname}"
            return 1
        fi
        log -f ${CURRENT_FUNC} "Finished enabling iscsi_tcp & dm_crypt for ${role} node ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Started installing Longhorn-cli for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            set -euo pipefail

            if command -v longhornctl &> /dev/null; then
                log -f ${CURRENT_FUNC} \"longhornctl not found. Installing on ${role} node ${hostname}\"
                CLI_ARCH=amd64
                if [ \"\$(uname -m)\" = 'aarch64' ]; then CLI_ARCH=arm64; fi
                cd /tmp

                url=https://github.com/longhorn/cli/releases/download/${LONGHORN_VERSION}/longhornctl-linux-\${CLI_ARCH}

                # Check if the URL exists
                if curl --output /dev/null --silent --head --fail \$url; then
                    log -f ${CURRENT_FUNC} \"Downloading longhornctl from source on ${role} node ${hostname}\"
                    curl -sSfL -o /tmp/longhornctl \${url}

                    sudo mv /tmp/longhornctl /usr/local/bin/

                    sudo chmod +x /usr/local/bin/longhornctl

                    sudo ln -sf /usr/local/bin/longhornctl /usr/bin
                    log -f ${CURRENT_FUNC} \"longhornctl installed successfully on ${role} node ${hostname}\"
                else
                    log -f ${CURRENT_FUNC} \"ERROR\" \"longhornctl not found. Installing on ${role} node ${hostname}\"
                    exit 1
                fi
            else
                log -f ${CURRENT_FUNC} \"longhornctl is already installed.\"
            fi
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to install Longhorn-cli for ${role} node ${hostname}"
            return 1
        fi
        log -f ${CURRENT_FUNC} "Finished installing Longhorn-cli for ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "Running the environment check script on the cluster..."
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        set -euo pipefail

        url=https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/scripts/environment_check.sh

        if curl --output /dev/null --silent --head --fail \$url; then
            curl -sSfL -o /tmp/environment_check.sh \${url}
            sudo chmod +x /tmp/environment_check.sh

            OUTPUT=\$(/tmp/environment_check.sh)

            # Check for errors in the output
            if echo \"\$OUTPUT\" | grep -q '\[ERROR\]'; then
                log -f ${CURRENT_FUNC} 'ERROR' \"Errors found in the longhorn cluster environment check:\n\t\$OUTPUT\" | grep '\[ERROR\]'
                exit 1
            else
                log -f ${CURRENT_FUNC} 'No errors found in the Longhorn cluster environment check.'
            fi
        else
            log -f ${CURRENT_FUNC} 'ERROR' \"failed to download environment_check from url: \${url}\"
            exit 1
        fi
        log -f ${CURRENT_FUNC} 'Finished Running the environment check script on the cluster...'
    """

    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} 'ERROR' 'Failed to run the environment check script on the cluster'
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished running the environment check script on the cluster..."
    ##################################################################
    log -f ${CURRENT_FUNC} "Check the prerequisites and configurations for Longhorn:"
    log -f ${CURRENT_FUNC} "currently preflight doesnt support almalinux"
    #  so if on almalinx; run os-camo o, alll nodes prior to check preflight
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "sending camo script to target node: ${hostname}"
        scp -q ./longhorn/os-camo.sh ${hostname}:/tmp/
        log -f ${CURRENT_FUNC} "Executing camofoulage for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo chmod +x /tmp/os-camo.sh
            /tmp/os-camo.sh camo
        """
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} 'Started checking the longhorn preflight pre installation'
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        export KUBERNETES_SERVICE_HOST=$CONTROL_PLANE_HOST
        export KUBERNETES_SERVICE_PORT=$CONTROLPLANE_API_PORT
        export KUBERNETES_MASTER=https://$CONTROL_PLANE_HOST:$CONTROLPLANE_API_PORT

        OUTPUT=\$(longhornctl check preflight global-options --kube-config=\$HOME/.kube/config 2>&1)

        kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer  >/dev/null 2>&1 || true

        # Check for errors in the output
        if echo \"\$OUTPUT\" | grep -q 'level\=error'; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Errors found in the environment check: \n\t\$OUTPUT\" | grep 'level\=error'
            exit 1
        else
            log -f ${CURRENT_FUNC} 'No errors found during the longhornctl preflight environment check.'
        fi
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to check the preflights of longhorn"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished checking the preflights of longhorn"
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing the preflight of longhorn"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        OUTPUT=\$(longhornctl install preflight global-options --kube-config=\$HOME/.kube/config 2>&1)
        kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer  >/dev/null 2>&1 || true
        # Check for errors in the output
        if echo \"\$OUTPUT\" | grep -q 'level\=error'; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Errors found during the in longhornctl install preflight \n\t\$OUTPUT\" | grep 'level\=error'
            exit 1
        else
            log -f ${CURRENT_FUNC} 'No errors found in the environment check.'
        fi
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install the preflights of longhorn"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished installing the preflights of longhorn"
    ##################################################################
    # check the preflight again after install:
    log -f ${CURRENT_FUNC} "Started checking the longhorn preflight post installation"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        OUTPUT=\$(longhornctl check preflight global-options --kube-config=\$HOME/.kube/config 2>&1)
        kubectl delete -n default ds/longhorn-preflight-checker ds/longhorn-preflight-installer >/dev/null 2>&1 || true
        if echo \"\$OUTPUT\" | grep -q 'level\=error'; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Errors found in the environment check: \n\t\$OUTPUT\" | grep 'level\=error'
            exit 1
        else
            log -f ${CURRENT_FUNC} 'No errors found during the longhornctl preflight environment check.'
        fi
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to check the longhorn preflight post installation"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished checking the longhorn preflight post installation"
    ##################################################################
    # revert camo:
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "Resetting camofoulage for ${role} node ${hostname}"
        ssh -q ${hostname} /tmp/os-camo.sh revert
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished installing required utilities for longhorn"
}


install_longhorn () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started longhorn helm chart prerequisites"
    helm_chart_prerequisites "${CONTROL_PLANE_HOST}" "longhorn" " https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install longhorn helm chart prerequisites"
        return 1
    fi

    log -f ${CURRENT_FUNC} "Finished longhorn helm chart prerequisites"
    #################################################################
    reset_storage
    # #################################################################
    # ssh -q ${CONTROL_PLANE_HOST} <<< """
    #     # create tmp dir for longhorn
    #     rm -rf /tmp/longhorn &&  mkdir -p /tmp/longhorn
    # """
    # #################################################################
    # log -f ${CURRENT_FUNC} "sending longhorn http-routes to control-plane node: ${CONTROL_PLANE_HOST}"
    # scp -q ./longhorn/http-routes.yaml $CONTROL_PLANE_HOST:/tmp/longhorn/
    # ##################################################################
    # log -f ${CURRENT_FUNC} "sending longhorn values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    # scp -q ./longhorn/values.yaml $CONTROL_PLANE_HOST:/tmp/longhorn/
    # ##################################################################
    # log -f "${CURRENT_FUNC}" "Started installing longhorn on namespace: '${LONGHORN_NS}'"
    # # TODO: --set http_proxy --set https_proxy --set no_proxy
    # ssh -q ${CONTROL_PLANE_HOST} <<< """
    #     output=\$(helm install longhorn longhorn/longhorn  \
    #         --namespace $LONGHORN_NS  \
    #         --version ${LONGHORN_VERSION} \
    #         -f /tmp/longhorn/values.yaml \
    #         --set persistence.defaultClassReplicaCount=${LONGHORN_REPLICAS} \
    #         --set csi.attacherReplicaCount=${LONGHORN_REPLICAS} \
    #         --set csi.provisionerReplicaCount=${LONGHORN_REPLICAS} \
    #         --set csi.resizerReplicaCount=${LONGHORN_REPLICAS} \
    #         --set csi.snapshotterReplicaCount=${LONGHORN_REPLICAS} \
    #         --set longhornUI.replicas=${LONGHORN_REPLICAS} \
    #         --set longhornConversionWebhook.replicas=${LONGHORN_REPLICAS} \
    #         --set longhornAdmissionWebhook.replicas=${LONGHORN_REPLICAS} \
    #         --set longhornRecoveryBackend.replicas=${LONGHORN_REPLICAS} \
    #         ${VERBOSE} || true)
    #     # Check if the Helm install command was successful
    #     if [ ! \$? -eq 0 ]; then
    #         log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install longhorn:\n\t\${output}\"
    #         exit 1
    #     fi
    # """
    # if [ $? -eq 0 ]; then
    #     log -f "${CURRENT_FUNC}" "Finished installing longhorn on namespace: '${LONGHORN_NS}'"
    # else
    #     log -f "${CURRENT_FUNC}" "ERROR" "Failed to install longhorn"
    #     return 1
    # fi
    # ##################################################################
    # # Wait for the pods to be running
    # log -f ${CURRENT_FUNC} "Waiting for Longhorn pods to be running..."
    # ssh -q ${CONTROL_PLANE_HOST} <<< """
    #     sleep 90  # approximate time for longhorn to boostrap
    #     current_retry=0
    #     max_retries=5
    #     sleep_time=30
    #     while true; do
    #         current_retry=\$((current_retry + 1))
    #         if [ \$current_retry -gt \$max_retries ]; then
    #             log -f ${CURRENT_FUNC} 'ERROR' 'Reached maximum retry count. Exiting.'
    #             exit 1
    #         fi
    #         log -f ${CURRENT_FUNC} \"Checking Longhorn chart deployment completion... try N: \$current_retry\"
    #         PODS=\$(kubectl -n $LONGHORN_NS get pods --no-headers | grep -v 'Running\|Completed' || true)
    #         if [ -z \"\$PODS\" ]; then
    #             log -f ${CURRENT_FUNC} 'All Longhorn pods are running.'
    #             exit 0
    #         else
    #             log -f ${CURRENT_FUNC} 'Waiting for pods to be ready...'
    #         fi
    #         sleep \$sleep_time
    #     done
    # """
    # if [ $? -ne 0 ]; then
    #     log -f ${CURRENT_FUNC} "ERROR" "longhorn pods are not running as expected"
    #     return 1
    # fi
    # ##################################################################
    # log -f ${CURRENT_FUNC} "Applying longhorn HTTP-Route for ingress."
    # ssh -q ${CONTROL_PLANE_HOST} <<< """
    #     eval \"kubectl apply -f /tmp/longhorn/http-routes.yaml ${VERBOSE}\"
    # """
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished deploying Longhorn on the cluster."
}


install_consul() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started consul helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "hashicorp" " https://helm.releases.hashicorp.com" "$CONSUL_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install consul helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished consul helm chart prerequisites"
    #################################################################
    log -f ${CURRENT_FUNC} "removing consul crds"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete crd --selector app=consul
    """
    #################################################################
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        # create tmp dir for longhorn
        rm -rf /tmp/consul &&  mkdir -p /tmp/consul
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending consul values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./consul/values.yaml $CONTROL_PLANE_HOST:/tmp/consul/
    ##################################################################
    # log -f ${CURRENT_FUNC} "sending consul http-routes.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    # scp -q ./consul/http-routes.yaml $CONTROL_PLANE_HOST:/tmp/consul/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing hashicorp consul Helm chart"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        output=\$(helm install consul hashicorp/consul \
            --namespace $CONSUL_NS \
            --create-namespace \
            --version $CONSUL_VERSION \
            -f /tmp/consul/values.yaml \
            ${VERBOSE} || true)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install consul:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing consul on namespace: '${CONSUL_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install consul"
        return 1
    fi
    ##################################################################
    # log -f ${CURRENT_FUNC} "applying http-routes for vault ingress"
    # ssh -q ${CONTROL_PLANE_HOST} <<< """
    #     kubectl apply -f /tmp/vault/http-routes.yaml ${VERBOSE}
    # """
}


install_vault () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started vault helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "hashicorp" " https://helm.releases.hashicorp.com" "$VAULT_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install vault helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished vault helm chart prerequisites"
    #################################################################
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        # create tmp dir for longhorn
        rm -rf /tmp/vault &&  mkdir -p /tmp/vault
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending vault values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./vault/values.yaml $CONTROL_PLANE_HOST:/tmp/vault/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending vault http-routes.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./vault/http-routes.yaml $CONTROL_PLANE_HOST:/tmp/vault/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing hashicorp vault Helm chart"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        output=\$(helm install vault hashicorp/vault \
            --namespace $VAULT_NS \
            --create-namespace \
            --version $VAULT_VERSION \
            -f /tmp/vault/values.yaml \
            ${VERBOSE} || true)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install vault:\n\t\${output}\"
            exit 1
        fi
        echo \$output
    """
    # -- set server.dev.enabled=true \

    #
    # --set injector.replicas=1 \
    # --set server.ha.replicas=1 \
    # ${REPLICAS}
    # --set server.dataStorage.mountPath="${EXTRAVOLUMES_ROOT}"/vault/data \
    # --set server.auditStorage.mountPath="${EXTRAVOLUMES_ROOT}"/vault/audit \
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing vault on namespace: '${VAULT_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install vault"
        return 1
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "applying http-routes for vault ingress"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl apply -f /tmp/vault/http-routes.yaml ${VERBOSE}
    """
}



install_rancher () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started rancher-${RANCHER_BRANCH} helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "rancher-${RANCHER_BRANCH}" "https://releases.rancher.com/server-charts/${RANCHER_BRANCH}" "$RANCHER_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install rancher-${RANCHER_BRANCH} helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished rancher-${RANCHER_BRANCH} helm chart prerequisites"
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
    # log -f ${CURRENT_FUNC} "WARNING" "Warning: Currently rancher supports kubeVersion up to 1.31.0"
    # log -f ${CURRENT_FUNC} "WARNING" "initiating workaround to force the install..."

    # DEVEL=""
    # if [ ${RANCHER_BRANCH} == "alpha" ]; then
    #     log -f ${CURRENT_FUNC} "WARNING" "Deploying rancher from alpha branch..."
    #     DEVEL="--devel"
    # fi
    # # helm install rancher rancher-${RANCHER_BRANCH}/rancher \
    # # helm install rancher ./rancher/rancher-${RANCHER_VERSION}.tar.gz \


    # log -f ${CURRENT_FUNC} "Started deploying rancher on the cluster"
    # eval """
    #     helm install rancher rancher-${RANCHER_BRANCH}/rancher ${DEVEL} \
    #     --version ${RANCHER_VERSION}  \
    #     --namespace ${RANCHER_NS} \
    #     --set hostname=${RANCHER_FQDN} \
    #     --set bootstrapPassword=${RANCHER_ADMIN_PASS}  \
    #     --set replicas=${REPLICAS} \
    #     -f rancher/values.yaml ${VERBOSE} \
    #     ${VERBOSE}
    # """
    # # kubectl -n $RANCHER_NS rollout status deploy/rancher
    # log -f ${CURRENT_FUNC} "Finished deploying rancher on the cluster"

    # admin_url="https://rancher.pfs.pack/dashboard/?setup=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}')"
    # log -f ${CURRENT_FUNC} "Access the admin panel at: $admin_url"

    # admin_password=$(kubectl get secret --namespace ${RANCHER_NS} bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}{{ "\n" }}')
    # log -f ${CURRENT_FUNC} "Admin bootstrap password is: ${admin_password}"
    # ##################################################################
    # log -f ${CURRENT_FUNC} "Applying rancher HTTPRoute for ingress."
    # kubectl apply -f rancher/http-routes.yaml
    # ##################################################################
    # sleep 150
    # log -f ${CURRENT_FUNC} "Removing completed pods"
    # kubectl delete pods -n ${RANCHER_NS} --field-selector=status.phase=Succeeded
    # ##################################################################
    log -f ${CURRENT_FUNC} "Rancher installation completed."

}


install_cephrook(){
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="rook-ceph"
    local chart_url="https://charts.rook.io/release"
    ###################################################################
    log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "${chart_name}" "${chart_url}" "$ROOKCEPH_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        rm -rf /tmp/${chart_name} &&  mkdir -p /tmp/${chart_name}
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending ${chart_name} values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./${chart_name}/values.yaml $CONTROL_PLANE_HOST:/tmp/${chart_name}/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing ${chart_name} Helm chart"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        output=\$(helm install ${chart_name} ${chart_name}/${chart_name} \
            --namespace $ROOKCEPH_NS \
            --create-namespace \
            --version $ROOKCEPH_VERSION \
            -f /tmp/${chart_name}/values.yaml \
            > /dev/null 2>&1 )
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install ${chart_name}:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing ${chart_name} on namespace: '${ROOKCEPH_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install ${chart_name}"
        return 1
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished deploying ${chart_name} on the cluster."

}


# deploy_helm_chart(){
#     log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
#     helm_chart_prerequisites "$CONTROL_PLANE_HOST" "${chart_name}" "${chart_url}" "$ROOKCEPH_NS" "false" "false"
#     if [ $? -ne 0 ]; then
#         log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
#         return 1
#     fi
#     log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
#     ##################################################################
#     ssh -q ${CONTROL_PLANE_HOST} <<< """
#         rm -rf /tmp/${chart_name} &&  mkdir -p /tmp/${chart_name}
#     """
#     ##################################################################
#     log -f ${CURRENT_FUNC} "sending ${chart_name} values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
#     scp -q ./${chart_name}/values.yaml $CONTROL_PLANE_HOST:/tmp/${chart_name}/
#     ##################################################################
#     log -f ${CURRENT_FUNC} "Installing ${chart_name} cluster Helm chart"
#     ssh -q ${CONTROL_PLANE_HOST} <<< """
#         output=\$(helm install ${chart_name} ${chart_name}/${chart_name} \
#             --namespace $ROOKCEPH_NS \
#             --create-namespace \
#             --set operatorNamespace=$ROOKCEPH_NS \
#             --version $ROOKCEPH_VERSION \
#             -f /tmp/${chart_name}/values.yaml \
#             >/dev/null 2>&1)
#         echo output: \$output
#         if [ ! \$? -eq 0 ]; then
#             log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install ${chart_name}:\n\t\$(printf \"%s\n\" \"\$output\")\"
#             exit 1
#         fi
#         echo \$output
#     """
#     if [ $? -eq 0 ]; then
#         log -f "${CURRENT_FUNC}" "Finished installing ${chart_name} on namespace: '${ROOKCEPH_NS}'"
#     else
#         log -f "${CURRENT_FUNC}" "ERROR" "Failed to install ${chart_name}"
#         return 1
#     fi
#     ##################################################################
# }


install_cephrook_cluster(){
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="rook-ceph-cluster"
    local chart_url="https://charts.rook.io/release"
    log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "${chart_name}" "${chart_url}" "$ROOKCEPH_NS" "false" "false"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        rm -rf /tmp/${chart_name} &&  mkdir -p /tmp/${chart_name}
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending ${chart_name} values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./${chart_name}/values.yaml $CONTROL_PLANE_HOST:/tmp/${chart_name}/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing ${chart_name} cluster Helm chart"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        output=\$(helm install ${chart_name} ${chart_name}/${chart_name} \
            --namespace $ROOKCEPH_NS \
            --create-namespace \
            --set operatorNamespace=$ROOKCEPH_NS \
            --version $ROOKCEPH_VERSION \
            -f /tmp/${chart_name}/values.yaml \
            >/dev/null 2>&1 )
        echo output: \$output
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install ${chart_name}:\n\t\$(printf \"%s\n\" \"\$output\")\"
            exit 1
        fi
        echo \$output
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing ${chart_name} on namespace: '${ROOKCEPH_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install ${chart_name}"
        return 1
    fi
    ##################################################################
    log -f "${CURRENT_FUNC}" "⏳ Waiting for CephCluster to be ready..."
    ssh -q "${CONTROL_PLANE_HOST}" <<< """
        TIMEOUT=600   # seconds
        SLEEP_INTERVAL=10
        ELAPSED=0
        while [[ \$ELAPSED -lt \$TIMEOUT ]]; do

            STATUS=\$(kubectl get cephcluster rook-ceph \
                    --namespace \"${ROOKCEPH_NS}\" \
                    -o json | jq -r '.status?.phase // \"Pending\"')

            log -f \"${CURRENT_FUNC}\" \"🌀 Current status: \$STATUS\"

            if [[ \"\$STATUS\" == 'Ready' ]]; then
                log -f \"${CURRENT_FUNC}\" '✅ CephCluster is Ready!'
                exit 0
            elif [[ \"\$STATUS\" == 'Error' ]]; then
                log -f \"${CURRENT_FUNC}\" 'ERROR' '❌ CephCluster entered Error state.'
                exit 1
            fi

            sleep \"\$SLEEP_INTERVAL\"
            ((ELAPSED+=SLEEP_INTERVAL))
        done

        log -f \"${CURRENT_FUNC}\" 'ERROR' \"❌ Timeout reached (\$TIMEOUT seconds). CephCluster is not Ready.\"
        exit 1
    """
    if [ $? -ne 0 ]; then
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to check the status of rook-ceph cluster"
        return 1
    else
        log -f "${CURRENT_FUNC}" "Finished deploying rook-ceph cluster on the cluster."
    fi
    ##################################################################
}







install_kafka() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    log -f ${CURRENT_FUNC} "Started kafka helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_HOST" "bitnami" "https://charts.bitnami.com/bitnami" "$KAFKA_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install kafka helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished kafka helm chart prerequisites"
    ##################################################################
    log -f ${CURRENT_FUNC} "removing kafka crds"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        kubectl delete crd --selector app=kafka --now=true ${VERBOSE} || true
    """
    ##################################################################
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        # create tmp dir for kafka
        rm -rf /tmp/kafka &&  mkdir -p /tmp/kafka
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending kafka values.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./kafka/values.yaml $CONTROL_PLANE_HOST:/tmp/kafka/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending kafka http-routes.yaml to control-plane node: ${CONTROL_PLANE_HOST}"
    scp -q ./kafka/http-routes.yaml $CONTROL_PLANE_HOST:/tmp/kafka/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing bitnami kafka Helm chart"
    ssh -q ${CONTROL_PLANE_HOST} <<< """
        output=\$(helm install kafka bitnami/kafka \
            --namespace $KAFKA_NS \
            --create-namespace \
            --version $KAFKA_VERSION \
            -f /tmp/kafka/values.yaml \
            ${VERBOSE} || true)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install kafka:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing kafka on namespace: '${KAFKA_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install kafka"
        return 1
    fi
    ##################################################################
    # log -f ${CURRENT_FUNC} "applying http-routes for kafka ingress"
    # ssh -q ${CONTROL_PLANE_HOST} <<< """
    #     kubectl apply -f /tmp/kafka/http-routes.yaml ${VERBOSE}
    # """
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished deploying kafka on the cluster."
}


#################################################################
if [ "$PREREQUISITES" = true ]; then
    # #################################################################
    # if ! provision_deployer; then
    #     log -f "main" "ERROR" "An error occurred while provisioning the deployer node."
    #     exit 1
    # fi
    # log -f "main" "Deployer node provisioned successfully."
    #################################################################
    if ! deploy_hostsfile; then
        log -f "main" "ERROR" "An error occured while updating the hosts files."
        exit 1
    fi
    log -f "main" "Hosts files updated successfully."
    #################################################################
fi

echo end of test
exit 1
#################################################################
if [ $RESET_CLUSTER_ARG -eq 1 ]; then
    reset_cluster
    log -f "main" "Cluster reset completed."
    exit 0
fi
#################################################################
if [ "$PREREQUISITES" == "true" ]; then
    #################################################################
    if ! prerequisites_requirements; then
        log -f "main" "ERROR" "Failed the prerequisites requirements for the cluster installation."
        exit 1
    fi
    #################################################################
    if ! install_kubetools; then
        log -f "main" "ERROR" "Failed to install kuberenetes required tools for cluster deployment."
        exit 1
    fi
else
    log -f "main" "Cluster prerequisites have been skipped"
fi

#################################################################
if ! install_cluster; then
    log -f main "ERROR" "An error occurred while deploying the cluster"
    exit 1
fi
#################################################################
if ! install_gateway_CRDS; then
    log -f main "ERROR" "An error occurred while deploying gateway CRDS"
    exit 1
fi
#################################################################
if ! install_cilium_prerequisites; then
    log -f main "ERROR" "An error occurred while installing cilium prerequisites"
    exit 1
fi
#################################################################
if ! install_cilium; then
    log -f main "ERROR" "An error occurred while installing cilium"
    exit 1
fi
#################################################################
join_cluster
#################################################################
if ! install_gateway; then
    log -f "main" "ERROR" "Failed to deploy ingress gateway API on the cluster, services might be unreachable..."
    exit 1
fi
##################################################################
if ! restart_cilium; then
    log -f "main" "ERROR" "Failed to start cilium service."
    exit 1
fi
#################################################################
if [ "$PREREQUISITES" == "true" ]; then
    if ! install_certmanager_prerequisites; then
        log -f "main" "ERROR" "Failed to installed cert-manager prerequisites"
        exit 1
    fi
fi
if ! install_certmanager; then
    log -f "main" "ERROR" "Failed to deploy cert_manager on the cluster, services might be unreachable due to faulty TLS..."
    exit 1
fi

################################################################
# TODO, status checks and tests
# install_rancher

#################################################################
if [ "$PREREQUISITES" == "true" ]; then
    if ! install_longhorn_prerequisites; then
        log -f "main" "ERROR" "Failed to install longhorn prerequisites"
        exit 1
    fi
fi
if ! install_longhorn; then
    log -f "main" "ERROR" "Failed to install longhorn on the cluster"
    exit 1
fi
##################################################################
if ! install_cephrook; then
    log -f "main" "ERROR" "Failed to install ceph-rook on the cluster"
    exit 1
fi
##################################################################
if ! install_cephrook_cluster; then
    log -f "main" "ERROR" "Failed to install ceph-rook cluster on the cluster"
    exit 1
fi
# ##################################################################
# # if ! install_consul; then
# #     log -f "main" "ERROR" "Failed to install consul on the cluster"
# #     exit 1
# # fi
# ##################################################################
# if ! install_vault; then
#     log -f "main" "ERROR" "Failed to install longhorn on the cluster"
#     exit 1
# fi

##################################################################
# if ! install_kafka; then
#     log -f "main" "ERROR" "Failed to install kafka on the cluster"
#     exit 1
# fi
##################################################################
log -f "main" "deployment finished"


# ./main -r -v --with-prerequisites



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


# kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/v1.8.1/examples/storageclass.yaml
# kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/v1.8.1/examples/pod_with_pvc.yaml



