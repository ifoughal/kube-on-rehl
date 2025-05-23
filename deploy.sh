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
RESET_CLUSTER_ARG=0
CLUSTER_NODES=
INSTALL_CLUSTER=false
PRINT_ROOK_PASSWORD=false
UPGRADE_CILIUM=false
STABILIZE_CLUSTER=false
set -u # fail on unset variables

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
        --install)
            INSTALL_CLUSTER=true
            shift
            ;;
        --upgrade-cilium)
            UPGRADE_CILIUM=true
            shift
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
        --print-rookceph-password)
            PRINT_ROOK_PASSWORD=true
            shift
            ;;
        --stabilize)
            STABILIZE_CLUSTER=true
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

if [ "$VERBOSE_LEVEL" -eq 0 ]; then
    VERBOSE="> /dev/null 2>&1"
# on level 1; we allow error outputs.
elif [ "$VERBOSE_LEVEL" -eq 1 ]; then
    VERBOSE="1> /dev/null"
else
    alias debug_log="/usr/local/bin/log -l DEBUG"  # by default, silence debug logs for verbose 0 and 1
    # on level 2; we allow info and error outputs.
    if [ "$VERBOSE_LEVEL" -eq 2 ]; then
        VERBOSE=""
    # unsilence debug logs
    # on level 3-5; we verbose the executed commands.
    elif [ "$VERBOSE_LEVEL" -eq 3 ]; then
        VERBOSE="-v"
    elif [ "$VERBOSE_LEVEL" -eq 4 ]; then
        VERBOSE="-vv"
    elif [ "$VERBOSE_LEVEL" -eq 5 ]; then
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
if command -v yq &> /dev/null; then
    parse_inventory
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
    if command -v yq &> /dev/null; then
        log -f ${CURRENT_FUNC} "YQ already installed, skipping installation."
    else
        sudo wget https://github.com/mikefarah/yq/releases/download/v4.45.1/yq_linux_amd64 -O /usr/local/bin/yq
        sudo chmod +x /usr/local/bin/yq
    fi
    ####################################################################
    parse_inventory
    ####################################################################
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
        #######################################################################
        # Normalize SSH_BLOCK
        local normalized_ssh_block=$(echo "$SSH_BLOCK" | sed '/^\s*$/d' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Normalize current_block
        local normalized_current_block=$(echo "$current_block" | sed '/^\s*$/d' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        #######################################################################
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
        #######################################################################
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
        #######################################################################
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
        #######################################################################
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    if [ "$hosts_updated" == true ]; then
        log -f ${CURRENT_FUNC} "SSH config file updated successfully. Relaunch terminal to apply changes."
        exit 0
    else
        log -f ${CURRENT_FUNC} "No changes made to SSH config file."
    fi
    #######################################################################
    while read -r node; do
        #######################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local port=$(echo "$node" | jq -r '.port // 22')
        local role=$(echo "$node" | jq -r '.role')
        local user=$(echo "$node" | jq -r '.user')
        local password=$(echo "$node" | jq -r '.password')
        #######################################################################
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
        ########################################################################
        # export keys to nodes:
        if [ "$STRICT_HOSTKEYS" -eq 0 ]; then
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
        #######################################################################
        # 1. Check if SSH key exists
        if [[ ! -f "${SSH_KEY}" || ! -f "${SSH_KEY}.pub" ]]; then
            log -f $CURRENT_FUNC "Generating 🔑 SSH key for $role node ${hostname}..."
            ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N "" -C "$USER@$CLUSTER_NAME"
        else
            log -f $CURRENT_FUNC "✅ SSH key already exists: ${SSH_KEY}"
        fi
        #######################################################################
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
        #######################################################################
        log -f ${CURRENT_FUNC} "sending SSH config file to target $role node ${hostname}"
        # scp -q $CONFIG_FILE ${hostname}:/tmp
        output=$(scp -q "$CONFIG_FILE" "${hostname}:/tmp" 2>&1)
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while sending SSH config file to node ${hostname}...\n\toutput: $output"
            continue  # continue to next node and skip this one
        fi
        # Check if the output contains the SSH key scan prompt
        if echo "$output" | grep -q "The authenticity of host"; then
            error_raised=1
            echo "Error: SSH key scan prompt detected."
            continue
        fi
        #######################################################################
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
        #######################################################################
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
        #######################################################################
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
        #######################################################################
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
        #######################################################################
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
        #######################################################################
        log -f ${CURRENT_FUNC} "Deploying logger function for ${role} node ${hostname}"
        scp -q ./log $hostname:/tmp/
        ssh -q $hostname <<< """
            sudo mv /tmp/log /usr/local/bin/log
            sudo chmod +x /usr/local/bin/log
        """
        log -f ${CURRENT_FUNC} "Finished deploying logger function for ${role} node ${hostname}"
        #######################################################################
        log -f ${CURRENT_FUNC} "Configuring NTP for ${role} node ${hostname}"
        ssh -q $hostname <<< """
            sudo timedatectl set-ntp true > /dev/null 2>&1
            sudo timedatectl set-timezone $TIMEZONE > /dev/null 2>&1
            sudo timedatectl status > /dev/null 2>&1
        """
        #######################################################################
        log -f ${CURRENT_FUNC} "Configuring repos for ${role} node ${hostname}"
        configure_repos $hostname $role "/etc/yum.repos.d/almalinux.repo"
        if [ $? -ne 0 ]; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring repos for node ${hostname}..."
            continue  # continue to next node and skip this one
        else
            log -f ${CURRENT_FUNC} "repos configured successfully for ${role} node ${hostname}"
        fi
        ########################################################################
        log -f ${CURRENT_FUNC} "Adjusting NTP with chrony ${role} node ${hostname}"
        ssh -q $hostname <<< """
            sudo dnf install -y chrony > /dev/null 2>&1
            sudo systemctl enable --now chronyd > /dev/null 2>&1
            sudo chronyc makestep > /dev/null 2>&1
        """
        ########################################################################
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
            sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools ipcalc lsof ${VERBOSE}
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
    if [ "$error_raised" -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished deploying hosts file"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the hosts file deployment"
        return 1
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


reset_cluster () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started reseting cluster worker nodes:"
    ##################################################################
    error_raised=0
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        if [ "$role" == "control-plane-leader" ] || [ "$role" == "control-plane-replica" ]; then
            continue
        fi
        ##################################################################
        log -f ${CURRENT_FUNC} "Started resetting k8s ${role} node node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo swapoff -a

            log -f ${CURRENT_FUNC} 'Removing kubernetes hanging pods and containers'
            for id in \$(sudo crictl pods -q 2>&1); do
                sudo crictl stopp \"\$id\" > /dev/null 2>&1
                sudo crictl rmp \"\$id\" > /dev/null 2>&1
            done

            if command -v kubectl &> /dev/null; then
                sudo crictl rm -fa > /dev/null 2>&1 # remove all containers
                sudo crictl rmp -a > /dev/null 2>&1  # remove all pods
                sudo crictl rmi -a > /dev/null 2>&1  # remove all images
            fi

            log -f ${CURRENT_FUNC} 'Stopping containerd'
            sudo systemctl stop containerd > /dev/null 2>&1

            log -f ${CURRENT_FUNC} 'Stopping kubelet'
            sudo systemctl stop kubelet > /dev/null 2>&1

            log -f ${CURRENT_FUNC} 'removing cilium cgroupv2 mount and deleting cluster directories'
            sudo umount /var/run/cilium/cgroupv2 > /dev/null 2>&1
            sudo rm -rf \
                /var/lib/rook \
                /var/lib/cilium \
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
                /var/lib/containerd \
                /var/lib/etcd
            log -f ${CURRENT_FUNC} 'reloading systemd daemon and flushing iptables'
            sudo systemctl daemon-reload
            sudo iptables -F
            sudo iptables -t nat -F
            sudo iptables -t mangle -F
            sudo iptables -X
        """
        ##################################################################
        kill_services_by_port "$hostname" 6443 2379 2380
        ##################################################################
        log -f ${CURRENT_FUNC} "Finished resetting k8s ${role} node node: ${hostname}"
        ##################################################################
        log -f ${CURRENT_FUNC} "Removing prior installed versions of K8S for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes > /dev/null 2>&1
            sudo dnf remove -y containerd.io > /dev/null 2>&1
        """
        ##################################################################
        log -f ${CURRENT_FUNC} "Finished resetting ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "Started resetting cluster main control plane node"
    # reset cilium, crds etc on the main control plane node
    ssh -q $CONTROL_PLANE_NODE <<< """
        sudo swapoff -a

        if command -v cilium &> /dev/null; then
            log -f ${CURRENT_FUNC} 'Uninstalling Cilium from node ${CONTROL_PLANE_NODE}'
            cilium uninstall --timeout 30s ${VERBOSE}
        fi

        if command -v kubectl &> /dev/null; then
            log -f ${CURRENT_FUNC} 'Deleting Cilium resources from node ${CONTROL_PLANE_NODE}'
            kubectl delete crds -l app.kubernetes.io/part-of=cilium ${VERBOSE}
            kubectl delete validatingwebhookconfigurations cilium-operator ${VERBOSE}
            kubectl -n $CILIUM_NS delete deployment -l k8s-app=cilium-operator > /dev/null 2>&1
        fi

        if command -v kubeadm &> /dev/null; then
            log -f ${CURRENT_FUNC} 'Reseting kubeadm on node ${CONTROL_PLANE_NODE}'
            output=\$(sudo kubeadm reset -f 2>&1 )
            if [ \$? -ne 0 ]; then
                log -f ${CURRENT_FUNC} 'WARNING' 'Error occurred while resetting k8s node ${CONTROL_PLANE_NODE}...\n\$(printf \"%s\n\" \"\$output\")'
            elif echo \"\$output\" | grep -qi 'failed\|error'; then
                log -f ${CURRENT_FUNC} 'WARNING' \"Error occurred while resetting k8s node ${CONTROL_PLANE_NODE}...\n\$(printf \"%s\n\" \"\$output\")\"
            fi
        fi
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "Started resetting cluster control plane nodes"
    # reset the control plane node replicas last.
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        if [ "$role" != "control-plane-leader" ] && [ "$role" != "control-plane-replica" ]; then
            continue
        fi
        log -f ${CURRENT_FUNC} "Started resetting k8s ${role} node node: ${hostname}"
        ssh -q ${hostname} <<< """
            sudo swapoff -a

            if command -v kubeadm &> /dev/null; then
                log -f ${CURRENT_FUNC} 'Reseting kubeadm on node ${hostname}'
                output=\$(sudo kubeadm reset -f 2>&1 )
                if [ \$? -ne 0 ]; then
                    log -f ${CURRENT_FUNC} 'WARNING' 'Error occurred while resetting k8s node ${hostname}...\n\$(printf \"%s\n\" \"\$output\")'
                elif echo \"\$output\" | grep -qi 'failed\|error'; then
                    log -f ${CURRENT_FUNC} 'WARNING' \"Error occurred while resetting k8s node ${hostname}...\n\$(printf \"%s\n\" \"\$output\")\"
                fi
            fi

            log -f ${CURRENT_FUNC} 'Removing kubernetes hanging pods and containers'
            for id in \$(sudo crictl pods -q 2>&1); do
                sudo crictl stopp \"\$id\" > /dev/null 2>&1
                sudo crictl rmp \"\$id\" > /dev/null 2>&1
            done

            if command -v kubectl &> /dev/null; then
                sudo crictl rm -fa > /dev/null 2>&1 # remove all containers
                sudo crictl rmp -a > /dev/null 2>&1  # remove all pods
                sudo crictl rmi -a > /dev/null 2>&1  # remove all images
            fi

            log -f ${CURRENT_FUNC} 'Stopping containerd'
            sudo systemctl stop containerd > /dev/null 2>&1

            log -f ${CURRENT_FUNC} 'Stopping kubelet'
            sudo systemctl stop kubelet > /dev/null 2>&1

            log -f ${CURRENT_FUNC} 'removing cilium cgroupv2 mount and deleting cluster directories'
            sudo umount /var/run/cilium/cgroupv2 > /dev/null 2>&1
            sudo rm -rf \
                /var/lib/cilium \
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
                /var/lib/containerd \
                /var/lib/etcd
            log -f ${CURRENT_FUNC} 'reloading systemd daemon and flushing iptables'
            sudo systemctl daemon-reload
            sudo iptables -F
            sudo iptables -t nat -F
            sudo iptables -t mangle -F
            sudo iptables -X
        """
        ##################################################################
        log -f ${CURRENT_FUNC} "Finished resetting ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    if [ "$error_raised" -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished resetting cluster nodes"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the cluster nodes reset"
        return 1
    fi
    ##################################################################
}


# policycoreutils iproute  iptables
prerequisites_requirements() {
    #######################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #######################################################################
    local error_raised=0
    #######################################################################
    log -f ${CURRENT_FUNC}  "Started cluster prerequisites installation and checks"
    #######################################################################
    log -f ${CURRENT_FUNC} "WARNING" "Will install cluster prerequisites, manual nodes reboot is required."
    #######################################################################
    while read -r node; do
       #######################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        #######################################################################
        log -f ${CURRENT_FUNC} "Starting dnf optimisations for ${role} node ${hostname}"
        optimize_dnf $hostname "${VERBOSE}"
        log -f ${CURRENT_FUNC} "Finished dnf optimisations for ${role} node ${hostname}"
        #######################################################################
        log -f ${CURRENT_FUNC} "Started checking if the kernel is recent enough for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            log -f $CURRENT_FUNC 'checking if the kernel is recent enough...' ${VERBOSE}
            kernel_version=\$(uname -r)
            log -f $CURRENT_FUNC \"Kernel version: '\$kernel_version'\" ${VERBOSE}

            # Compare kernel versions
            if [[ \$(printf '%s\n' \"$recommended_rehl_version\" \"\$kernel_version\" | sort -V | head -n1) == \"$recommended_rehl_version\" ]]; then
                log -f $CURRENT_FUNC \"Kernel version is sufficient.\" ${VERBOSE}
            else
                log -f $CURRENT_FUNC \"ERROR\" \"Kernel version is below the recommended version $recommended_rehl_version for ${role} node ${hostname}\"
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
        #######################################################################
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
        #######################################################################
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
        #######################################################################
        log -f $CURRENT_FUNC "Started updating env variables for ${role} node ${hostname}"
        update_path ${hostname}
        log -f $CURRENT_FUNC "Finished updating env variables for ${role} node ${hostname}"
        #######################################################################
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
        log -f ${CURRENT_FUNC} "WARNING" "WORKAROUND: Stopping firewalld for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo systemctl stop firewalld.service
        """
        ############################################################################
        log -f ${CURRENT_FUNC} "Ensuring that unprivileged BPF is enabled on ${role} node ${hostname}"
        enable_unprivileged_bpf "$hostname"
        local status=$?
        if [ $status -eq 0 ]; then
            log -f ${CURRENT_FUNC} "Finished ensuring that unprivileged BPF is enabled on ${role} node ${hostname}"
        elif [ $status -eq 200 ]; then
            log -f ${CURRENT_FUNC} "eBPF unpriviledge mode has been enabled on ${role} node ${hostname}"
            log -f ${CURRENT_FUNC} "Finished ensuring that unprivileged BPF is enabled on ${role} node ${hostname}"
        else
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while ensuring that unprivileged BPF is enabled on ${role} node ${hostname}"
            continue # continue to next node...
        fi
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

            sudo touch \"\$file\"
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
        if ! install_containerd "$hostname" "$role" "$PAUSE_VERSION" "$SUDO_GROUP" "$HTTP_PROXY" "$HTTPS_PROXY" "$NO_PROXY"; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while configuring containerd for ${role} node ${hostname}"
            continue  # continue to next node and skip this one
        fi
        log -f ${CURRENT_FUNC} "Containerd installed and configured successfully for ${role} node ${hostname}"
        #############################################################################
        # Define the GRUB configuration file location
        GRUB_CONFIG_FILE="/etc/default/grub"
        log -f ${CURRENT_FUNC} "Checking if ipv6 is enabled in the GRUB configuration for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            set -euo pipefail
            # Check if ipv6.disable=1 exists in the GRUB configuration
            if grep -q 'ipv6.disable=1' '$GRUB_CONFIG_FILE'; then
                # Remove ipv6.disable=1 from the GRUB configuration
                sudo sed -i 's/ipv6.disable=1//g' '$GRUB_CONFIG_FILE'
                log -f $CURRENT_FUNC 'IPv6 disabled flag removed from GRUB configuration on ${role} node ${hostname}'

                # Update GRUB to apply the changes
                if sudo test -f '/boot/grub2/grub.cfg'; then
                    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
                elif sudo test -f '/boot/efi/EFI/centos/grub.cfg'; then
                    sudo grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
                fi
                exit 210
            fi
        """
        local exist_status=$?
        if [ $exist_status -ne 0 ]; then
            if [ $exist_status -eq 210 ]; then
                log -f  ${CURRENT_FUNC} 'WARNING' "Manually rebooting $role node $hostname to apply changes is required prior to proceeding...."
            else
                error_raised=1
                log -f ${CURRENT_FUNC} "ERROR" "Error occurred while checking GRUB configuration for $role node ${hostname}..."
                continue  # continue to next node and skip this one
            fi
        fi
        log -f ${CURRENT_FUNC} "Finished checkingipv6 GRUB configuration for ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    #############################################################################
    if [ "$error_raised" -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished cluster prerequisites installation and checks"
        return 0
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the cluster prerequisites installation and checks"
        return 1
    fi
}


install_cluster () {
    #############################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #############################################################################
    # TODO: loop through the hosts to install contaienrD:
    # TEST and refactor it...
    error_raised=0
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        log -f ${CURRENT_FUNC} "Configuring containerd for ${role} node ${hostname}"
        if ! install_containerd $hostname $role $PAUSE_VERSION $SUDO_GROUP "$HTTP_PROXY" "$HTTPS_PROXY" "$NO_PROXY"; then
            error_raised=1
            log -f ${CURRENT_FUNC} "ERROR" "Error occurred while installing and configuring containerd for ${role} node ${hostname}"
            continue
        fi
        log -f ${CURRENT_FUNC} "Containerd installed and configured successfully for ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    #############################################################################
    if ! install_kubetools; then
        log -f "main" "ERROR" "Failed to install kuberenetes required tools for cluster deployment."
        error_raised=1
    fi
    #############################################################################
    if [ ! "$error_raised" -eq 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the installation of kubernetes required tools for cluster deployment."
        return 1
    fi
    #############################################################################
    log -f ${CURRENT_FUNC} "Generating kubeadm init config file"
    envsubst < init-config-template.yaml > /tmp/init-config.yaml
    ####################################################################
    log -f ${CURRENT_FUNC} "sending kubeadm init config file to main control-plane: ${CONTROL_PLANE_NODE}"
    scp -q /tmp/init-config.yaml ${CONTROL_PLANE_NODE}:/tmp/
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
    ssh -q $CONTROL_PLANE_NODE <<< """
        ####################################################################
        KUBEADM_INIT_OUTPUT=\$(eval $KUBE_ADM_COMMAND  2>&1 || true)

        if echo \$(echo \"\$KUBEADM_INIT_OUTPUT\" | tr '[:upper:]' '[:lower:]') | grep 'error'; then
            log -f \"${CURRENT_FUNC}\" 'ERROR' \"\$KUBEADM_INIT_OUTPUT\"
            exit 1
        fi
        echo \$KUBEADM_INIT_OUTPUT
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
            kubectl taint nodes $CONTROL_PLANE_NODE node-role.kubernetes.io/control-plane:NoSchedule- >/dev/null 2>&1
            kubectl taint nodes $CONTROL_PLANE_NODE node.kubernetes.io/not-ready:NoSchedule- >/dev/null 2>&1
            log -f \"${CURRENT_FUNC}\" \"sleeping for 30s to wait for Kubernetes control-plane node: ${CONTROL_PLANE_NODE} setup completion...\"
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

    log -f ${CURRENT_FUNC} "sending http-routes.yaml file to control plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./cilium/http-routes.yaml ${CONTROL_PLANE_NODE}:/tmp/

    # using experimental CRDS channel
    log -f ${CURRENT_FUNC} "Installing Gateway API version: ${GATEWAY_VERSION} from the experimental channel"
    ssh -q $CONTROL_PLANE_NODE <<< """
        set -euo pipefail

        kubectl create ns cilium-monitoring > /dev/null 2>&1 || true

        kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_VERSION}/experimental-install.yaml ${VERBOSE}

        log -f ${CURRENT_FUNC} 'Installing Gateway API Experimental TLSRoute from the Experimental channel'

        kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/${GATEWAY_VERSION}/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml ${VERBOSE}

        log -f ${CURRENT_FUNC} 'Applying hubble-ui HTTPRoute for ingress.'
        kubectl apply -f /tmp/http-routes.yaml ${VERBOSE}
    """
    if [ $? -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished installing Gateway API CRDS"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Error occurred while installing Gateway API CRDS"
        return 1
    fi
}


install_cilium_prerequisites () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    log -f ${CURRENT_FUNC} "INFO" "Started installing cilium prerequisites"
    ##################################################################
    # ssh -q $CONTROL_PLANE_NODE <<< """
    #     eval 'sudo cilium uninstall > /dev/null 2>&1' || true
    #     log -f '${CURRENT_FUNC}' 'Ensuring that kube-proxy is not installed'
    #     eval 'kubectl -n kube-system delete ds kube-proxy > /dev/null 2>&1' || true
    #     # Delete the configmap as well to avoid kube-proxy being reinstalled during a Kubeadm upgrade (works only for K8s 1.19 and newer)
    #     eval 'kubectl -n kube-system delete cm kube-proxy > /dev/null 2>&1' || true
    # """
    ##################################################################
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        local ingress_cluster_interface=$(echo "$node" | jq -r '.ingress.cluster_interface')
        local ingress_public_interface=$(echo "$node" | jq -r '.ingress.public_interface')
        ##################################################################
        # free_space $hostname
        ##################################################################
        log -f ${CURRENT_FUNC} "setting public interface: ${ingress_public_interface} rp_filter to 1 on $role node ${hostname}"
        log -f ${CURRENT_FUNC} "setting cluster interface: ${ingress_cluster_interface} rp_filter to 2 on $role node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo sysctl -w net.ipv4.conf.$ingress_cluster_interface.rp_filter=2 ${VERBOSE}
            sudo sysctl -w net.ipv4.conf.${ingress_public_interface}.rp_filter=1 ${VERBOSE}

            sudo sysctl --system ${VERBOSE}
        """
        ##################################################################
        # CILIUM_CLI_VERSION=$(curl --silent https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
        ##################################################################
        log -f ${CURRENT_FUNC} "installing cilium cli version: $CILIUM_CLI_VERSION on $role node ${hostname}"
        ssh -q ${hostname} <<< """
            if command -v cilium &> /dev/null; then
                log -f \"${CURRENT_FUNC}\" 'cilium cli already installed, skipping installation.'
                exit 0
            fi
            cd /tmp

            CLI_ARCH=amd64
            if [ \"\$\(uname -m\)\" = 'aarch64' ]; then CLI_ARCH=arm64; fi

            curl -s -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-\${CLI_ARCH}.tar.gz{,.sha256sum}

            sha256sum --check cilium-linux-\${CLI_ARCH}.tar.gz.sha256sum ${VERBOSE}
            sudo tar xzvfC cilium-linux-\${CLI_ARCH}.tar.gz /usr/local/bin ${VERBOSE}
            rm cilium-linux-*
        """
        add_bashcompletion ${hostname}  cilium $VERBOSE
        log -f ${CURRENT_FUNC} "Finished installing cilium cli on $role node ${hostname}"

        ##################################################################
        log -f ${CURRENT_FUNC} "installing cilium Hubble cli version: $CILIUM_HUBBLE_CLI_VERSION on $role node ${hostname}"

        # get the latest version of hubble cli:
        # HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
        ssh -q ${hostname} <<< """

            if command -v hubble &> /dev/null; then
                log -f \"${CURRENT_FUNC}\" 'cilium hubble cli already installed, skipping installation.'
                exit 0
            fi
            cd /tmp

            HUBBLE_ARCH=amd64

            if [ \"\$\(uname -m\)\" = 'aarch64' ]; then HUBBLE_ARCH=arm64; fi

            curl -s -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$CILIUM_HUBBLE_CLI_VERSION/hubble-linux-\${HUBBLE_ARCH}.tar.gz{,.sha256sum}

            sha256sum --check hubble-linux-\${HUBBLE_ARCH}.tar.gz.sha256sum ${VERBOSE}
            sudo tar xzvfC hubble-linux-\${HUBBLE_ARCH}.tar.gz /usr/local/bin ${VERBOSE}
            rm hubble-linux-\${HUBBLE_ARCH}.tar.gz{,.sha256sum}
        """
        add_bashcompletion ${hostname}  hubble $VERBOSE

        log -f ${CURRENT_FUNC} "checkout https://docs.cilium.io/en/stable/observability/hubble/setup/#hubble-cli-install for hubble CLI usage details."

        log -f ${CURRENT_FUNC} "Finished installing cilium hubble cli on $role node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "INFO" "Finished installing cilium prerequisites"
}


install_cilium () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #############################################################
    set +u
    if [ -z "$MAGLEV_HASH_SEED" ]; then
        log -f ${CURRENT_FUNC} "Cilium maglev hashseed is not set, generating a random one."
        local hash_seed=$(head -c12 /dev/urandom | base64 -w0)
    else
        local hash_seed=$MAGLEV_HASH_SEED
    fi
    log -f ${CURRENT_FUNC} "Cilium maglev hashseed is: ${hash_seed}"
    set -u
    #############################################################
    local control_plane_address=$(ssh -q ${CONTROL_PLANE_NODE} <<< """
        ip -o -4 addr show $CONTROLPLANE_INGRESS_CLUSTER_INTER | awk '{print \$4}' | cut -d/ -f1
    """)

    local control_plane_subnet=$(ssh -q "${CONTROL_PLANE_NODE}" """
        # Use 'ip' to show the IPv4 address and CIDR of the given interface

        ip -o -f inet addr show ${CONTROLPLANE_INGRESS_CLUSTER_INTER} | awk '{print \$4}' | while read cidr; do
            # Split the CIDR into IP and prefix (e.g., 10.10.10.11 and 24)
            IFS=/ read ip prefix <<< \"\$cidr\"
            # Split the IP address into its 4 octets
            IFS=. read -r o1 o2 o3 o4 <<< \"\$ip\"

            # Generate the subnet mask as a 32-bit integer, then mask out unused bits
            mask=\$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))

            # Extract each octet of the subnet mask
            m1=\$(( (mask >> 24) & 0xFF ))
            m2=\$(( (mask >> 16) & 0xFF ))
            m3=\$(( (mask >> 8) & 0xFF ))
            m4=\$(( mask & 0xFF ))

            # Calculate the network address by bitwise ANDing IP and subnet mask
            n1=\$(( o1 & m1 ))
            n2=\$(( o2 & m2 ))
            n3=\$(( o3 & m3 ))
            n4=\$(( o4 & m4 ))

            # Output the resulting network address in CIDR notation
            echo \"\$n1.\$n2.\$n3.\$n4/\$prefix\"
        done
    """)
    log -f ${CURRENT_FUNC} "Cilium native routing subnet is: ${control_plane_subnet}"
    #############################################################
    log -f ${CURRENT_FUNC} "Started cilium helm chart prerequisites"
    ssh -q $CONTROL_PLANE_NODE <<< """
        cilium uninstall --namespace $CILIUM_NS > /dev/null 2>&1 || true
        helm uninstall --namespace $CILIUM_NS cilium > /dev/null 2>&1 || true
    """
    helm_chart_prerequisites ${CONTROL_PLANE_NODE} "cilium" "cilium" "https://helm.cilium.io" "$CILIUM_NS" "false" "false"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install cilium helm chart prerequisites"
        return 1
    fi
    ##################################################################
    # # cleaning up cilium and maglev tables
    # # EXPERIMENTAL ONLY AND STILL UNDER TESTING....
    log -f ${CURRENT_FUNC} "Started cilium cleanup"
    cilium_cleanup
    log -f ${CURRENT_FUNC} "Cilium cleanup done"
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished cilium helm chart prerequisites"
    ##################################################################
    log -f ${CURRENT_FUNC} "Started installing cilium"
    #############################################################
    log -f ${CURRENT_FUNC} "sending cilium values to control plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./cilium/values.yaml ${CONTROL_PLANE_NODE}:/tmp/
    #############################################################
    log -f ${CURRENT_FUNC} "Generating lb ip pool file"
    generate_ip_pool
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to generate lb ip pool file"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished generating lb ip pool file"
    #############################################################
    log -f ${CURRENT_FUNC} "sending lb ip pool to control plane node: ${CONTROL_PLANE_NODE}"
    scp -q /tmp/loadbalancer-ip-pool.yaml ${CONTROL_PLANE_NODE}:/tmp/
    #############################################################
    log -f ${CURRENT_FUNC} "Installing cilium version: '${CILIUM_VERSION}' using cilium cli"
    ssh -q $CONTROL_PLANE_NODE <<< """
        #############################################################
        RETRY_COUNT=0
        MAX_RETRIES=5  # Set the maximum number of retries

        while [ \$RETRY_COUNT -lt \$MAX_RETRIES ]; do
            OUTPUT=\$(cilium install --version $CILIUM_VERSION \
                --namespace $CILIUM_NS \
                --set ipv4NativeRoutingCIDR=${control_plane_subnet} \
                --set operator.replicas=$OPERATOR_REPLICAS \
                --set hubble.relay.replicas=$HUBBLE_RELAY_REPLICAS \
                --set hubble.ui.replicas=$HUBBLE_UI_REPLICAS \
                --set maglev.hashSeed="${hash_seed}" \
                -f /tmp/values.yaml \
                2>&1)
            if [ \$RETRY_COUNT -eq \$MAX_RETRIES ]; then
                log -f $CURRENT_FUNC 'ERROR' 'Max retries reached. Cilium installation failed.'
                exit 1
            fi

            if echo \$OUTPUT | grep -q 'it is being terminated'; then
                # If the error is detected, retry the installation
                log -f $CURRENT_FUNC 'INFO' \"Cilium NS is being terminated, retrying... (\$((RETRY_COUNT+1))/\$MAX_RETRIES)\"
                ((RETRY_COUNT++))
                sleep 30  # Sleep before retrying
            elif echo \$OUTPUT | grep -q 'Error'; then
                # If there is any other error, log and exit
                log -f $CURRENT_FUNC 'ERROR' \"Failed to deploy cilium, retrying... (\$((RETRY_COUNT+1))/\$MAX_RETRIES)\n\toutput:\n\t\$OUTPUT\"
                ((RETRY_COUNT++))
                sleep 30  # Sleep before retrying
            else
                # Successful installation, break the loop
                log -f $CURRENT_FUNC 'INFO' 'Cilium installed successfully.'
                break
            fi
        done
        #############################################################
        sleep 30
        log -f $CURRENT_FUNC 'Removing default cilium ingress.'
        kubectl delete svc -n $CILIUM_NS cilium-ingress >/dev/null 2>&1 || true
        #############################################################
        log -f $CURRENT_FUNC 'Apply LB IPAM on cluster'
        eval \"kubectl apply -f /tmp/loadbalancer-ip-pool.yaml > /dev/null 2>&1\"
        if [ \$? -ne 0 ]; then
            sudo systemctl restart containerd
            eval \"kubectl apply -f /tmp/loadbalancer-ip-pool.yaml ${VERBOSE}\"
        fi
        #############################################################
    """
    #############################################################
    if [ $? -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished deploying cilium."
    else
        return 1
    fi
    #############################################################
    #  \
    #             --set cleanBpfState=true \
    #             --set cleanState=true \
            # --set k8sServiceHost=auto \
            #   --set cleanBpfState=true \
            #     --set cleanState=true \
            # --set k8sServiceHost=10.96.0.1 \
            #     --set k8sServicePort=6443 \
}


join_cluster () {
    set +u
    set +e
    set +o pipefail
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    # TODO: for control-plane nodes:

    log -f ${CURRENT_FUNC} "Getting control-plane node config"
    ssh -q $CONTROL_PLANE_NODE <<< """
        cd /etc/kubernetes

        kubectl get configmap kubeadm-config -n kube-system -o jsonpath='{.data.ClusterConfiguration}'  | sudo tee kubeadm-config.yaml > /dev/null
        sudo tar czf pki-and-config.tar.gz pki admin.conf kubeadm-config.yaml
        sudo mv pki-and-config.tar.gz /tmp/ && sudo chmod 666 /tmp/pki-and-config.tar.gz
    """
    scp -q ${CONTROL_PLANE_NODE}:/tmp/pki-and-config.tar.gz /tmp

    log -f ${CURRENT_FUNC} "Getting cluster config from control-plane node: ${CONTROL_PLANE_NODE}"
    ssh -q $CONTROL_PLANE_NODE <<< "sudo cat /etc/kubernetes/admin.conf" > /tmp/admin.conf


    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "WARNING" "WORKAROUND: Stopping firewalld for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo systemctl stop firewalld.service
        """

        if [ $hostname == ${CONTROL_PLANE_NODE} ]; then
            continue
        fi

        log -f ${CURRENT_FUNC} "Sending cluster config to target ${role} node: ${hostname}"
        scp -q /tmp/admin.conf ${hostname}:/tmp/

        ssh -q ${hostname} <<< """
            set -euo pipefail
            sudo cp /tmp/admin.conf /etc/kubernetes/admin.conf
            sudo chmod 600 /etc/kubernetes/admin.conf
            mkdir -p \$HOME/.kube
            sudo cp -f -i /etc/kubernetes/admin.conf \$HOME/.kube/config >/dev/null 2>&1
            sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config
        """
        if [ $? -ne 0 ]; then
            sudo rm -f /tmp/admin.conf
            log -f ${CURRENT_FUNC} "ERROR" "Failed to send cluster config to target ${role} node: ${hostname}"
            continue
        fi

        if [ $role == "worker" ]; then
            log -f ${CURRENT_FUNC} "Generating join command from control-plane node: ${CONTROL_PLANE_NODE}"
            JOIN_COMMAND_WORKER=$(ssh -q $CONTROL_PLANE_NODE <<< "kubeadm token create --print-join-command""")

            log -f ${CURRENT_FUNC} "initiating cluster join for ${role} node ${hostname}"
            ssh -q ${hostname} <<< """
                set -euo pipefail

                log -f $CURRENT_FUNC 'Executing join command: $JOIN_COMMAND_WORKER on ${role} node ${hostname}'
                eval sudo ${JOIN_COMMAND_WORKER} >/dev/null 2>&1 || true
            """
            if [ $? -ne 0 ]; then
                log -f ${CURRENT_FUNC} "ERROR" "Failed to join cluster for ${role} node ${hostname}"
                continue
            fi

        elif [ $role == "control-plane-replica" ]; then


            log -f ${CURRENT_FUNC} "Generating join command from control-plane node: ${CONTROL_PLANE_NODE}"
            JOIN_COMMAND_CONTROLPLANE=$(ssh -q $CONTROL_PLANE_NODE <<< """kubeadm token create --print-join-command --certificate-key \$(sudo kubeadm init phase upload-certs --upload-certs | sed -n '3p')""")

            log -f ${CURRENT_FUNC} "initiating cluster join for ${role} node ${hostname}"
            ssh -q ${hostname} <<< """
                set -euo pipefail

                log -f $CURRENT_FUNC 'Executing join command: $JOIN_COMMAND_CONTROLPLANE on ${role} node ${hostname}'
                output=\$(sudo ${JOIN_COMMAND_CONTROLPLANE}  2>&1 || true)
                echo output is: \$output
            """
            if [ $? -ne 0 ]; then
                log -f ${CURRENT_FUNC} "ERROR" "Failed to join cluster for ${role} node ${hostname}"
                continue
            fi
        else
            log -f ${CURRENT_FUNC} "Can't initiate cluster join for ${role} node ${hostname}, role unknown"

        fi
        log -f ${CURRENT_FUNC} "Finished joining cluster for ${role} node ${hostname}"
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')

    sudo rm -f /tmp/admin.conf
    log -f ${CURRENT_FUNC} "Finished joining cluster for all nodes"
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
    config_check ${CONTROL_PLANE_NODE} "cilium config view" "kube-proxy-replacement" "true"
    if [ ! "$RETURN_CODE" -eq 0 ]; then
        return $RETURN_CODE
    fi
    ##################################################################
    # Check the value of enable-l7-proxy
    config_check ${CONTROL_PLANE_NODE} "cilium config view" "enable-l7-proxy" "true"
    if [ ! "$RETURN_CODE" -eq 0 ]; then
        return $RETURN_CODE
    fi
    log -f "${CURRENT_FUNC}" "Finished checking prerequisites for Gateway API"
    ##################################################################
    generate_http_gateway
    ##################################################################
    log -f "${CURRENT_FUNC}" "Sending Gateway API config to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q /tmp/http-gateway.yaml ${CONTROL_PLANE_NODE}:/tmp/
    ##################################################################
    log -f "${CURRENT_FUNC}" "Started deploying TLS cert for TLS-HTTPS Gateway API on control-plane node: ${CONTROL_PLANE_NODE}"

    CERTS_PATH=/etc/cilium/certs
    GATEWAY_API_SECRET_NAME=shared-tls
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        set -euo pipefail
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
        eval \"kubectl delete secret  ${GATEWAY_API_SECRET_NAME} --namespace=kube-system > /dev/null 2>&1 || true\"
        log -f \"${CURRENT_FUNC}\" 'Started creating Gateway API TLS secret'
        eval \"kubectl create secret tls ${GATEWAY_API_SECRET_NAME} --cert=\$CERT_FILE --key=\$KEY_FILE --namespace=kube-system  ${VERBOSE}\"
        log -f \"${CURRENT_FUNC}\" 'Finished deploying TLS cert for TLS-HTTPS Gateway API'
        ##################################################################
        log -f \"${CURRENT_FUNC}\" 'Started deploying Gateway API'
        eval \"kubectl apply -f /tmp/http-gateway.yaml ${VERBOSE}\"
        log -f \"${CURRENT_FUNC}\" 'Finished deploying Gateway API'
        ##################################################################
    """
    #################################################################
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to deploy Gateway API"
        return 1
    else
        log -f ${CURRENT_FUNC} "Finished deploying Gateway API"
        return 0
    fi
    #################################################################
}


restart_cilium() {
    #################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #################################################################
    local sleep_timer=500
    log -f "$CURRENT_FUNC" "Ensuring that cilium replicas scale without errors..."

    current_retry=0
    max_retries=10
    while true; do
        current_retry=$((current_retry + 1))
        #################################################################
        if [ $current_retry -gt $max_retries ]; then
            log -f ${CURRENT_FUNC} 'ERROR' 'Reached maximum retry count for cilium status to go up. Exiting...'
            return 1
        fi
        #################################################################
        ssh -q ${CONTROL_PLANE_NODE} <<< """
                CILIUM_STATUS=\$(cilium status | tr -d '\0')

                if echo "\$CILIUM_STATUS" | grep -qi 'error'; then
                    log -f ${CURRENT_FUNC} 'cilium status contains errors...'
                    exit 1
                else
                    log -f ${CURRENT_FUNC} 'Cilium is up and running'
                    exit 0
                fi
        """
        if [ $? -eq 0 ]; then
            log -f ${CURRENT_FUNC} "Finished restarting cilium"
            return 0
        else
            #################################################################
            while read -r node; do
                local hostname=$(echo "$node" | jq -r '.hostname')
                local ip=$(echo "$node" | jq -r '.ip')
                local role=$(echo "$node" | jq -r '.role')

                log -f ${CURRENT_FUNC} "Restarting cilium PIDs on $role node ${hostname}"
                ssh -q ${hostname} <<< """
                    sudo rm -f /var/run/cilium/cilium.pid
                    sudo rm -f /var/run/cilium/cilium-envoy.pid
                """

            done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
            #################################################################
            log -f ${CURRENT_FUNC} "Restarting cilium pods... Try: $current_retry"
            ssh -q ${CONTROL_PLANE_NODE} <<< """
                kubectl rollout restart -n $CILIUM_NS \
                    ds/cilium \
                    ds/cilium-envoy \
                    deployment/cilium-operator \
                    deployment/hubble-relay \
                    deployment/coredns \
                    > /dev/null 2>&1 || true
            """
            #################################################################
            echo refactor this:
            exit 1
            # Live polling loop: max $sleep_total seconds
            log -f $CURRENT_FUNC "Waiting up to ${sleep_total}s for Cilium to recover (polling every ${sleep_interval}s)..."
            local waited=0
            while [ $waited -lt $sleep_total ]; do
                ssh -q ${CONTROL_PLANE_NODE} <<< """
                    CILIUM_STATUS=\$(cilium status | tr -d '\0')

                    if echo "\$CILIUM_STATUS" | grep -qi 'error'; then
                        exit 1
                    else
                        exit 0
                    fi
                """
                if [ $? -eq 0 ]; then
                    log -f ${CURRENT_FUNC} "Cilium became ready after ${waited}s"
                    return 0
                fi

                sleep $sleep_interval
                waited=$((waited + sleep_interval))
            done
            log -f ${CURRENT_FUNC} "Cilium still not ready after ${sleep_total}s"

        fi
        #################################################################
        echo "refactor this"
        exit 1
        # to be repalced with live probe
        log -f $CURRENT_FUNC "Sleeping for $sleep_timer seconds to allow cilium to scale up..."
        sleep $sleep_timer
        #################################################################
    done
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/${CERTMANAGER_VERSION}/cert-manager.crds.yaml -n ${CERTMANAGER_NS} > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager CRDs from cluster"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl delete ClusterRole -A \
            cert-manager:leaderelection \
            > /dev/null 2>&1 || true
    """
    ##################################################################
    log -f "${CURRENT_FUNC}" "removing cert-manager startup job from cluster"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    local chart_dir="/tmp/kube-on-rehl/certmanager"
    ##################################################################
    log -f ${CURRENT_FUNC} "Started testing cert-manager installation"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        TEST_MANIFEST=$chart_dir/test-resources.yaml
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
    local chart_dir="/tmp/kube-on-rehl/certmanager"
    ##################################################################
    log -f ${CURRENT_FUNC} "Started cert-manager helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "cert-manager" "jetstack" "https://charts.jetstack.io" "$CERTMANAGER_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install cert-manager helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished cert-manager helm chart prerequisites"
    ##################################################################
    log -f "$CURRENT_FUNC" "Sending certmanager values to control-plane node: ${CONTROL_PLANE_NODE}"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        rm -rf $chart_dir
        mkdir -p $chart_dir
    """
    scp -q ./certmanager/values.yaml $CONTROL_PLANE_NODE:$chart_dir/
    ##################################################################
    log -f "$CURRENT_FUNC" "Sending certmanager test deployment to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./certmanager/test-resources.yaml $CONTROL_PLANE_NODE:$chart_dir/

    log -f "$CURRENT_FUNC" "Sending certmanager cluster-issuer and role-binding  to control-plane node: ${CONTROL_PLANE_NODE}"

    scp -q ./pki/$chart_name/cluster-issuer.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/
    scp -q ./pki/$chart_name/role-binding.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/
    ##################################################################
    log -f "${CURRENT_FUNC}" "Started installing cert-manger on namespace: '${CERTMANAGER_NS}'"
    # TODO: --set http_proxy --set https_proxy --set no_proxy
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install cert-manager cert-manager/cert-manager  \
            --version ${CERTMANAGER_VERSION} \
            --namespace ${CERTMANAGER_NS} \
            --create-namespace \
            -f $chart_dir/values.yaml \
            2>&1 || true)
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
    ##################################################################
    log -f "${CURRENT_FUNC}" "Started installing cert-manager cluster issuer and role binding"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for certmanager
        kubectl apply -f $chart_dir/pki/cluster-issuer.yaml
        kubectl apply -f $chart_dir/pki/role-binding.yaml
    """
    log -f "${CURRENT_FUNC}" "✅ Finished installing cert-manager cluster issuer and role binding"
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
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "longhorn" "longhorn" "https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"
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
        ssh -q ${CONTROL_PLANE_NODE} <<< """
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
            ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
        scp -q ./tools/os-camo.sh ${hostname}:/tmp/
        log -f ${CURRENT_FUNC} "Executing camofoulage for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo chmod +x /tmp/os-camo.sh
            /tmp/os-camo.sh camo
        """
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} 'Started checking the longhorn preflight pre installation'
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        export KUBERNETES_SERVICE_HOST=$CONTROL_PLANE_NODE
        export KUBERNETES_SERVICE_PORT=$CONTROL_PLANE_API_PORT
        export KUBERNETES_MASTER=https://$CONTROL_PLANE_NODE:$CONTROL_PLANE_API_PORT

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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    helm_chart_prerequisites "${CONTROL_PLANE_NODE}" "longhorn" "longhorn" " https://charts.longhorn.io" "$LONGHORN_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install longhorn helm chart prerequisites"
        return 1
    fi

    log -f ${CURRENT_FUNC} "Finished longhorn helm chart prerequisites"
    #################################################################
    reset_storage
    # #################################################################
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
    #     # create tmp dir for longhorn
    #     rm -rf /tmp/longhorn &&  mkdir -p /tmp/longhorn
    # """
    # #################################################################
    # log -f ${CURRENT_FUNC} "sending longhorn http-routes to control-plane node: ${CONTROL_PLANE_NODE}"
    # scp -q ./longhorn/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/longhorn/
    # ##################################################################
    # log -f ${CURRENT_FUNC} "sending longhorn values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    # scp -q ./longhorn/values.yaml $CONTROL_PLANE_NODE:/tmp/longhorn/
    # ##################################################################
    # log -f "${CURRENT_FUNC}" "Started installing longhorn on namespace: '${LONGHORN_NS}'"
    # # TODO: --set http_proxy --set https_proxy --set no_proxy
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    #         2>&1 || true)
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
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
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
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "consul" "hashicorp" " https://helm.releases.hashicorp.com" "$CONSUL_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install consul helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished consul helm chart prerequisites"
    #################################################################
    log -f ${CURRENT_FUNC} "removing consul crds"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl delete crd --selector app=consul
    """
    #################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for longhorn
        rm -rf /tmp/consul &&  mkdir -p /tmp/consul
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending consul values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./consul/values.yaml $CONTROL_PLANE_NODE:/tmp/consul/
    ##################################################################
    # log -f ${CURRENT_FUNC} "sending consul http-routes.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    # scp -q ./consul/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/consul/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing hashicorp consul Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install consul hashicorp/consul \
            --namespace $CONSUL_NS \
            --create-namespace \
            --version $CONSUL_VERSION \
            -f /tmp/consul/values.yaml \
            2>&1 || true)
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
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
    #     kubectl apply -f /tmp/vault/http-routes.yaml ${VERBOSE}
    # """
}


vault_uninstall() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started uninstalling vault helm chart"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "vault" "hashicorp" " https://helm.releases.hashicorp.com" "$VAULT_NS" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install vault helm chart prerequisites"
        return 1
    fi
    #################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl delete crd --selector app=vault
    """
    log -f ${CURRENT_FUNC} "Finished uninstalling vault helm chart"
    #################################################################
}


install_vault () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started vault helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "vault" "hashicorp" " https://helm.releases.hashicorp.com" "$VAULT_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install vault helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished vault helm chart prerequisites"
    #################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for longhorn
        rm -rf /tmp/vault &&  mkdir -p /tmp/vault
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending vault values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./vault/values.yaml $CONTROL_PLANE_NODE:/tmp/vault/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending vault http-routes.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./vault/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/vault/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing hashicorp vault Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install vault hashicorp/vault \
            --namespace $VAULT_NS \
            --create-namespace \
            --version $VAULT_VERSION \
            -f /tmp/vault/values.yaml \
            2>&1 || true)
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
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl apply -f /tmp/vault/http-routes.yaml ${VERBOSE}
    """
}



install_rancher () {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ##################################################################
    log -f ${CURRENT_FUNC} "Started rancher-${RANCHER_BRANCH} helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "rancher-${RANCHER_BRANCH}" "rancher" "https://releases.rancher.com/server-charts/${RANCHER_BRANCH}" "$RANCHER_NS" "true" "true"
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


rook_ceph_cleanup() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="rook-ceph"
    local chart_url="https://charts.rook.io/release"
    # log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
    # helm_chart_prerequisites "$CONTROL_PLANE_NODE" "${chart_name}" "${chart_url}" "$ROOKCEPH_NS" "true" "true"
    # if [ $? -ne 0 ]; then
    #     log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
    #     return 1
    # fi
    # log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
    # ###################################################################
    # local chart_name="rook-ceph-cluster"
    # local chart_url="https://charts.rook.io/release"
    # log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
    # helm_chart_prerequisites "$CONTROL_PLANE_NODE" "${chart_name}" "${chart_url}" "$ROOKCEPH_NS"
    # if [ $? -ne 0 ]; then
    #     log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
    #     return 1
    # fi
    # log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
    # ###################################################################
    # log -f ${CURRENT_FUNC} "Started cleaning up rook-ceph on control-plane node ${CONTROL_PLANE_NODE}"
    # ssh -q $CONTROL_PLANE_NODE <<< """
    #     set -e

    #     kubectl delete -n $ROOKCEPH_NS cephblockpool replicapool --timeout=30s > /dev/null 2>&1 || true
    #     kubectl delete storageclass rook-ceph-block --timeout=30s > /dev/null 2>&1 || true
    #     kubectl delete storageclass csi-cephfs --timeout=30s > /dev/null 2>&1 || true

    #     kubectl -n $ROOKCEPH_NS patch cephcluster rook-ceph --type merge -p '{\"spec\":{\"cleanupPolicy\":{\"confirmation\":\"yes-really-destroy-data\"}}}' > /dev/null 2>&1 || true

    #     kubectl patch cephcluster -n $ROOKCEPH_NS rook-ceph -p '{\"metadata\":{\"finalizers\":[]}}' --type=merge > /dev/null 2>&1
    #     kubectl -n $ROOKCEPH_NS delete cephcluster rook-ceph --timeout=30s > /dev/null 2>&1 || true
    # """
    # log -f ${CURRENT_FUNC} "Finished cleaning up rook-ceph on control-plane node ${CONTROL_PLANE_NODE}"

    ##################################################################
    # log -f ${CURRENT_FUNC} "removing cephcluster crds"
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
    #     kubectl patch cephcluster rook-ceph -n $ROOKCEPH_NS -p '{"metadata":{"finalizers":null}}' --type=merge
    # """
    ##################################################################
    local error_raised=0
    ###################################################################
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Started cleaning up rook-ceph on $role node ${hostname}"
        ssh -q ${hostname} <<< """
            log -f ${CURRENT_FUNC} 'Started cleaning up rook-ceph on $role node ${hostname}'
            set -euo pipefail

            sudo rm -rf /var/lib/rook

            # Zap the disk to a fresh, usable state (zap-all is important, b/c MBR has to be clean)
            log -f ${CURRENT_FUNC} 'Zapping the disk to a fresh, usable state on $role node ${hostname}'
            sudo sgdisk --zap-all $ROOKCEPH_HOST_DISK

            log -f ${CURRENT_FUNC} 'Removing all filesystem signatures on $role node ${hostname}'
            sudo wipefs -a $ROOKCEPH_HOST_DISK


            # Wipe a large portion of the beginning of the disk to remove more LVM metadata that may be present
            log -f ${CURRENT_FUNC} 'Wiping a large portion of the beginning of the disk to remove more LVM metadata that may be present on $role node ${hostname}'
            sudo dd if=/dev/zero of='$ROOKCEPH_HOST_DISK' bs=1M count=100 oflag=direct,dsync

            # SSDs may be better cleaned with blkdiscard instead of dd
            log -f ${CURRENT_FUNC} 'Cleaning the disk with blkdiscard on $role node ${hostname}'
            sudo blkdiscard $ROOKCEPH_HOST_DISK || true

            # Inform the OS of partition table changes
            log -f ${CURRENT_FUNC} 'Informing the OS of partition table changes on $role node ${hostname}'
            sudo partprobe $ROOKCEPH_HOST_DISK

            rm -rf /dev/ceph-*
            rm -rf /dev/mapper/ceph--*
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to clean up rook-ceph on $role node ${hostname}"
            error_raised=1
        fi
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    if [ $error_raised -eq 1 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to clean up rook-ceph."
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished cleaning up rook-ceph storage on all nodes"
    log -f ${CURRENT_FUNC} "WARNING" "a reboot for all nodes is required to remove the ceph modules"
    ##################################################################
}


install_rookceph(){
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="rook-ceph"
    local chart_url="https://charts.rook.io/release"
    ###################################################################
    log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "${chart_name}" "rook-ceph" "${chart_url}" "$ROOKCEPH_NS" "true" "true"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        rm -rf /tmp/${chart_name} &&  mkdir -p /tmp/${chart_name}
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending ${chart_name} values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./${chart_name}/values.yaml $CONTROL_PLANE_NODE:/tmp/${chart_name}/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing ${chart_name} Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install ${chart_name} ${chart_name}/${chart_name} \
            --namespace $ROOKCEPH_NS \
            --create-namespace \
            --version $ROOKCEPH_VERSION \
            -f /tmp/${chart_name}/values.yaml \
            2>&1 )
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


install_rookceph_cluster() {
    ###################################################################
    CURRENT_FUNC="${FUNCNAME[0]}"
    ###################################################################
    local chart_name="rook-ceph-cluster"
    local chart_url="https://charts.rook.io/release"
    log -f ${CURRENT_FUNC} "Started ${chart_name} helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "${chart_name}" "rook-ceph" "${chart_url}" "$ROOKCEPH_NS" "false" "false"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install ${chart_name} helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished ${chart_name} helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        rm -rf /tmp/${chart_name} &&  mkdir -p /tmp/${chart_name}
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending ${chart_name} values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./${chart_name}/values.yaml $CONTROL_PLANE_NODE:/tmp/${chart_name}/
    ##################################################################
    log -f ${CURRENT_FUNC} "installing CSI snapshot CRDs"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for rook-ceph-cluster
        kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v8.2.1/client/config/crd/snapshot.storage.k8s.io_volumesnapshotclasses.yaml
        kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v8.2.1/client/config/crd/snapshot.storage.k8s.io_volumesnapshotcontents.yaml
        kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v8.2.1/client/config/crd/snapshot.storage.k8s.io_volumesnapshots.yaml

        kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v8.2.1/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml
        kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v8.2.1/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml

    """

    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl delete -f https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}/crds.yaml > /dev/null 2>&1 || true
        kubectl delete -f https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}/rbac.yaml > /dev/null 2>&1 || true
        kubectl delete -f https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}/setup-controller.yaml > /dev/null 2>&1 || true

        kubectl create ns csi-addons-system

        kubectl create -f https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}/crds.yaml ${VERBOSE}
        kubectl create -f https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}/rbac.yaml ${VERBOSE}
        kubectl create -f https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}/setup-controller.yaml ${VERBOSE}
    """
    ##################################################################
    # to be able to run ceph-rook on the control plane nodes:

    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local role=$(echo "$node" | jq -r '.role')

        ssh -q ${CONTROL_PLANE_NODE} <<< """
            log -f ${CURRENT_FUNC} 'Started untainting $role node ${hostname}'
            kubectl taint nodes $hostname node-role.kubernetes.io/control-plane- > /dev/null 2>&1 || true
        """
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing ${chart_name} cluster Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install ${chart_name} ${chart_name}/${chart_name} \
            --namespace $ROOKCEPH_NS \
            --version $ROOKCEPH_VERSION \
            --set operatorNamespace=$ROOKCEPH_NS \
            -f /tmp/${chart_name}/values.yaml \
            2>&1)
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
    ssh -q "${CONTROL_PLANE_NODE}" <<< """
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
        log -f "${CURRENT_FUNC}" "ERROR" "rook-ceph cluster is not ready..."
        return 1
    else
        log -f "${CURRENT_FUNC}" "Applying http-route for rook-ceph ingress."
        scp -q ./rook-ceph-cluster/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/rook-ceph-cluster/

        ssh -q ${CONTROL_PLANE_NODE} <<< """
            kubectl apply -f /tmp/rook-ceph-cluster/http-routes.yaml ${VERBOSE}
            log -f ${CURRENT_FUNC} 'Removing completed pods'
            kubectl delete pods -n ${ROOKCEPH_NS} --field-selector=status.phase=Succeeded > /dev/null 2>&1 || true
        """

        log -f "${CURRENT_FUNC}" "Finished deploying rook-ceph cluster on the cluster."
        return 0
    fi
    ##################################################################
}


deploy_helm_chart(){
    local chart_url=$1
    local repo_name=$2
    local chart_name=$3
    local chart_ns=$4
    local chart_version=$5
    local delete_ns=$6
    local create_ns=$7
    local extra_args=$8

    ###################################################################
    log -f ${CURRENT_FUNC} "Started $chart_name helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "$chart_name" "$repo_name" "$chart_url" "$chart_ns" "$delete_ns" "$create_ns"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install $chart_name helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished $chart_name helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        sudo rm -rf /tmp/$chart_name
        mkdir -p /tmp/$chart_name
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/values.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/ > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "values.yaml file not found, generating default values..."
        ssh -q ${CONTROL_PLANE_NODE} <<< """
            helm show values $repo_name/$chart_name --version $chart_version > /tmp/$chart_name/values.yaml
        """
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing $chart_name Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # Construct the Helm command with optional extra_args
        helm_cmd=\"helm install $chart_name $repo_name/$chart_name \\
            --version $chart_version \\
            --namespace $chart_ns \\
            --create-namespace \\
            -f /tmp/$chart_name/values.yaml\"

        # Append extra_args if provided
        if [ -n \"$extra_args\" ]; then
            echo \"Deploying with extra_args: $extra_args\"
            helm_cmd=\"\$helm_cmd $extra_args\"
        else
            echo \"Deploying without extra_args\"
        fi

        echo \"helm_cmd: \$helm_cmd\"

        # Execute the command and capture output
        output=\$(eval \$helm_cmd 2>&1)

        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install $chart_name:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing $chart_name on namespace: '${chart_ns}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install $chart_name"
        return 1
    fi
    ##################################################################
    scp -q ./$chart_name/routes.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/ > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Applying routes for $chart_name on control-plane node: ${CONTROL_PLANE_NODE}"
        ssh -q ${CONTROL_PLANE_NODE} <<< """
            kubectl apply -f /tmp/$chart_name/routes.yaml ${VERBOSE}
        """
    fi
    ##################################################################
}


install_kafka_cluster() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="strimzi-kafka-cluster"
    local chart_dir="/tmp/kube-on-rehl/$chart_name"
    local timeout_=300  # 5 minutes in seconds
    local broker_secret="kafka-cluster-clients-ca"
    local client_secrets_dir=$chart_dir/secrets
    ###################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        rm -rf "$chart_dir"
        mkdir -p $chart_dir/pki
    """
    log -f ${CURRENT_FUNC} "sending $chart_name cluster-crd.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./strimzi-kafka-operator/cluster-crd.yaml $CONTROL_PLANE_NODE:$chart_dir/

    log -f ${CURRENT_FUNC} "sending $chart_name routes.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./strimzi-kafka-operator/routes.yaml $CONTROL_PLANE_NODE:$chart_dir/

    log -f ${CURRENT_FUNC} "sending $chart_name kafka-bridge.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./strimzi-kafka-operator/kafka-bridge.yaml $CONTROL_PLANE_NODE:$chart_dir/

    log -f ${CURRENT_FUNC} "sending $chart_name users.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./strimzi-kafka-operator/users.yaml $CONTROL_PLANE_NODE:$chart_dir/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name pki CRDs to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./pki/$chart_name/cluster.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/
    scp -q ./pki/$chart_name/clients.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/
    scp -q ./pki/$chart_name/brokers.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/
    ##################################################################
    # cleanup kafka PV/PVC
    if [ "$RESET_KAFKA_STORAGE" == "true" ]; then
        log -f ${CURRENT_FUNC} "Uninstalling previous Kafka-cluster in namespace $STRIMZI_KAFKA_NS..."
        ssh -q ${CONTROL_PLANE_NODE} <<< """
            kubectl delete -f $chart_dir/cluster-crd.yaml > /dev/null 2>&1
            kubectl delete -f $chart_dir/users.yaml > /dev/null 2>&1
            kubectl delete -f $chart_dir/routes.yaml > /dev/null 2>&1

            kubectl delete -f $chart_dir/pki/cluster.yaml > /dev/null 2>&1 || true
            kubectl delete -f $chart_dir/pki/clients.yaml > /dev/null 2>&1 || true
            kubectl delete -f $chart_dir/pki/brokers.yaml > /dev/null 2>&1 || true

            kubectl delete secrets kafka-cluster-clients-ca \
                -n "$STRIMZI_KAFKA_NS" > /dev/null 2>&1

            kubectl delete secrets kafka-cluster-clients-ca-cert \
                -n "$STRIMZI_KAFKA_NS" > /dev/null 2>&1

            kubectl delete secrets kafka-cluster-cluster-ca \
                -n "$STRIMZI_KAFKA_NS" > /dev/null 2>&1

            kubectl delete secrets kafka-cluster-cluster-ca-cert \
                -n "$STRIMZI_KAFKA_NS" > /dev/null 2>&1
        """
        log -f ${CURRENT_FUNC} "Deleting Kafka-related PVCs in namespace $STRIMZI_KAFKA_NS..."

        ssh -q ${CONTROL_PLANE_NODE} <<< """
            kubectl get pvc -n $STRIMZI_KAFKA_NS --no-headers -o custom-columns=\":metadata.name\" | grep '^data-' | while read pvc; do
                log -f ${CURRENT_FUNC} \"Deleting PVC: \$pvc\"

                kubectl delete pvc -n $STRIMZI_KAFKA_NS \"\$pvc\" --timeout=3s || {
                    log -f ${CURRENT_FUNC} \"Timed out waiting for \$pvc deletion, removing finalizers...\"
                    kubectl patch pvc -n $STRIMZI_KAFKA_NS \"\$pvc\" -p '{\"metadata\":{\"finalizers\":[]}}' --type=merge ${VERBOSE}
                }
            done

            log -f ${CURRENT_FUNC} 'Waiting for PVs to be released and deleted...'
            sleep 5

            log -f ${CURRENT_FUNC} 'Deleting orphaned PVs (if any)...'
            kubectl get pv --no-headers | awk '/$STRIMZI_KAFKA_NS/ {print \$1}' | while read pv; do
                log -f ${CURRENT_FUNC} \"Deleting PV: \$pv\"
                kubectl delete pv \"\$pv\" --timeout 3s ${VERBOSE}  || {
                    log -f ${CURRENT_FUNC} \"Timed out waiting for \$pv deletion, removing finalizers...\"
                    kubectl patch pv \"\$pv\" -p '{\"metadata\":{\"finalizers\":[]}}' --type=merge ${VERBOSE}
                }
            done

            sleep 30
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "[❌] Failed to clean-up Kafka-related PVCs in namespace $STRIMZI_KAFKA_NS"
            return 1
        fi
        log -f ${CURRENT_FUNC} "Finished cleaning up Kafka-related PVCs in namespace $STRIMZI_KAFKA_NS"
    fi
    #############################################################
    log -f ${CURRENT_FUNC} "Started deploying PKI for Kafka-cluster"
    # TODO: TESTONLY:
    scp -q ./pki/cluster-issuer.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/
    scp -q ./pki/role-binding.yaml $CONTROL_PLANE_NODE:$chart_dir/pki/

    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl apply -f $chart_dir/pki/cluster-issuer.yaml > /dev/null 2>&1 || true
        kubectl apply -f $chart_dir/pki/role-binding.yaml > /dev/null 2>&1 || true

        kubectl apply -f $chart_dir/pki/cluster.yaml > /dev/null 2>&1 || true
        kubectl apply -f $chart_dir/pki/clients.yaml > /dev/null 2>&1 || true
        kubectl apply -f $chart_dir/pki/brokers.yaml > /dev/null 2>&1 || true
    """
    log -f ${CURRENT_FUNC} "Finished deploying PKI for Kafka-cluster"
    ###################################################################
    log -f ${CURRENT_FUNC} "Started ensuring that kafka-cluster is deployed and running"
    ###################################################################
    log -f ${CURRENT_FUNC} "Waiting for broker_secret: $broker_secret to become Ready (timeout: ${timeout_}s)..."
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        INTERVAL=5
        ELAPSED=0
        while true; do
            kubectl get secrets $broker_secret -n '$STRIMZI_KAFKA_NS' > /dev/null 2>&1
            if [ \$? -eq 0 ]; then
                log -f ${CURRENT_FUNC} \"✅ broker_secret: $broker_secret is Ready\"
                exit 0
            fi

            if [ \"\$ELAPSED\" -ge \"$timeout_\" ]; then
                log -f ${CURRENT_FUNC} 'ERROR' '[❌] Timeout reached! broker_secret: $broker_secret is not Ready after $timeout_ seconds'
                exit 1
            fi
            sleep \"\$INTERVAL\"
            ELAPSED=\$((ELAPSED + INTERVAL))
        done
    """
    if [ $? -ne 0 ]; then
        return 1
    fi
    log -f ${CURRENT_FUNC} "✅ Finished waiting for broker_secret: $broker_secret to become Ready"
    ###################################################################
    log -f ${CURRENT_FUNC} "Started deploying kafka-cluster CRDS"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl apply -f $chart_dir/routes.yaml > /dev/null 2>&1
        kubectl apply -f $chart_dir/cluster-crd.yaml > /dev/null 2>&1
        kubectl apply -f $chart_dir/users.yaml > /dev/null 2>&1
    """
    ###################################################################
    local pod_name="kafka-cluster-controller-0"
    log -f ${CURRENT_FUNC} "Waiting for controller pod $pod_name to become Ready (timeout: ${timeout_}s)..."
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        INTERVAL=5
        ELAPSED=0
        while true; do
            STATUS=\$(kubectl get pod $pod_name -n '$STRIMZI_KAFKA_NS' -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo 'false')
            if [ \"\$STATUS\" == \"true\" ]; then
                log -f ${CURRENT_FUNC} '✅ $pod_name is Ready'
                exit 0
            fi

            if [ \"\$ELAPSED\" -ge \"$timeout_\" ]; then
                log -f ${CURRENT_FUNC} 'ERROR' '[❌] Timeout reached: $pod_name is not Ready after $timeout_ seconds'
                exit 1
            fi
            sleep \"\$INTERVAL\"
            ELAPSED=\$((ELAPSED + INTERVAL))
        done
    """
    if [ $? -ne 0 ]; then
        return 1
    fi
    log -f ${CURRENT_FUNC} "✅ Finished deploying kafka-cluster CRDS"
    ###################################################################
    log -f ${CURRENT_FUNC} "Waiting for kafka-cluster svcs to become Ready (timeout: ${timeout_}s)..."
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        INTERVAL=5
        ELAPSED=0
        broker_svc=''
        while true; do
            broker_svc=\$(kubectl get svc -n '$STRIMZI_KAFKA_NS' -o json | jq -r '.items[] | select(.metadata.name | test(\"kafka-cluster-broker-.*\")) | .metadata.name' | head -n1) 2>&1
            if [ ! -z \"\$broker_svc\" ]; then
                log -f ${CURRENT_FUNC} \"✅ broker_svc: \$broker_svc is Ready\"
                exit 0
            fi

            if [ \"\$ELAPSED\" -ge \"$timeout_\" ]; then
                log -f ${CURRENT_FUNC} 'ERROR' '[❌] Timeout reached! broker_svc is not Ready after $timeout_ seconds'
                exit 1
            fi
            sleep \"\$INTERVAL\"
            ELAPSED=\$((ELAPSED + INTERVAL))
        done
    """
    if [ $? -ne 0 ]; then
        return 1
    fi
    log -f ${CURRENT_FUNC} "✅ Kafka-cluster svcs are Ready!"
    ###################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        INTERVAL=5
        ELAPSED=0

        readarray -t users_secrets < <(yq eval-all '.metadata.name' $chart_dir/users.yaml | grep -v '^---$')
        if [ -z "\$users_secrets" ]; then
            log -f ${CURRENT_FUNC} 'ERROR' '[❌] No users secrets found in users.yaml'
            exit 1
        fi

        log -f ${CURRENT_FUNC} \"Waiting for broker_secret: \${users_secrets[0]} to become Ready (timeout: \${timeout_}s)...\"

        while true; do
            kubectl get secrets \"\${users_secrets[0]}\" -n '$STRIMZI_KAFKA_NS' > /dev/null 2>&1
            if [ \$? -eq 0 ]; then
                log -f ${CURRENT_FUNC} \"✅ broker_secret: '\${users_secrets[0]}' is Ready\"
                log -f ${CURRENT_FUNC} \"✅ Finished waiting for broker_secret: '\${users_secrets[0]}' to become Ready\"
                exit 0
            fi

            if [ \"\$ELAPSED\" -ge \"$timeout_\" ]; then
                log -f ${CURRENT_FUNC} 'ERROR' \"[❌] Timeout reached! broker_secret: '\${users_secrets[0]}' is not Ready after $timeout_ seconds\"
                exit 1
            fi
            sleep \"\$INTERVAL\"
            ELAPSED=\$((ELAPSED + INTERVAL))
        done
    """
    if [ $? -ne 0 ]; then
        return 1
    fi
    ###################################################################
    log -f ${CURRENT_FUNC} "Exporting broker_secrets for testing..."
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        rm -rf '$client_secrets_dir' && mkdir -p '$client_secrets_dir'

        readarray -t users_secrets < <(yq eval-all '.metadata.name' $chart_dir/users.yaml | grep -v '^---$')


        kubectl get secret brokers-tls-cert  \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.ca\.crt}' | base64 -d  \
            > $client_secrets_dir/brokers-ca.crt

        kubectl get secret \${users_secrets[0]}  \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.user\.key}' | base64 -d \
            > $client_secrets_dir/\${users_secrets[0]}.key

        kubectl get secret \${users_secrets[0]}  \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.user\.crt}' | base64 -d \
            > $client_secrets_dir/\${users_secrets[0]}.crt

        kubectl get secret kafka-cluster-clients-ca-cert \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.ca\.crt}' | base64 -d  \
            > $client_secrets_dir/clients-ca.crt
    """
    log -f ${CURRENT_FUNC} "✅ Finished exporting broker_secrets."
    ###################################################################
    log -f ${CURRENT_FUNC} "Testing kafka-cluster sshl handshake..."
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        readarray -t users_secrets < <(yq eval-all '.metadata.name' $chart_dir/users.yaml | grep -v '^---$')
        openssl verify -CAfile '$client_secrets_dir/clients-ca.crt' \"$client_secrets_dir/\${users_secrets[0]}.crt\"  > /dev/null 2>&1
        if [ \$? -ne 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"[❌] Client: '\${users_secrets[0]}' certificate verification failed against clients-ca\"
            exit 1
        fi
    """
    if [ $? -ne 0 ]; then
        return 1
    fi
    log -f ${CURRENT_FUNC} "✅ Finished testing client certificate verification against cluster-ca"
    ###################################################################
    log -f ${CURRENT_FUNC} "Testing kafka-cluster connection..."
    local address="$KAFKA_BROKER_0_FQDN:$KAFKA_BROKERS_TLS_PORT"
    # openssl s_client -connect $address -showcerts -CAfile /tmp/kafka-client/secrets/brokers-ca.crt --cert /tmp/kafka-client/secrets/$broker_secret.crt --key /tmp/kafka-client/secrets/$broker_secret.key
    # openssl s_client -connect $address -showcerts -CAfile  </dev/null   | openssl x509 -outform PEM > /tmp/kafka-server.crt
    # -X debug=security  # -X enable.ssl.certificate.verification=false \
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        readarray -t users_secrets < <(yq eval-all '.metadata.name' $chart_dir/users.yaml | grep -v '^---$')

        kcat -b '$address' -L -m 15 \
            -X security.protocol=ssl \
            -X ssl.key.location=\"$client_secrets_dir/\${users_secrets[0]}.key\" \
            -X ssl.certificate.location=\"$client_secrets_dir/\${users_secrets[0]}.crt\" \
            -X ssl.ca.location='$client_secrets_dir/brokers-ca.crt' > /dev/null 2>&1
        if [ \$? -ne 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"[❌] Kafka-cluster connection test failed! Failed to connect to '$address'\"
            # rm -rf $client_secrets_dir
            exit 1
        fi
        # rm -rf $client_secrets_dir
        exit 0
    """
    if [ $? -ne 0 ]; then
        return 1
    fi
    log -f ${CURRENT_FUNC} "✅ Finished testing kafka-cluster connection"
    ###################################################################
    log -f ${CURRENT_FUNC} "✅ Finished testing kafka-cluster successfully"
    return 0
}


generate_certs(){
    local tls_secret=$1
    local ca_password=$2
    local secrets_path=$3
    local sign_cert=${4:-false}
    mkdir -p $secrets_path
    # local org=$3
    # local org_unit=$4
    # local broker_cert_chain=$5

    # if [ "$tls_secret" = "clients-ca" ]; then
    #     local sign_cert=true
    # fi
    # 1. Generate private key
    # openssl genrsa -out ${tls_secret}.key 4096

    if [ "$sign_cert" = true ]; then
        log -f ${CURRENT_FUNC} "Generating private key and CSR for $tls_secret..."
        openssl genrsa -out "$secrets_path/$tls_secret.key" 4096

        openssl req -new -key "$secrets_path/$tls_secret.key" -out "$secrets_path/$tls_secret.csr" -subj "/CN=$tls_secret"

        log -f ${CURRENT_FUNC} "Signing $tls_secret CSR with cluster-ca..."
        # Assumes cluster-ca.key and cluster-ca.crt exist in $secrets_path
        openssl x509 -req -in "$secrets_path/$tls_secret.csr" \
            -CA "$secrets_path/cluster-ca.crt" \
            -CAkey "$secrets_path/cluster-ca.key" \
            -CAcreateserial \
            -out "$secrets_path/$tls_secret.crt" \
            -days 365

        # Clean up CSR and serial
        rm -f "$secrets_path/$tls_secret.csr" "$secrets_path/cluster-ca.srl"
    else
        log -f ${CURRENT_FUNC} "Generating self-signed cert for $tls_secret..."
        openssl req -x509 -new -nodes -keyout "$secrets_path/$tls_secret.key" \
            -out "$secrets_path/$tls_secret.crt" -days 365 -subj "/CN=$tls_secret"
    fi



    log -f ${CURRENT_FUNC} "Generating PKCS12 for $tls_secret..."
    openssl pkcs12 -export \
        -in "$secrets_path/$tls_secret.crt" \
        -inkey "$secrets_path/$tls_secret.key" \
        -out "$secrets_path/$tls_secret.p12" \
        -caname ca.crt \
        -password pass:"$ca_password"


    secret_ca_cert_name="${KAFKA_CLUSTER_NAME}-$tls_secret-cert"
    log -f ${CURRENT_FUNC} "Creating Kubernetes secrets for $tls_secret..."
    kubectl delete secret  -n $STRIMZI_KAFKA_NS $secret_ca_cert_name --ignore-not-found
    kubectl create secret generic $secret_ca_cert_name \
        -n $STRIMZI_KAFKA_NS \
        --from-file=ca.crt="$secrets_path/${tls_secret}.crt" \
        --from-file=ca.p12="$secrets_path/${tls_secret}.p12" \
        --from-literal=ca.password="$ca_password"

    kubectl label secret $secret_ca_cert_name -n $STRIMZI_KAFKA_NS \
        strimzi.io/kind=Kafka strimzi.io/cluster="$KAFKA_CLUSTER_NAME" --overwrite
    kubectl annotate secret $secret_ca_cert_name -n $STRIMZI_KAFKA_NS \
        strimzi.io/ca-cert-generation="0" --overwrite


    secret_ca_name="${KAFKA_CLUSTER_NAME}-$tls_secret"

    kubectl delete secret $secret_ca_name \
        -n $STRIMZI_KAFKA_NS \
        --ignore-not-found
    kubectl create secret generic $secret_ca_name \
        -n $STRIMZI_KAFKA_NS \
        --from-file=ca.crt="$secrets_path/${tls_secret}.crt" \
        --from-file=ca.key="$secrets_path/${tls_secret}.key"

    kubectl label secret $secret_ca_name -n $STRIMZI_KAFKA_NS \
        strimzi.io/kind=Kafka strimzi.io/cluster="$KAFKA_CLUSTER_NAME" --overwrite
    kubectl annotate secret $secret_ca_name \
        -n $STRIMZI_KAFKA_NS \
        strimzi.io/ca-key-generation="0" --overwrite
    #############################################################
    return 0
    ###########################################################
    export broker_address=10.66.65.10
    export broker_port=31698

    # export broker_secret=brokers-tls-cert
    export broker_secret=ifoughali
    export client_secrets_dir=/tmp/kafka-client/secrets/

    mkdir -p $client_secrets_dir
    kubectl get secret $broker_secret -o jsonpath='{.data.user\.key}' | base64 -d > $client_secrets_dir/$broker_secret.key

    kubectl get secret $broker_secret -o jsonpath='{.data.user\.crt}' | base64 -d > $client_secrets_dir/$broker_secret.crt

    kubectl get secret $broker_secret -o jsonpath='{.data.ca\.crt}' | base64 -d  > $client_secrets_dir/$broker_secret-ca.crt


    kcat -b "$broker_address:$broker_port" -L \
        -X security.protocol=ssl \
        -X ssl.key.location="$client_secrets_dir/$broker_secret.key" \
        -X ssl.certificate.location="$client_secrets_dir/$broker_secret.crt" \
        -X ssl.ca.location="$client_secrets_dir/$broker_secret-ca.crt"

    kcat -b "$broker_address:$broker_port" -L \
        -X security.protocol=ssl \
        -X ssl.key.location="$client_secrets_dir/$broker_secret.key" \
        -X ssl.certificate.location="$client_secrets_dir/$broker_secret.crt" \
        -X ssl.ca.location="clients-ca.crt" \
        -X enable.ssl.certificate.verification=false
    ###########################################################
    return 0

















#     # 2. Generate CSR with SANs (using process substitution)
#     openssl req -new \
#     -key ${tls_secret}.key \
#     -out ${tls_secret}.csr \
#     -subj "/CN=$KAFKA_CLUSTER_NAME-$tls_secret/O=$org/OU=$org_unit/C=FR/ST=Île-de-France/L=Paris" \
#     -reqexts SAN \
#     -config <(cat <<EOF
# [req]
# distinguished_name = req_distinguished_name
# req_extensions = SAN

# [req_distinguished_name]
# CN = $KAFKA_CLUSTER_NAME-$tls_secret
# O = $org
# OU = $org_unit
# C = FR
# ST = Île-de-France
# L = Paris

# [SAN]
# subjectAltName=DNS:*.kafka,DNS:*.$STRIMZI_KAFKA_NS.svc,DNS:*.$STRIMZI_KAFKA_NS.svc.cluster.local,DNS:kafka-broker-0.pfs.pack,DNS:kafka-broker-1.pfs.pack,DNS:kafka-broker-2.pfs.pack,DNS:kafka-bootstrap.pfs.pack,IP:10.66.65.10,IP:10.66.65.11,IP:10.66.65.12
# EOF
# )

#     # 3. Sign CSR with the broker CA cert and key
#     openssl x509 -req -in ${tls_secret}.csr \
#     -CA $broker_cert_chain.crt -CAkey $broker_cert_chain.key \
#     -CAcreateserial -out ${tls_secret}.crt -days 365 -sha256 \
#     -extensions SAN \
#     -extfile <(cat <<EOF
# [SAN]
# subjectAltName=DNS:*.kafka,DNS:*.$STRIMZI_KAFKA_NS.svc,DNS:*.$STRIMZI_KAFKA_NS.svc.cluster.local,DNS:kafka-broker-0.pfs.pack,DNS:kafka-broker-1.pfs.pack,DNS:kafka-broker-2.pfs.pack,DNS:kafka-bootstrap.pfs.pack,IP:10.66.65.10,IP:10.66.65.11,IP:10.66.65.12
# EOF
# )

#     # 4. Generate PKCS#12 bundle (Java-friendly)
#     openssl pkcs12 -export -in ${tls_secret}.crt \
#     -inkey ${tls_secret}.key  \
#     -out ${tls_secret}.p12 \
#     -certfile $broker_cert_chain.crt \
#     -password pass:${ca_password}

#     # openssl pkcs12 -export -in  ${tls_secret}.crt \
#     #     -nokeys -out -out ${tls_secret}.p12 \
#     #     -password pass:${ca_password} \
#     #     -caname ca.crt


#     # Replace the cluster CA cert secret in Kubernetes
#     kubectl delete secret ${KAFKA_CLUSTER_NAME}-$tls_secret-cert --ignore-not-found
#     kubectl create secret generic ${KAFKA_CLUSTER_NAME}-$tls_secret-cert \
#     --from-file=ca.crt=${tls_secret}.crt \
#     --from-file=ca.p12=${tls_secret}.p12 \
#     --from-literal=ca.password=${ca_password}


#     kubectl label secret  $KAFKA_CLUSTER_NAME-$tls_secret-cert strimzi.io/kind=Kafka strimzi.io/cluster="$KAFKA_CLUSTER_NAME" --overwrite


#     kubectl annotate secret  $KAFKA_CLUSTER_NAME-$tls_secret-cert strimzi.io/ca-cert-generation="0" --overwrite

#     kubectl delete secret $KAFKA_CLUSTER_NAME-$tls_secret
#     kubectl create secret generic $KAFKA_CLUSTER_NAME-$tls_secret \
#         --from-file=ca.crt=./${tls_secret}.crt \
#         --from-file=ca.key=./${tls_secret}.key

#     kubectl label secret $KAFKA_CLUSTER_NAME-$tls_secret strimzi.io/kind=Kafka strimzi.io/cluster="$KAFKA_CLUSTER_NAME" --overwrite

#     kubectl annotate secret $KAFKA_CLUSTER_NAME-$tls_secret strimzi.io/ca-key-generation="0" --overwrite
#     #############################################################



#     tls_secret=clients-ca

#     openssl genrsa -out $tls_secret.key 4096

#     openssl req -x509 -new -nodes -key $tls_secret.key -sha256 -days 365 -out $tls_secret.crt -subj "/CN=$KAFKA_CLUSTER_NAME-$tls_secret"
#     #############################################################
#     kubectl delete secret $KAFKA_CLUSTER_NAME-$tls_secret-cert
#     kubectl create secret generic $KAFKA_CLUSTER_NAME-$tls_secret-cert --from-file=ca.crt=$tls_secret.crt



#     kubectl label secret  $KAFKA_CLUSTER_NAME-$tls_secret-cert strimzi.io/kind=Kafka strimzi.io/cluster="$KAFKA_CLUSTER_NAME" --overwrite

#     kubectl annotate secret $KAFKA_CLUSTER_NAME-$tls_secret-cert strimzi.io/ca-cert-generation="0" --overwrite

#     kubectl delete secret $KAFKA_CLUSTER_NAME-$tls_secret
#     kubectl create secret generic $KAFKA_CLUSTER_NAME-$tls_secret \
#         --from-file=ca.crt=./$tls_secret.crt \
#         --from-file=ca.key=./$tls_secret.key

#     kubectl label secret $KAFKA_CLUSTER_NAME-$tls_secret strimzi.io/kind=Kafka strimzi.io/cluster="$KAFKA_CLUSTER_NAME" --overwrite

#     kubectl annotate secret $KAFKA_CLUSTER_NAME-$tls_secret strimzi.io/ca-key-generation="0" --overwrite







#     ###########################################################
#     export broker_address=10.66.65.10
#     export broker_port=32084

#     # export broker_secret=brokers-tls-cert
#     export broker_secret=ifoughali
#     export client_secrets_dir=/tmp/kafka-client/secrets/

#     mkdir -p $client_secrets_dir
#     kubectl get secret $broker_secret -o jsonpath='{.data.user\.key}' | base64 -d > $client_secrets_dir/$broker_secret.key

#     kubectl get secret $broker_secret -o jsonpath='{.data.user\.crt}' | base64 -d > $client_secrets_dir/$broker_secret.crt

#     kubectl get secret $broker_secret -o jsonpath='{.data.ca\.crt}' | base64 -d  > $client_secrets_dir/$broker_secret-ca.crt


#     kcat -b "$broker_address:$broker_port" -L \
#         -X security.protocol=ssl \
#         -X ssl.key.location="$client_secrets_dir/$broker_secret.key" \
#         -X ssl.certificate.location="$client_secrets_dir/$broker_secret.crt" \
#         -X ssl.ca.location="$client_secrets_dir/$broker_secret-ca.crt"

#     kcat -b "$broker_address:$broker_port" -L \
#         -X security.protocol=ssl \
#         -X ssl.key.location="$client_secrets_dir/$broker_secret.key" \
#         -X ssl.certificate.location="$client_secrets_dir/$broker_secret.crt" \
#         -X ssl.ca.location="$client_secrets_dir/$broker_secret-ca.crt" \
#         -X enable.ssl.certificate.verification=false



#     # TODO: make sure they match :
#     openssl rsa -noout -modulus -in "$client_secrets_dir/$broker_secret.key" | openssl md5
#     openssl rsa -noout -modulus -in "$client_secrets_dir/$broker_secret.key" | openssl md5

































#     kubectl create secret generic <ca_key_secret> --from-file=ca.key=ca.key



#     kubectl delete -f strimzi-kafka-operator/cluster-crd.yaml

#     kubectl delete -f strimzi-kafka-operator/pki/clients.yaml
#     kubectl delete -f strimzi-kafka-operator/pki/cluster.yaml
#     kubectl delete -f strimzi-kafka-operator/pki/kafka-issuer.yaml
#     kubectl delete -f strimzi-kafka-operator/brokers.yaml

#     kubectl delete secret -n $STRIMZI_KAFKA_NS \
#         kafka-cluster-clients-ca \
#         kafka-cluster-clients-ca-cert \
#         kafka-cluster-cluster-ca  \
#         kafka-cluster-cluster-ca-cert \
#         kafka-cluster-cluster-operator-certs \
#         kafka-root-ca \
#         brokers-tls-cert

#     # kubectl delete -f strimzi-kafka-operator/pki/role-binding.yaml

#     kubectl apply -f strimzi-kafka-operator/pki/kafka-issuer.yaml

#     kubectl apply -f strimzi-kafka-operator/pki/clients.yaml
#     kubectl apply -f strimzi-kafka-operator/pki/cluster.yaml
#     kubectl apply -f strimzi-kafka-operator/pki/brokers.yaml

#     sleep 10

#     kubectl delete pod -n ${STRIMZI_KAFKA_NS}  --field-selector=status.phase=Succeeded > /dev/null 2>&1 || true

#     kubectl apply -f strimzi-kafka-operator/cluster-crd.yaml






#         secret=kafka-cluster-controller-0

#         kubectl get secrets $secret  -o yaml > secrets/$secret.yaml









#     rm -f /tmp/strimzi-kafka-truststore-$kafka_user_2.jks
#     keytool -delete -alias ca -keystore /tmp/strimzi-kafka-truststore-$kafka_user_2.jks -storepass $store_pass



#     keytool -importcert -alias ca -file /tmp/ca.crt -keystore /tmp/truststore-$kafka_user_2.jks -storepass $store_pass -noprompt

#     keytool -import -trustcacerts -alias kafka-ca-$store_pass -file /tmp/ca.crt -keystore /tmp/truststore-$kafka_user_2.jks -storepass $store_pass -noprompt

#     kubectl delete secret ssl-$kafka_user_2 -n $STRIMZI_KAFKA_NS
#     kubectl create secret generic ssl-$kafka_user_2 --from-file=truststore.jks=/tmp/truststore-$kafka_user_2.jks -n $STRIMZI_KAFKA_NS

#     # kubectl create configmap ssl-$kafka_user_2 --from-file=truststore.jks=/tmp/truststore-$kafka_user_2.jks -n $STRIMZI_KAFKA_NS



#     # TODO: make sure they match :
#     openssl rsa -noout -modulus -in "$client_secrets_dir/$broker_secret.key" | openssl md5
#     openssl rsa -noout -modulus -in "$client_secrets_dir/$broker_secret.key" | openssl md5


#     openssl s_client -connect kafka-bootstrap.pfs.pack:9092 -showcerts </dev/null   | openssl x509 -outform PEM > /tmp/kafka-server.crt

#     rm /tmp/truststore-$kafka_user_2.jks

#     keytool -import -trustcacerts -alias kafka-ca-$store_pass -file /tmp/kafka-server.crt -keystore /tmp/truststore-$kafka_user_2.jks -storepass $store_pass -noprompt

#     kubectl delete secret ssl-$kafka_user_2 -n $STRIMZI_KAFKA_NS
#     kubectl create secret generic ssl-$kafka_user_2 --from-file=truststore.jks=/tmp/truststore-$kafka_user_2.jks -n $STRIMZI_KAFKA_NS



#     ########################################################


#     JAAS_CONFIG=$(kubectl get secret $kafka_user_2 -o json | jq '.data."sasl.jaas.config"' | tr -d '"' | base64 --decode)
# #     cat <<EOF > /tmp/kafka-user-$kafka_user_2-config.properties
# # bootstrap.servers=kafka-bootstrap.pfs.pack:9092
# # sasl.jaas.config=$JAAS_CONFIG
# # security.protocol=SSL
# # sasl.mechanism=SCRAM-SHA-512
# # ssl.truststore.location=/tmp/strimzi-kafka-truststore.jks
# # ssl.truststore.password=$store_pass
# # EOF

#     cat <<EOF > /tmp/kafka-user-$kafka_user_2-config.properties
# bootstrap.servers=kafka-bootstrap.pfs.pack:9092
# enable.ssl.certificate.verification=false
# sasl.jaas.config=$JAAS_CONFIG
# security.protocol=SASL_SSL
# sasl.mechanism=SCRAM-SHA-512
# ssl.truststore.location=/tmp/kafka-truststore/truststore.jks
# ssl.truststore.password=$store_pass
# EOF
# # #     ########################################################
#     kubectl delete configmap kafka-user-$kafka_user_2-config -n $STRIMZI_KAFKA_NS
#     kubectl create configmap kafka-user-$kafka_user_2-config --from-file=kafka-client-config.properties=/tmp/kafka-user-$kafka_user_2-config.properties -n $STRIMZI_KAFKA_NS





# #     kubectl delete -f strimzi-kafka-operator/kafka-prodcon-test.yaml
# #     kubectl apply -f strimzi-kafka-operator/kafka-prodcon-test.yaml

#     ###################################################################
#     # TS:
#     # openssl s_client -debug -connect kafka-bootstrap.pfs.pack:9092 -tls1_3
#     # test if port and fqdn is reachable
#     # from host: nc -zv kafka-broker-0.pfs.pack 9092
#     # kubectl exec -ti deployments/producer -- nc -zv kafka-cluster-kafka-external1-bootstrap 9092
#     ###################################################################



#     # TODO: CHECK FOR KAFKA CLUSTER STATUS in a loop....
#     #  kubectl get kafka kafka-cluster -o=jsonpath='{.spec.kafka.listeners[?(@.name=="external")].bootstrapServers}{"\n"}'
#     # kafka-cluster-kafka-external-bootstrap.strimzi-kafka.svc:9094
}


install_kafka_operator() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_url="https://strimzi.io/charts/"
    local repo_name="strimzi"
    local chart_name="strimzi-kafka-operator"
    local chart_ns="$STRIMZI_KAFKA_OPERATOR_NS"
    local chart_version=$STRIMZI_KAFKA_OPERATOR_VERSION
    local delete_ns=true
    local create_ns=false

    if [ "$RESET_KAFKA_STORAGE" == "true" ]; then
        local delete_ns=true
    fi
    ##################################################################
    # cleanup kafka PV/PVC
    if [ "$RESET_KAFKA_STORAGE" == "true" ]; then
        log -f ${CURRENT_FUNC} "Uninstalling previous Kafka-cluster in namespace $STRIMZI_KAFKA_NS..."
        ssh -q ${CONTROL_PLANE_NODE} <<< """
            kubectl delete -f /tmp/$chart_name/cluster-crd.yaml > /dev/null 2>&1
        """
        log -f ${CURRENT_FUNC} "Deleting Kafka-related PVCs in namespace $STRIMZI_KAFKA_NS..."

        ssh -q ${CONTROL_PLANE_NODE} <<< """
            kubectl get pvc -n $STRIMZI_KAFKA_NS --no-headers -o custom-columns=\":metadata.name\" | grep '^data-' | while read pvc; do
                log -f ${CURRENT_FUNC} \"Deleting PVC: \$pvc\"

                kubectl delete pvc -n $STRIMZI_KAFKA_NS \"\$pvc\" --timeout=3s || {
                    log -f ${CURRENT_FUNC} \"Timed out waiting for \$pvc deletion, removing finalizers...\"
                    kubectl patch pvc -n $STRIMZI_KAFKA_NS \"\$pvc\" -p '{\"metadata\":{\"finalizers\":[]}}' --type=merge ${VERBOSE}
                }
            done

            log -f ${CURRENT_FUNC} 'Waiting for PVs to be released and deleted...'
            sleep 5

            log -f ${CURRENT_FUNC} 'Deleting orphaned PVs (if any)...'
            kubectl get pv --no-headers | awk '/$STRIMZI_KAFKA_NS/ {print \$1}' | while read pv; do
                log -f ${CURRENT_FUNC} \"Deleting PV: \$pv\"
                kubectl delete pv \"\$pv\" --timeout 3s ${VERBOSE}  || {
                    log -f ${CURRENT_FUNC} \"Timed out waiting for \$pv deletion, removing finalizers...\"
                    kubectl patch pv \"\$pv\" -p '{\"metadata\":{\"finalizers\":[]}}' --type=merge ${VERBOSE}
                }
            done

            log -f ${CURRENT_FUNC} 'Deleting KafkaTopics (if any)...'
            kubectl get kafkatopics.kafka.strimzi.io -n \"$STRIMZI_KAFKA_NS\" -o jsonpath='{range .items[*]}{.metadata.name}{\"\n\"}{end}' | while read topic; do
                kubectl delete kafkatopic.kafka.strimzi.io \"\$topic\" -n \"$STRIMZI_KAFKA_NS\" --timeout 3s ${VERBOSE}  || {
                    log -f ${CURRENT_FUNC} \"Timed out waiting for \$topic deletion, removing finalizers...\"
                    kubectl patch kafkatopic.kafka.strimzi.io \"\$topic\" -p '{\"metadata\":{\"finalizers\":[]}}' --type=merge ${VERBOSE}
                }
            done
        """
        if [ $? -ne 0 ]; then
            return 1
        fi
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Uninstalling and removing previous Kafka-cluster in namespace $STRIMZI_KAFKA_NS..."
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        set +euo pipefail

        kubectl delete all --all -n $STRIMZI_KAFKA_NS --timeout 3s --force --grace-period=0 > /dev/null 2>&1
        kubectl delete pods --all -n $STRIMZI_KAFKA_NS --timeout 3s --force --grace-period=0 > /dev/null 2>&1

        kubectl delete pods -l strimzi.io/name=kafka-cluster-kafka -n $STRIMZI_KAFKA_NS --force --grace-period=0 > /dev/null 2>&1

        log -f ${CURRENT_FUNC} 'Deleting namespace $STRIMZI_KAFKA_NS...'
        output=\$(kubectl delete ns $STRIMZI_KAFKA_NS --timeout 3s 2>&1)
        if [ \$? -ne 0 ]; then
            log -f ${CURRENT_FUNC} 'Failed to delete namespace $STRIMZI_KAFKA_NS...Attempting to remove finalizers...'            kubectl patch namespace $STRIMZI_KAFKA_NS -p '{\"metadata\":{\"finalizers\":null}}' --type=merge > /dev/null 2>&1 || true

            kubectl patch namespace $STRIMZI_KAFKA_NS -p '{\"spec\":{\"finalizers\":[]}}' --type=merge > /dev/null 2>&1 || true

            kubectl get namespace $STRIMZI_KAFKA_NS -o json > /tmp/strimzi-ns.json > /dev/null 2>&1 || true

            jq 'del(.spec.finalizers)' /tmp/strimzi-ns.json > /tmp/strimzi-ns-clean.json > /dev/null 2>&1 || true

            kubectl replace --raw '/api/v1/namespaces/$STRIMZI_KAFKA_NS/finalize' -f strimzi-ns-clean.json > /dev/null 2>&1 || true
        fi

        log -f ${CURRENT_FUNC} 'Creating namespace $STRIMZI_KAFKA_NS...'
        output=\$(kubectl create ns $STRIMZI_KAFKA_NS 2>&1)
        if [ \$? -ne 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to create namespace $STRIMZI_KAFKA_NS...\n\t\$output\"
            exit 1
        fi
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to uninstall and remove previous Kafka-cluster in namespace $STRIMZI_KAFKA_NS"
        return 1
    fi
    ###################################################################
    log -f ${CURRENT_FUNC} "Started $chart_name helm chart prerequisites"
    helm_chart_prerequisites "$CONTROL_PLANE_NODE" "$chart_name" "$repo_name" "$chart_url" "$chart_ns" "$delete_ns" "$create_ns"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install kafka helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished $chart_name helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        sudo rm -rf /tmp/$chart_name
        mkdir -p /tmp/$chart_name
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name values-$chart_version.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/values-$chart_version.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing $chart_name Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install $chart_name $repo_name/$chart_name \
            --version $chart_version \
            --namespace $chart_ns \
            --create-namespace \
            -f /tmp/$chart_name/values-$chart_version.yaml \
            2>&1)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install $chart_name:\n\t\${output}\"
            exit 1
        fi

        # log -f ${CURRENT_FUNC} 'WARNING' \"Initiating workaround to force the install on kubenerete 1.33\"
        # kubectl -n $chart_ns set env deployment/strimzi-cluster-operator STRIMZI_KUBERNETES_VERSION=\"major=1,minor=33\" > /dev/null 2>&1 || true

        # kubectl -n $chart_ns rollout restart deployment strimzi-cluster-operator > /dev/null 2>&1 || true

        log -f ${CURRENT_FUNC} 'INFO' 'Waiting for the strimzi-cluster-operator to be ready...'
        sleep 60
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install kafka helm chart"
        return 1
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing kafkacat on the cluster nodes:"
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "Restarting cilium PIDs on $role node ${hostname}"
        ssh -q ${hostname} <<< """
            if command -v kcat &> /dev/null; then
                log -f ${CURRENT_FUNC} 'kafkacat is already installed on nodes: $hostname'
                exit 0
            else
                sudo dnf update -y
                sudo dnf install librdkafka-devel -y
                cd /tmp
                git clone https://github.com/edenhill/kcat.git -b 1.7.1
                cd kcat
                ./configure
                make
                sudo make install
                rm -rf /tmp/kcat
                log -f ${CURRENT_FUNC} 'Finished installing kafkacat on node: $hostname'

            fi
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} "ERROR" "Failed to install kafkacat on nodes: $hostname"
        fi
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished deploying kafka on the cluster."
    ##################################################################
    return 0
}


install_akhq() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="kafka-akhq"
    log -f ${CURRENT_FUNC} "Started $chart_name helm chart prerequisites"
    helm_chart_prerequisites ${CONTROL_PLANE_NODE} $chart_name "akhq" "https://akhq.io/" "$STRIMZI_KAFKA_NS"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install $chart_name helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished $chart_name helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        rm -rf /tmp/$chart_name &&  mkdir -p /tmp/$chart_name
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/values.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name http-routes.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing $chart_name Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install $chart_name $chart_name/akhq \
            --namespace $STRIMZI_KAFKA_NS \
            --create-namespace \
            --version $KAFKA_AKHQ_VERSION \
            -f /tmp/$chart_name/values.yaml \
            2>&1)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install kafka:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing $chart_name on namespace: '${STRIMZI_KAFKA_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install $chart_name"
        return 1
    fi
    # ##################################################################
    # log -f $CURRENT_FUNC "applying http-routes for $chart_name ingress"
    # ssh -q ${CONTROL_PLANE_NODE} <<< """
    #     kubectl apply -f /tmp/$chart_name/http-routes.yaml ${VERBOSE}
    # """
    ##################################################################
}


install_kafka_ui() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="kafka-ui"
    ###################################################################
    log -f ${CURRENT_FUNC} "Started $chart_name helm chart prerequisites"
    helm_chart_prerequisites ${CONTROL_PLANE_NODE} $chart_name "kafbat" "https://ui.charts.kafbat.io/" "$STRIMZI_KAFKA_NS"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install $chart_name helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished $chart_name helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        rm -rf /tmp/$chart_name &&  mkdir -p /tmp/$chart_name
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/values.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name http-routes.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "Ensuring that 'keytool' command is available on the control-plane node: ${CONTROL_PLANE_NODE}"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        set -euo pipefail
        if command -v keytool &> /dev/null; then
            log -f ${CURRENT_FUNC} 'keytool is already installed on the control-plane node: $CONTROL_PLANE_NODE'
        else
            log -f ${CURRENT_FUNC} 'keytool is not installed, installing it...'
            sudo dnf install java-17-openjdk-headless -y > /dev/null 2>&1
        fi
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install keytool on the control-plane node: $CONTROL_PLANE_NODE"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished ensuring that 'keytool' command is available on the control-plane node: ${CONTROL_PLANE_NODE}"
    ##################################################################
    log -f ${CURRENT_FUNC} "Exporting '$KAFKA_UI_USER' secrets for truststore and keystore creation"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        client_secrets_dir='/tmp/kube-on-rehl/kafka-ui/secrets'
        rm -rf \$client_secrets_dir && mkdir -p \$client_secrets_dir
        cd \$client_secrets_dir
        ###################################################################
        log -f ${CURRENT_FUNC} 'Creating truststore.jks for kafka-ui'
        ca_certs=(
            brokers-tls-cert
            kafka-clients-tls-cert
            kafka-cluster-tls-cert
            kafka-cluster-clients-ca
            kafka-cluster-cluster-ca
        )
        ###################################################################
        log -f ${CURRENT_FUNC} 'Started exporting kafka ca-certs for truststore creation'
        kubectl get cm kube-root-ca.crt \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.ca\.crt}'  \
            > \$client_secrets_dir/kube-root-ca.crt
        for alias in \"\${ca_certs[@]}\"; do
            if [ \$alias == "kube-root-ca" ]; then
                continue
            fi
            kubectl get secrets \$alias \
                -n $STRIMZI_KAFKA_NS \
                -o jsonpath='{.data.ca\.crt}' | base64 -d \
                > \$client_secrets_dir/\$alias.crt
            if [ \$? -ne 0 ]; then
                log -f ${CURRENT_FUNC} 'ERROR' \"Failed to get secret ca-cert: \$alias from ns: '$STRIMZI_KAFKA_NS' \"
                exit 1
            fi
        done
        log -f ${CURRENT_FUNC} '✅ Finished exporting kafka ca-certs for truststore creation'
        ###################################################################
        log -f ${CURRENT_FUNC} 'Started adding ca-certs to truststore.jks for kafka-ui'
        for alias in \"\${ca_certs[@]}\"; do
            output=\$(
                keytool -importcert \
                    -file \"\$client_secrets_dir/\${alias}.crt\" \
                    -keystore \"\$client_secrets_dir/truststore.jks\" \
                    -storepass \"$KAFKA_UI_TRUSTSTORE_PASS\" \
                    -alias \"\$alias\" \
                    -noprompt 2>&1
            )
            if [ \$? -ne 0 ]; then
                log -f ${CURRENT_FUNC} 'ERROR' \"Failed to add ca-cert: \$alias to truststore.jks for kafka-ui...\n\t\t:\$output\"
                exit 1
            fi
        done
        log -f ${CURRENT_FUNC} '✅ Finished adding ca-certs to truststore.jks for kafka-ui'
        ###################################################################
        # DEBUG commands:
        # openssl s_client -connect broker-0-kafka-cluster.pfs.pack:9093 -showcerts -CAfile brokers-ca.crt
        # keytool -list -keystore \$PWD/truststore.jks -storepass atreides
        ###################################################################
        log -f ${CURRENT_FUNC} 'Started creating truststore.jks secret for kafka-ui'
        kubectl delete secret kafka-ui-truststore -n $STRIMZI_KAFKA_NS > /dev/null 2>&1 || true
        kubectl create secret generic kafka-ui-truststore \
            --from-file=./truststore.jks \
            -n $STRIMZI_KAFKA_NS > /dev/null 2>&1
        log -f ${CURRENT_FUNC} '✅ Finished creating truststore.jks secret for kafka-ui'

        ###################################################################


        kubectl get secret kafka-ui \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.user\.key}' | base64 -d \
            > \$client_secrets_dir/kafka-ui.key

        kubectl get secret kafka-ui \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.user\.crt}' | base64 -d \
            > \$client_secrets_dir/kafka-ui.crt

        kubectl get secret kafka-ui \
            -n $STRIMZI_KAFKA_NS \
            -o jsonpath='{.data.ca\.crt}' | base64 -d \
            > \$client_secrets_dir/ca.crt
        ###################################################################
        log -f ${CURRENT_FUNC} 'Started creating keystore.p12 for kafka-ui'
        openssl pkcs12 -export \
            -inkey \$client_secrets_dir/kafka-ui.key \
            -in \$client_secrets_dir/kafka-ui.crt \
            -certfile \$client_secrets_dir/ca.crt \
            -name kafka-ui-keystore \
            -out \$client_secrets_dir/keystore.p12 \
            -password pass:$KAFKA_KEYSTORE_PASS

        kubectl delete secret kafka-ui-keystore -n $STRIMZI_KAFKA_NS > /dev/null 2>&1 || true
        kubectl create secret generic kafka-ui-keystore \
            --from-file=./keystore.p12 \
            -n $STRIMZI_KAFKA_NS > /dev/null 2>&1
        log -f ${CURRENT_FUNC} '✅ Finished creating keystore.p12 secret for kafka-ui'
        ###################################################################
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to export '$KAFKA_UI_USER' secrets for keystore & truststore creation"
        return 1
    fi
    log -f ${CURRENT_FUNC} "✅ Finished exporting '$KAFKA_UI_USER' secrets for keystore & truststore and keystore creation"
    ###################################################################
    log -f ${CURRENT_FUNC} "Installing $chart_name Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install $chart_name $chart_name/$chart_name \
            --namespace $STRIMZI_KAFKA_NS \
            --create-namespace \
            --version $KAFKA_UI_VERSION \
            -f /tmp/$chart_name/values.yaml \
            2>&1)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install kafka:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing $chart_name on namespace: '${STRIMZI_KAFKA_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install $chart_name"
        return 1
    fi
    ##################################################################
    log -f $CURRENT_FUNC "applying http-routes for $chart_name ingress"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl apply -f /tmp/$chart_name/http-routes.yaml ${VERBOSE}
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "applying dnsPolicy and dnsConfig for $chart_name deployment"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl patch deployment kafka-ui -n $STRIMZI_KAFKA_NS --type='json' -p='
        [
            {
                \"op\": \"add\",
                \"path\": \"/spec/template/spec/dnsPolicy\",
                \"value\": \"ClusterFirstWithHostNet\"
            },
            {
                \"op\": \"add\",
                \"path\": \"/spec/template/spec/dnsConfig\",
                \"value\": {
                    \"nameservers\": [\"10.37.224.6\", \"10.12.180.71\"]
                }
            }
        ]'
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished deploying $chart_name on the cluster."
    ##################################################################
    return 0
}


install_kyverno() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_name="kyverno"
    local chart_url=" https://kyverno.github.io/kyverno/"
    ###################################################################
    log -f ${CURRENT_FUNC} "Started $chart_name helm chart prerequisites"
    helm_chart_prerequisites ${CONTROL_PLANE_NODE} "${chart_name}" "kyverno" "${chart_url}" "$KYVERNO_NS"
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install $chart_name helm chart prerequisites"
        return 1
    fi
    log -f ${CURRENT_FUNC} "Finished $chart_name helm chart prerequisites"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        rm -rf /tmp/$chart_name &&  mkdir -p /tmp/$chart_name
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name values.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/values.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name http-proxy.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/http-proxy.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing $chart_name Helm chart"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        output=\$(helm install $chart_name $chart_name/$chart_name \
            --namespace $KYVERNO_NS \
            --create-namespace \
            --version $KYVERNO_VERSION \
            --set admissionController.replicas=3 \
            --set backgroundController.replicas=2 \
            --set cleanupController.replicas=2 \
            --set reportsController.replicas=2 \
            -f /tmp/$chart_name/values.yaml \
            2>&1)
            # Check if the Helm install command was successful
        if [ ! \$? -eq 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to install ${chart_name}:\n\t\${output}\"
            exit 1
        fi
    """
    if [ $? -eq 0 ]; then
        log -f "${CURRENT_FUNC}" "Finished installing $chart_name on namespace: '${KYVERNO_NS}'"
    else
        log -f "${CURRENT_FUNC}" "ERROR" "Failed to install $chart_name"
        return 1
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "applying http-proxy for $chart_name ingress"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl apply -f /tmp/$chart_name/http-proxy.yaml ${VERBOSE}
    """
    ##################################################################
}


upgrade_cilium() {
    ##################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    #############################################################
    set +u
    if [ -z "$MAGLEV_HASH_SEED" ]; then
        log -f ${CURRENT_FUNC} "Cilium maglev hashseed is not set, generating a random one."
        local hash_seed=$(head -c12 /dev/urandom | base64 -w0)
    else
        local hash_seed=$MAGLEV_HASH_SEED
    fi
    log -f ${CURRENT_FUNC} "Cilium maglev hashseed is: ${hash_seed}"
    set -u
    #############################################################
    local control_plane_address=$(ssh -q ${CONTROL_PLANE_NODE} <<< """
        ip -o -4 addr show $CONTROLPLANE_INGRESS_CLUSTER_INTER | awk '{print \$4}' | cut -d/ -f1
    """)

    local control_plane_subnet=$(ssh -q "${CONTROL_PLANE_NODE}" """
        # Use 'ip' to show the IPv4 address and CIDR of the given interface

        ip -o -f inet addr show ${CONTROLPLANE_INGRESS_CLUSTER_INTER} | awk '{print \$4}' | while read cidr; do
            # Split the CIDR into IP and prefix (e.g., 10.10.10.11 and 24)
            IFS=/ read ip prefix <<< \"\$cidr\"
            # Split the IP address into its 4 octets
            IFS=. read -r o1 o2 o3 o4 <<< \"\$ip\"

            # Generate the subnet mask as a 32-bit integer, then mask out unused bits
            mask=\$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))

            # Extract each octet of the subnet mask
            m1=\$(( (mask >> 24) & 0xFF ))
            m2=\$(( (mask >> 16) & 0xFF ))
            m3=\$(( (mask >> 8) & 0xFF ))
            m4=\$(( mask & 0xFF ))

            # Calculate the network address by bitwise ANDing IP and subnet mask
            n1=\$(( o1 & m1 ))
            n2=\$(( o2 & m2 ))
            n3=\$(( o3 & m3 ))
            n4=\$(( o4 & m4 ))

            # Output the resulting network address in CIDR notation
            echo \"\$n1.\$n2.\$n3.\$n4/\$prefix\"
        done
    """)
    log -f ${CURRENT_FUNC} "Cilium native routing subnet is: ${control_plane_subnet}"
    #############################################################
    log -f ${CURRENT_FUNC} "sending cilium values to control plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./cilium/values.yaml ${CONTROL_PLANE_NODE}:/tmp/
    #############################################################
    log -f ${CURRENT_FUNC} "Upgrading cilium to version: '${CILIUM_VERSION}' using cilium cli"
    ssh -q $CONTROL_PLANE_NODE <<< """
        #############################################################
        echo \" upgrading cilium with command:
            cilium upgrade --version $CILIUM_VERSION \
            --namespace $CILIUM_NS \
            --set cluster.name="$CLUSTER_NAME" \
            --set ipv4NativeRoutingCIDR=${control_plane_subnet} \
            --set operator.replicas=$OPERATOR_REPLICAS \
            --set hubble.relay.replicas=$HUBBLE_RELAY_REPLICAS \
            --set hubble.ui.replicas=$HUBBLE_UI_REPLICAS \
            --set maglev.hashSeed=\"${hash_seed}\" \
            -f /tmp/values.yaml
        \"
        OUTPUT=\$(cilium upgrade --version $CILIUM_VERSION \
            --namespace $CILIUM_NS \
            --set ipv4NativeRoutingCIDR=${control_plane_subnet} \
            --set operator.replicas=$OPERATOR_REPLICAS \
            --set hubble.relay.replicas=$HUBBLE_RELAY_REPLICAS \
            --set hubble.ui.replicas=$HUBBLE_UI_REPLICAS \
            --set maglev.hashSeed=\"${hash_seed}\" \
            -f /tmp/values.yaml \
            2>&1)
        echo \$OUTPUT
        kubectl rollout restart -n $CILIUM_NS ds/cilium ds/cilium-envoy deployment/cilium-operator deployment/coredns deployment/hubble-relay > /dev/null 2>&1 || true
        #############################################################
        sleep 30
        # log -f $CURRENT_FUNC 'Removing default cilium ingress.'
        # kubectl delete svc -n $CILIUM_NS cilium-ingress >/dev/null 2>&1 || true
        #############################################################
    """
    #############################################################
    if [ $? -eq 0 ]; then
        log -f ${CURRENT_FUNC} "Finished upgrading cilium."
    else
        return 1
    fi
    #############################################################
}


install_cilium_observability() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    log -f ${CURRENT_FUNC} "Started cilium observability installation on the cluster"

    log -f ${CURRENT_FUNC} "Patching cilium config map to enable observability on prometheus port: $PROMETHEUS_LISTEN_PORT"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        set -euo pipefail
        kubectl patch -n ${CILIUM_NS} configmap cilium-config --type merge --patch '{\"data\":{\"prometheus-serve-addr\":\":$PROMETHEUS_LISTEN_PORT\"}}' ${VERBOSE}
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to patch cilium config map"
        return 1
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Installing cilium prometheus service monitor"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        set -euo pipefail
        kubectl delete -f https://raw.githubusercontent.com/cilium/cilium/${CILIUM_VERSION}/examples/kubernetes/addons/prometheus/monitoring-example.yaml > /dev/null 2>&1 || true

        kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/${CILIUM_VERSION}/examples/kubernetes/addons/prometheus/monitoring-example.yaml ${VERBOSE}
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to install cilium prometheus service monitor"
        return 1
    fi
    ##################################################################
    local chart_name="cilium"
    ##################################################################
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # create tmp dir for chart
        rm -rf /tmp/$chart_name &&  mkdir -p /tmp/$chart_name
    """
    ##################################################################
    log -f ${CURRENT_FUNC} "sending $chart_name http-routes.yaml to control-plane node: ${CONTROL_PLANE_NODE}"
    scp -q ./$chart_name/http-routes.yaml $CONTROL_PLANE_NODE:/tmp/$chart_name/
    ###################################################################
    log -f ${CURRENT_FUNC} "Deploying http-routes for cilium Grafana ingress"
    ssh -q ${CONTROL_PLANE_NODE} <<< """
        kubectl apply -f /tmp/$chart_name/http-routes.yaml ${VERBOSE}
    """
    ###################################################################
    log -f ${CURRENT_FUNC} "Finished cilium observability installation on the cluster"
}


install_neo4j() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_url="https://helm.neo4j.com/neo4j"
    local repo_name=neo4j
    local chart_name=neo4j
    local chart_ns=neo4j
    local chart_version=5.26.5
    local delete_ns=true
    local create_ns=true

    deploy_helm_chart $chart_url $repo_name $chart_name $chart_ns $chart_version $delete_ns $create_ns
}


stabilise_cluster() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    while read -r node; do
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')

        log -f ${CURRENT_FUNC} "Restarting cilium PIDs on $role node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo rm -f /var/run/cilium/cilium.pid
            sudo rm -f /var/run/cilium/cilium-envoy.pid
        """
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')
    ###################################################################
    log -f ${CURRENT_FUNC} "Restarting cilium & rook-ceph pods on control plane node"
    ssh -q $CONTROL_PLANE_NODE <<< """
        kubectl -n $CILIUM_NS rollout restart deployment/coredns deployment/hubble-relay deployment/hubble-ui deployment/snapshot-controller daemonset/cilium daemonset/cilium-envoy deployment/snapshot-controller deployment/cilium-operator

        LABEL_SELECTORS=(
          \"app=rook-ceph-mon\"
          \"app=rook-ceph-mgr\"
          \"app=rook-ceph-exporter\"
          \"app=rook-ceph-crashcollector\"
          \"app.kubernetes.io/name=ceph-mds\"
          \"app.kubernetes.io/name=ceph-mgr\"
          \"app.kubernetes.io/name=ceph-mon\"
          \"app.kubernetes.io/name=ceph-osd\"
          \"app.kubernetes.io/name=ceph-rgw\"
          \"operator=rook\"
          \"app=rook-ceph-osd\"
          \"app=csi-cephfsplugin-provisioner\"
        )

        log -f $CURRENT_FUNC  \"Restarting Rook-Ceph deployments in namespace '$ROOKCEPH_NS'...\"

        for label in \"\${LABEL_SELECTORS[@]}\"; do
          deployments=\$(kubectl -n \"$ROOKCEPH_NS\" get deployments -l \"\$label\" -o jsonpath='{range .items[*]}{.metadata.name}{\"\n\"}{end}')
          for deploy in \$deployments; do
            echo \"Rolling out restart for deployment: \$deploy\"
            kubectl -n \"$ROOKCEPH_NS\" rollout restart deployment \"\$deploy\"
          done
        done



        kubectl -n \"$ROOKCEPH_NS\" rollout restart deployment csi-cephfsplugin-provisioner  csi-nfsplugin-provisioner   csi-rbdplugin-provisioner

        kubectl -n \"$ROOKCEPH_NS\" rollout restart daemonset csi-cephfsplugin csi-nfsplugin csi-rbdplugin

        # cleanup all unused / replaced replicaset:
        kubectl get rs -A --no-headers \
          | awk '\$3 == 0 {print \$1, \$2}' \
          | while read namespace rsname; do
            kubectl delete rs \"\$rsname\" -n \"\$namespace\"
        done

        sleep 30
        log -f $CURRENT_FUNC \"✅ Done.\"
        kubectl delete pods -n ${ROOKCEPH_NS} --field-selector=status.phase=Succeeded
    """

    ###################################################################
    log -f ${CURRENT_FUNC} "Restarting strimzi-cluster-operator deployment"
    ssh -q $CONTROL_PLANE_NODE <<< """
        kubectl rollout restart -n $STRIMZI_KAFKA_OPERATOR_NS deployment strimzi-cluster-operator > /dev/null 2>&1 || true
    """
    ###################################################################
}


install_prometheus() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_url="https://prometheus-community.github.io/helm-charts"
    local repo_name=prometheus-community
    local chart_name=kube-prometheus-stack
    local chart_ns=monitoring
    local chart_version=72.0.1
    local delete_ns=true
    local create_ns=true

    deploy_helm_chart $chart_url $repo_name $chart_name $chart_ns $chart_version $delete_ns $create_ns
    ###################################################################
    grafana_password=$(ssh -q $CONTROL_PLANE_NODE """
        kubectl --namespace $chart_ns get secrets kube-prometheus-stack-grafana -o jsonpath='{.data.admin-password}' | base64 -d ; echo
    """)
    log -f ${CURRENT_FUNC} "Login to grafana dashboard with: 'admin/${grafana_password}'"
    ###################################################################
}


install_metrics_server() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_url="https://kubernetes-sigs.github.io/metrics-server/"
    local repo_name=kubernetes-sigs
    local chart_name=metrics-server
    local chart_ns=monitoring
    local chart_version=3.12.2
    local delete_ns=false
    local create_ns=false

    deploy_helm_chart $chart_url $repo_name $chart_name $chart_ns $chart_version $delete_ns $create_ns
    ###################################################################
}


upgrade_keycloak() {
    local chart_name=keycloak
    # Define secret names
    local postgresql_secret_name="keycloak-postgresql-auth"

    local admin_secret_name="keycloak-admin-auth"


    export PASSWORD=$(kubectl get secret --namespace "$chart_name" "$postgresql_secret_name" -o jsonpath="{.data.password}" | base64 -d)

    export ADMIN_PASSWORD=$(kubectl get secret --namespace "$chart_name" "$admin_secret_name" -o jsonpath="{.data.admin-password}" | base64 -d)

    helm upgrade -n keycloak keycloak bitnami/keycloak \
        --reuse-values -f keycloak/values.yaml \
        --set postgresql.auth.existingSecret=$postgresql_secret_name \
        --set postgresql.auth.secretKeys.userPasswordKey=postgres-password \
        --set auth.existingSecret=$admin_secret_name \
        --set auth.passwordSecretKey=admin-password


         --set global.postgresql.auth.password=$PASSWORD \
        --set auth.adminPassword=$ADMIN_PASSWORD
}


install_keycloak() {
    ###################################################################
    CURRENT_FUNC=${FUNCNAME[0]}
    ###################################################################
    local chart_url="https://charts.bitnami.com/bitnami"
    local repo_name=bitnami
    local chart_name=keycloak
    local chart_ns=keycloak
    local chart_version=24.6.6
    local delete_ns=false
    local create_ns=false
    local extra_args=""


    # Define secret names
    local postgresql_secret_name="keycloak-postgresql-auth"
    local postgre_secret_password="postgres-password"
    local postgre_password="postgres-secret"


    local admin_secret_name="keycloak-admin-auth"
    local admin_password="admin-password"  # The password you want to use

    local auth_admin="admin"


    helm_uninstall_chart ${CONTROL_PLANE_NODE} $chart_name $chart_ns true true

    ssh -q ${CONTROL_PLANE_NODE} <<< """
        # Generate PostgreSQL auth secret
        kubectl create secret generic '$postgresql_secret_name' \
            --namespace '$chart_ns' \
            --from-literal=postgres-password='$postgre_secret_password' \
            --from-literal=password='$postgre_password' \
            --dry-run=client -o yaml | kubectl apply -f -

        # Generate admin auth secret
        kubectl create secret generic '$admin_secret_name' \
        --namespace '$chart_ns' \
        --from-literal=admin-password='$admin_password' \
        --dry-run=client -o yaml | kubectl apply -f -
    """


    # Set extra arguments for Helm deployment
    local extra_args=""
    extra_args+="--set postgresql.auth.existingSecret=$postgresql_secret_name "
    extra_args+="--set postgresql.auth.secretKeys.userPasswordKey=postgres-password "

    extra_args+="--set auth.adminUser=$auth_admin "
    extra_args+="--set auth.existingSecret=$admin_secret_name "
    extra_args+="--set auth.passwordSecretKey=admin-password "

    # Remove trailing comma if needed
    extra_args="${extra_args%,}"

    deploy_helm_chart "$chart_url" "$repo_name" "$chart_name" "$chart_ns" "$chart_version" "$delete_ns" "$create_ns" "$extra_args"

    ###################################################################
}

#############################################################
CURRENT_FUNC=main
#############################################################
if [ "$RESET_CLUSTER_ARG" -eq 1 ]; then
    reset_cluster
    rook_ceph_cleanup
    log -f "main" "Cluster reset completed."
    exit 0
fi


#################################################################
if [ "$INSTALL_CLUSTER" = true ]; then
    if [ "$PREREQUISITES" = true ]; then
        #################################################################
        if ! provision_deployer; then
            log -f "main" "ERROR" "An error occurred while provisioning the deployer node."
            exit 1
        fi
        log -f "main" "Deployer node provisioned successfully."
        #################################################################
        if ! deploy_hostsfile; then
            log -f "main" "ERROR" "An error occured while updating the hosts files."
            exit 1
        fi
        log -f "main" "Hosts files updated successfully."
        #################################################################
    fi
fi


if [ "$INSTALL_CLUSTER" = true ]; then
    ################################################################
    if [ "$PREREQUISITES" == "true" ]; then
        #################################################################
        if ! prerequisites_requirements; then
            log -f "main" "ERROR" "Failed the prerequisites requirements for the cluster installation."
            exit 1
        fi
        #################################################################
    else
        log -f "main" "Cluster prerequisites have been skipped"
    fi
    ################################################################
    if ! install_cluster; then
        log -f main "ERROR" "An error occurred while deploying the cluster"
        exit 1
    fi
    ################################################################
    join_cluster
    ################################################################
    if ! install_gateway_CRDS; then
        log -f main "ERROR" "An error occurred while deploying gateway CRDS"
        exit 1
    fi
    ################################################################
    if [ "$PREREQUISITES" == "true" ]; then
        if ! install_cilium_prerequisites; then
            log -f main "ERROR" "An error occurred while installing cilium prerequisites"
            exit 1
        fi
    fi
    ################################################################
    if ! install_cilium; then
        log -f main "ERROR" "An error occurred while installing cilium"
        exit 1
    fi
    #################################################################
    if ! install_gateway; then
        log -f "main" "ERROR" "Failed to deploy ingress gateway API on the cluster, services might be unreachable..."
        exit 1
    fi
    #################################################################
    if ! install_kyverno; then
         log -f "main" "WARNING" "Failed to deploy kyverno on the cluster, cluster pods wont be able to reach internet if nodes are behind a proxy..."
    fi
    ###############################################################
    if ! install_cilium_observability; then
        # https://github.com/cilium/cilium/tree/v1.17.3/examples/kubernetes/addons/prometheus
        log -f "main" "WARNING" "Failed to install cilium observability on the cluster"
    fi
    ################################################################
    if ! restart_cilium; then
        log -f "main" "ERROR" "Failed to start cilium service."
        exit 1
    fi
    ############################################################
    # apply metrics-server:
    if ! install_prometheus; then
        log -f "main" "WARNING" "Failed to install kube-prometheus server, metrics won't be installed"
    else
        if ! install_metrics_server; then
            log -f "main" "WARNING" "Failed to install metrics server, metrics won't be available"
        fi
    fi
fi


if [ "$UPGRADE_CILIUM" = true ]; then
    # TODO: https://docs.cilium.io/en/stable/operations/upgrade/
    if ! upgrade_cilium; then
        log -f "main" "ERROR" "Failed to upgrade cilium on the cluster"
        exit 1
    fi
fi


if [ "$INSTALL_CLUSTER" = true ]; then
    ##################################################################
    if ! install_rookceph; then
        log -f "main" "ERROR" "Failed to install ceph-rook on the cluster"
        exit 1
    fi
    ##################################################################
    if ! install_rookceph_cluster; then
        log -f "main" "ERROR" "Failed to install ceph-rook cluster on the cluster"
        exit 1
    fi
fi


################################################################
if [ "$PRINT_ROOK_PASSWORD" == "true" ]; then
    log -f "rook-ceph" "Generating admin password for rook-ceph dashboard"
    rook_ceph_dasbharod_password=$(ssh -q "${CONTROL_PLANE_NODE}" <<< """
        kubectl -n $ROOKCEPH_NS get secret rook-ceph-dashboard-password -o jsonpath=\"{['data']['password']}\" | base64 --decode && echo
    """)
    log -f "rook-ceph" "admin password for rook-ceph dashboard password is: '$rook_ceph_dasbharod_password'"
fi
################################################################


if [ "$INSTALL_CLUSTER" = true ]; then
    ################################################################
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
    # ##################################################################²
    # vault_uninstall
    # ##################################################################
    # ##################################################################
    if ! install_vault; then
        log -f "main" "ERROR" "Failed to install longhorn on the cluster"
        exit 1
    fi

    if ! install_keycloak; then
        log -f "main" "ERROR" "Failed to install keycloak on the cluster"
        exit 1
    fi
#     ##################################################################
        # if ! install_kafka_operator; then
        #     log -f "main" "ERROR" "Failed to install kafka on the cluster"
        #     exit 1
        # fi
        if ! install_kafka_cluster; then
            log -f "main" "ERROR" "Failed to install kafka on the cluster"
            exit 1
        fi
    ##################################################################
    # if ! install_akhq; then
    #     log -f "main" "ERROR" "Failed to install kafka-akhq gui on the cluster"
    #     exit 1
    # fi
    if ! install_kafka_ui; then
        log -f "main" "ERROR" "Failed to install kafka-ui on the cluster"
        exit 1
    fi
    ##################################################################
    if ! install_neo4j; then
        log -f "main" "ERROR" "Failed to install Neo4J on the cluster"
        exit 1
    fi
fi



##################################################################
# restabilize the cluster:
if [ "$STABILIZE_CLUSTER" == "true" ]; then
    stabilise_cluster
fi
##################################################################

log -f "main" "INFO" "Workload finished"
exit 0




# TODO : kubetools to include:
# https://www.portainer.io/

# https://k8slens.dev/   > https://docs.k8slens.dev/getting-started/install-lens/#install-lens-desktop-from-the-rpm-repository

# https://spacelift.io/blog/argocd
# https://argoproj.github.io/rollouts/
# https://github.com/stakater/Reloader
# https://github.com/kubernetes/dashboard


################################################################
# TODO, status checks and tests
# install_rancher

#################################################################
# if [ "$PREREQUISITES" == "true" ]; then
#     if ! install_longhorn_prerequisites; then
#         log -f "main" "ERROR" "Failed to install longhorn prerequisites"
#         exit 1
#     fi
# fi
# if ! install_longhorn; then
#     log -f "main" "ERROR" "Failed to install longhorn on the cluster"
#     exit 1
# fi
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
# log -f "main" "deployment finished"


# ./main -r -v --with-prerequisites



#  2>&1 || true
####################################################################################################################
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



# for some reason, the cluster is instable, the logs show nothing unusual, I suspect something is wrong with the SFR image...


# check cephcluster status: kubectl -n rook-ceph get cephcluster
# kubectl delete pods -l 'app in (csi-rbdplugin-provisioner, csi-cephfsplugin-provisioner)'
# kubectl get pods -l 'app in (csi-rbdplugin-provisioner, csi-cephfsplugin-provisioner)'
# kubectl get pods -l app.kubernetes.io/instance=kafka-cluster



