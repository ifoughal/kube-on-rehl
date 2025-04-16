#!/bin/bash


# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}


optimize_dnf() {
    local CURRENT_NODE=$1


    local log_prefix=$(date +"%Y-%m-%d %H:%M:%S,%3N - ${CURRENT_FUNC}")

    ssh -q $CURRENT_NODE <<< """
        echo '$log_prefix - $CURRENT_NODE - Enabling Delta RPMs' ${VERBOSE}
        sudo sed -i '/^deltarpm=/d' /etc/dnf/dnf.conf
        echo 'deltarpm=true' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Increase Download Threads' ${VERBOSE}
        sudo sed -i '/^max_parallel_downloads=/d' /etc/dnf/dnf.conf
        echo 'max_parallel_downloads=10' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Adjust Metadata Expiration' ${VERBOSE}
        sudo sed -i '/^metadata_expire=/d' /etc/dnf/dnf.conf
        echo 'metadata_expire=1h' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Enable Fastest Mirror Plugin' ${VERBOSE}
        sudo sed -i '/^fastestmirror=/d' /etc/dnf/dnf.conf
        echo 'fastestmirror=true' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Clean DNF All' ${VERBOSE}
        sudo dnf clean all ${VERBOSE}

        echo '$log_prefix - $CURRENT_NODE - Clean DNF packages' ${VERBOSE}
        sudo dnf clean packages ${VERBOSE}

        echo '$log_prefix - $CURRENT_NODE - Clean DNF metadata' ${VERBOSE}
        sudo dnf clean metadata ${VERBOSE}

        echo '$log_prefix - $CURRENT_NODE - Update System' ${VERBOSE}
        sudo dnf update -y  ${VERBOSE}
        echo '$log_prefix - $CURRENT_NODE - DNF cache cleaned and system updated successfully.' ${VERBOSE}
    """
}



# Function to update or add the PATH variable in /etc/environment
update_path() {
    local CURRENT_NODE=$1

    local NEW_PATH="export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    local ENV_FILE="/etc/environment"
    local BASHRC_FILE="\$HOME/.bashrc"

    ssh -q $CURRENT_NODE <<< """
        #########################################################
        # Check if the PATH variable is already defined in ENV_FILE
        if grep -q '^export PATH=' \"$ENV_FILE\"; then
            # If PATH exists, update it with the new value
            sudo sed -i 's|^export PATH=.*|'\"$NEW_PATH\"'|' \"$ENV_FILE\"
        else
            # If PATH does not exist, append it to the file
            echo \"$NEW_PATH\" | sudo tee -a \"$ENV_FILE\" > /dev/null
        fi
        #########################################################
        # append aliast loading option to use debug_log function
        # if ! grep -q '^shopt -s expand_aliases' \"$ENV_FILE\"; then
        #     echo \"shopt -s expand_aliases\" | sudo tee -a \"$ENV_FILE\" > /dev/null
        # fi

        if ! grep -q '^shopt -s expand_aliases' \"$BASHRC_FILE\"; then
            echo \"shopt -s expand_aliases\" | sudo tee -a \"$BASHRC_FILE\" > /dev/null
        fi

        #########################################################
        if grep -q '^alias debug_log=' \"$BASHRC_FILE\"; then
            sudo sed -i 's|^alias debug_log=.*|'\"$debug_log\"'|' \"$BASHRC_FILE\"
        else
            echo \"$debug_log\" | sudo tee -a \"$BASHRC_FILE\" > /dev/null
        fi
        #########################################################
        # source the environment variables to load debug_load
        . $ENV_FILE
        . $BASHRC_FILE
        #########################################################
        if ! grep -q '^alias ll' \"$ENV_FILE\"; then
            echo 'alias ll=\"ls -alF\"' | sudo tee -a $ENV_FILE > /dev/null
        fi
        #########################################################
        if grep -q '^export http_proxy=' \"$ENV_FILE\"; then
            sudo sed -i 's|^export http_proxy=.*|'\"export http_proxy=${HTTP_PROXY}\"'|' \"$ENV_FILE\"
            debug_log -f $CURRENT_FUNC \"Updated http_proxy in $ENV_FILE.\"
        else
            echo 'export http_proxy=\"${HTTP_PROXY}\"' | sudo tee -a $ENV_FILE > /dev/null
            debug_log -f $CURRENT_FUNC \"Added http_proxy to $ENV_FILE.\"
        fi
        #########################################################
        if grep -q '^export HTTP_PROXY=' \"$ENV_FILE\"; then
            sudo sed -i 's|^export HTTP_PROXY=.*|'\"export HTTP_PROXY=${HTTP_PROXY}\"'|' \"$ENV_FILE\"
            debug_log -f $CURRENT_FUNC \"Updated HTTP_PROXY in $ENV_FILE.\"
        else
            echo 'export HTTP_PROXY=\"${HTTP_PROXY}\"' | sudo tee -a $ENV_FILE > /dev/null
            debug_log -f $CURRENT_FUNC \"Added HTTP_PROXY to $ENV_FILE.\"
        fi
        #########################################################
        if grep -q '^export https_proxy=' \"$ENV_FILE\"; then
            sudo sed -i 's|^export https_proxy=.*|'\"export https_proxy=${HTTPS_PROXY}\"'|' \"$ENV_FILE\"
            debug_log -f $CURRENT_FUNC \"Updated https_proxy in $ENV_FILE.\"
        else
            echo 'export https_proxy=\"${HTTPS_PROXY}\"' | sudo tee -a $ENV_FILE > /dev/null
            debug_log -f $CURRENT_FUNC \"Added https_proxy to $ENV_FILE.\"
        fi
        #########################################################
        if grep -q '^export HTTPS_PROXY=' \"$ENV_FILE\"; then
            sudo sed -i 's|^export HTTP_PROXY=.*|'\"export HTTPS_PROXY=${HTTPS_PROXY}\"'|' \"$ENV_FILE\"
            debug_log -f $CURRENT_FUNC \"Updated HTTPS_PROXY in $ENV_FILE.\"
        else
            echo 'export HTTPS_PROXY=\"${HTTPS_PROXY}\"' | sudo tee -a $ENV_FILE > /dev/null
            debug_log -f $CURRENT_FUNC \"Added HTTPS_PROXY to $ENV_FILE.\"
        fi
        #########################################################
        if grep -q '^export no_proxy=' \"$ENV_FILE\"; then
            sudo sed -i 's|^export no_proxy=.*|'\"export no_proxy=${NO_PROXY}\"'|' \"$ENV_FILE\"
            debug_log -f $CURRENT_FUNC \"Updated no_proxy in $ENV_FILE.\"
        else
            echo 'export no_proxy=\"${NO_PROXY}\"' | sudo tee -a $ENV_FILE > /dev/null
            debug_log -f $CURRENT_FUNC \"Added no_proxy to $ENV_FILE.\"
        fi
        #########################################################
        if grep -q '^export NO_PROXY=' \"$ENV_FILE\"; then
            sudo sed -i 's|^export NO_PROXY=.*|'\"export NO_PROXY=${NO_PROXY}\"'|' \"$ENV_FILE\"
            debug_log -f $CURRENT_FUNC \"Updated NO_PROXY in $ENV_FILE.\"
        else
            echo 'export NO_PROXY=\"${NO_PROXY}\"' | sudo tee -a $ENV_FILE > /dev/null
            debug_log -f $CURRENT_FUNC \"Added NO_PROXY to $ENV_FILE.\"
        fi
        #########################################################
    """
}


check_ntp_sync () {
    local CURRENT_NODE=$1

    local_time=$(date +%s)  # Get the timestamp of the local system in seconds since epoch
    log -f ${CURRENT_FUNC} "Local time: $(date -d @$local_time)"

    # Get remote time and validate it's not empty or invalid
    # Get the timestamp of the remote system in seconds since epoch
    # remote_time=$(ssh -q "$CURRENT_NODE" 'echo 123') || true

    local remote_time=$(ssh -q $CURRENT_NODE <<< "date +%s || true")
    ssh_status=$?
    if [ $ssh_status -ne 0 ] || [[ -z "$remote_time" || ! "$remote_time" =~ ^[0-9]+$ ]]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to get remote time from $CURRENT_NODE via SSH."
        return 1
    fi

    if [[ -z "$remote_time" || ! "$remote_time" =~ ^[0-9]+$ ]]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to get remote time from $CURRENT_NODE via SSH."
        return 1
    fi
    log -f ${CURRENT_FUNC} "Remote time on $CURRENT_NODE is: $remote_time"


    # Calculate the difference in time between local and remote system
    time_diff=$((local_time - remote_time))
    log -f ${CURRENT_FUNC} "Time difference between local and remote system: $time_diff seconds."
    # You can define an acceptable threshold for time difference, for example, 5 seconds
    threshold=5

    # Compare time difference
    if ((time_diff > threshold || time_diff < -threshold)); then
        log -f ${CURRENT_FUNC} "Time on $CURRENT_NODE is not in sync with the local system. Difference: $time_diff seconds."
        return 1
    fi

    log -f ${CURRENT_FUNC} "Time on $CURRENT_NODE is in sync with the local system."
    return 0
}


config_check () {
    RETURN_CODE=0
    local NODE="$1"
    local command="$2"
    local key="$3"
    local expected_value="$4"

    # Execute the command and get the value for the specified key
    local value=$(ssh -q $NODE <<< "$command | grep -w \"$key\" | awk '{print \$2}' || true")

    # Check if the key was found
    if [ -z "$value" ]; then
        log -f "${CURRENT_FUNC}" "ERROR" "The value of '$command' not found."
        RETURN_CODE=1
    else
        # Check if the value matches the expected value
        if [ "$value" == "$expected_value" ]; then
            log -f "${CURRENT_FUNC}" "The value of '$command' is compliant: '${expected_value}'."
        else
            log -f "${CURRENT_FUNC}" "ERROR" "The value of '$command' expected to be: '$expected_value'. But Found: '$value'"
            RETURN_CODE=2
        fi
    fi
    return $RETURN_CODE
}


install_go () {
    CURRENT_NODE=$1
    GO_VERSION=$2
    TINYGO_VERSION=$3

    ssh -q $CURRENT_NODE <<< """
        cd /tmp

        # install Go
        log -f ${CURRENT_FUNC} \"installing go version: ${GO_VERSION}\"
        wget -q -nc https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

        # install tinyGo
        wget -q -nc https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo${TINYGO_VERSION}.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf tinygo${TINYGO_VERSION}.linux-amd64.tar.gz

        # Update path:
        files=(
            \"/etc/environment\"
            \"\$HOME/.bashrc\"
        )

        extra_paths=(
            \"/usr/local/go/bin\"
            \"/usr/local/tinygo/bin\"
        )

        log -f ${CURRENT_FUNC} \"Updating paths for GO\"
        for file in \"\${files[@]}\"; do
            debug_log -f ${CURRENT_FUNC} \"Updating environment for path: \${file}\"

            for path in \"\${extra_paths[@]}\"; do
                debug_log -f ${CURRENT_FUNC} \"Checking path: \$path\"

                # Check if the export PATH line exists
                if grep -q 'export PATH=' \"\$file\"; then
                    # Ensure the path is not already appended
                    if ! grep -q \"\$path\" \"\$file\"; then
                        debug_log -f ${CURRENT_FUNC} \"Appending \$path to \$file\"
                        sudo sed -i \"s|^export PATH=.*|&:\${path}|\" \"\$file\"
                    else
                        debug_log -f ${CURRENT_FUNC} \"\$path already exists in \$file\"
                    fi
                else
                    debug_log -f ${CURRENT_FUNC} \"export PATH not found, adding export line\"
                    echo \"export PATH=\\\$PATH:\${path}\" | sudo tee -a \"\$file\" > /dev/null
                fi
            done
        done

    """
}


configure_repos () {
    local current_host=$1
    local current_role=$2
    local repo_file=$3
    ##################################################################
    set -euo pipefail
    ##################################################################
    log -f ${CURRENT_FUNC} "sending repos file to target $current_role node: ${current_host}"
    scp -q $repo_file ${current_host}:/tmp/almalinux.repo
    ##################################################################
    if [ "$RESET_REPOS" == "true" ]; then
        log -f ${CURRENT_FUNC} "Resetting DNF repos to default for $current_role node: ${current_host}"
        ssh -q ${current_host} <<< """
            sudo rm -rf /etc/yum.repos.d/*
            sudo mkdir -p /etc/yum.repos.d/
            sudo mv /tmp/almalinux.repo /etc/yum.repos.d/
            sudo chmod 644 /etc/yum.repos.d/*
            sudo chown root:root /etc/yum.repos.d/*
        """
    else
        log -f ${CURRENT_FUNC} "Modifying DNF repos for $current_role node: ${current_host}"
        ssh -q ${current_host} <<< """
            sudo mv /tmp/almalinux.repo /etc/yum.repos.d/
            sudo chmod 644 /etc/yum.repos.d/*
            sudo chown root:root /etc/yum.repos.d/*
        """
    fi
    ##################################################################
    log -f ${CURRENT_FUNC} "Finished modifying repos file for ${current_role} node ${current_host}"
    set +e
    set +u
    set +o pipefail
    ##################################################################
    log -f ${CURRENT_FUNC} "Configuring AlmaLinux 9 Repositories for ${NODE_ROLE} node ${current_host}"
    ssh -q $current_host <<< """
        set -euo pipefail # Exit on error

        ####################################################################
        log -f ${CURRENT_FUNC} \"configuring crypto policies for DNF SSL\"
        eval \"sudo update-crypto-policies --set DEFAULT ${VERBOSE}\"

        log -f ${CURRENT_FUNC} \"Fetching and importing AlmaLinux GPG keys...\"
        sudo curl -s -o /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
        sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux ${VERBOSE}

        log -f ${CURRENT_FUNC} \"Cleaning up DNF cache and updating system...\"
        sudo rm -f /var/lib/rpm/__db*
        sudo rpm --rebuilddb ${VERBOSE}
        sudo dnf clean all  ${VERBOSE}
        sudo dnf makecache  ${VERBOSE}
        sudo dnf -y update  ${VERBOSE}

        log -f ${CURRENT_FUNC} \"Enabling EPEL & CRB repositories...\"
        sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm ${VERBOSE}

        sudo dnf config-manager --set-enabled crb  ${VERBOSE}

        log -f ${CURRENT_FUNC} \"Adding RPM Fusion Free (OSS) repositories...\"
        sudo dnf install -y https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm  ${VERBOSE}

        log -f ${CURRENT_FUNC} \"Adding RPM Fusion Non-Free (proprietary) repositories...\"
        sudo dnf install -y https://mirrors.rpmfusion.org/nonfree/el/rpmfusion-nonfree-release-9.noarch.rpm  ${VERBOSE}

        log -f ${CURRENT_FUNC} \"Cleaning up DNF cache and updating system...\"
        sudo dnf clean all  ${VERBOSE}
        sudo dnf makecache  ${VERBOSE}
        sudo dnf -y update  ${VERBOSE}
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Failed to configure AlmaLinux 9 Repositories for $current_role node ${current_host}"
        return 1
    else
        log -f ${CURRENT_FUNC} "INFO" "Successfully configured AlmaLinux 9 Repositories for $current_role node ${current_host}"
        return 0
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
    ##################################################################
    while read -r node; do
        ##################################################################
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        ##################################################################
        log -f ${CURRENT_FUNC} "Removing prior installed versions for ${role} node ${hostname}"
        ssh -q ${hostname} <<< """
            sudo dnf remove -y kubelet kubeadm kubectl --disableexcludes=kubernetes > /dev/null 2>&1
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
    if [ "$error_raised" -eq 0 ]; then
       log -f ${CURRENT_FUNC} "Finished installing kubernetes tools"
    else
        log -f ${CURRENT_FUNC} "ERROR" "Some errors occured during the kubernetes tools installation"
        return 1
    fi
    ##################################################################
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
        log -f ${CURRENT_FUNC} "Killing processes using port $port on $current_host..."
        ssh -q "$current_host" <<< """
            sudo lsof -t -i :$port | xargs -r sudo kill -9
        """
    done
}


parse_inventory() {
    ####################################################################
    log -f "main" "Started loading inventory file: $INVENTORY"
    CLUSTER_NODES=$(yq e -r -o=json '.hosts' "$INVENTORY")
    log -f "main" "Finished loading inventory file: $INVENTORY"
    #########################################################
    export CONTROLPLANE_INGRESS_CLUSTER_INTER=$(echo "$CLUSTER_NODES" | yq e -r '.[] | select(.role == "control-plane-leader") | .ingress.cluster_interface' -)
    export CONTROLPLANE_INGRESS_PUBLIC_INTER=$(echo "$CLUSTER_NODES" | yq e -r '.[] | select(.role == "control-plane-leader") | .ingress.public_interface' -)
    export CONTROL_PLANE_API_PORT=$(echo "$CLUSTER_NODES" | yq e -r '.[] | select(.role == "control-plane-leader") | .API_PORT' -)
    export CONTROL_PLANE_NODE=$(echo "$CLUSTER_NODES" | yq e -r '.[] | select(.role == "control-plane-leader") | .hostname' -)
    #########################################################
}


add_bashcompletion () {
    # Parse the application name as a function argument
    local CURRENT_NODE="$1"
    local app="$2"

    if [ -z "$CURRENT_NODE" ]; then
        log "ERROR" "node hostname must be provided."
        return 1
    fi

    if [ -z "$app" ]; then
        log "ERROR" "Application name must be provided."
        return 2
    fi

    COMPLETION_FILE="/etc/bash_completion.d/$app"

    log -f "${CURRENT_FUNC}" "Adding $app bash completion for node: ${CURRENT_NODE}"
    # Assuming the application has a completion script available
    ssh -q ${CURRENT_NODE} <<< """
        $app completion bash | sudo tee "$COMPLETION_FILE" >/dev/null
    """
    log -f "${CURRENT_FUNC}" "$app bash completion added successfully."
}


helm_chart_prerequisites () {
    ##################################################################
    local control_plane_host=$1
    local CHART_NAME=$2
    local CHART_REPO=$3
    local CHART_NS=$4
    local DELETE_NS=$5
    local CREATE_NS=$6
    local timeout=${7:-"10s"}
    local sleep_time=${8:-"15s"}

    ##################################################################
    ssh -q ${control_plane_host} <<< """
        set -euo pipefail
        log -f \"${CURRENT_FUNC}\" \"Adding '$CHART_NAME' repo to Helm\"
        helm repo add ${CHART_NAME} $CHART_REPO --force-update ${VERBOSE}
        helm repo update ${VERBOSE}
        ##################################################################
        log -f \"${CURRENT_FUNC}\" \"uninstalling and ensuring the cluster is cleaned from $CHART_NAME\"
        helm uninstall -n $CHART_NS $CHART_NAME > /dev/null 2>&1 || true
        ##################################################################
        if [ \"$DELETE_NS\" == \"true\" ] || [ \"$DELETE_NS\" == \"1\" ]; then
            log -f \"${CURRENT_FUNC}\" \"deleting '$CHART_NS' namespace\"
            kubectl delete ns $CHART_NS --now=true --ignore-not-found --timeout ${timeout} > /dev/null 2>&1 || true

            output=\$(kubectl get ns $CHART_NS --ignore-not-found)
            if [ ! -z \"\$output\" ]; then
                log -f \"${CURRENT_FUNC}\" \"Force deleting '$CHART_NS' namespace\"
                kubectl get namespace \"$CHART_NS\" -o json 2>/dev/null \\
                | tr -d '\n' | sed 's/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/' \\
                | kubectl replace --raw /api/v1/namespaces/$CHART_NS/finalize -f - ${VERBOSE} || true
                log -f \"${CURRENT_FUNC}\" \"sleeping for $sleep_time seconds while deleting '$CHART_NS' namespace\"
                sleep $sleep_time
            fi
        else
            log -f \"${CURRENT_FUNC}\" 'Skipping NS deletion'
        fi
        ##################################################################
        if [ \"$CREATE_NS\" == 'true' ] || [ \"$CREATE_NS\" == '1' ]; then
            ##################################################################
            log -f \"${CURRENT_FUNC}\" \"Creating '$CHART_NS' chart namespace: '$CHART_NS'\"
            kubectl create ns $CHART_NS ${VERBOSE} || true
            ##################################################################
        else
            log -f \"${CURRENT_FUNC}\" 'Skipping NS creation'
        fi
        ##################################################################
    """
    return $?
    ##################################################################
}


install_helm () {
    local CURRENT_NODE=$1

    ssh -q $CURRENT_NODE <<< """
        cd /tmp
        curl -s https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash ${VERBOSE}
        sudo ln -sf /usr/local/bin/helm /usr/bin/  > /dev/null
    """
}


install_containerd () {
    #############################################################################
    # configure proxy:
    local CURRENT_NODE=$1
    local NODE_ROLE=$2
    local PAUSE_VERSION=$3
    local SUDO_GROUP=$4
    local HTTP_PROXY=$5
    local HTTPS_PROXY=$6
    local NO_PROXY=$7
    ############################################################################
    log -f ${CURRENT_FUNC} "Installing containerD for ${NODE_ROLE} node ${CURRENT_NODE}"
    ssh -q ${CURRENT_NODE} <<< """
        set -euo pipefail # Exit on error
        sudo dnf install -y yum-utils ${VERBOSE}
        sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo  ${VERBOSE}
        sudo dnf install containerd.io -y ${VERBOSE}
    """
    # Check if the SSH command failed
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Error occured while installing containerD for ${NODE_ROLE} node ${CURRENT_NODE}"
        return 1 # continue to next node...
    fi
    log -f ${CURRENT_FUNC} "Finished installing containerD for ${NODE_ROLE} node ${CURRENT_NODE}"
    ############################################################################
    log -f ${CURRENT_FUNC} "Enabling containerD NRI with systemD and cgroups for ${NODE_ROLE} node ${CURRENT_NODE}"
    ssh -q ${CURRENT_NODE} <<< """
        set -euo pipefail # Exit on error

        CONFIG_FILE='/etc/containerd/config.toml'

        # Pause version mismatch:
        log -f ${CURRENT_FUNC} 'Resetting containerD config to default on ${NODE_ROLE} node ${CURRENT_NODE}'
        containerd config default | sudo tee \$CONFIG_FILE >/dev/null

        log -f ${CURRENT_FUNC} 'Backing up the original config file on ${NODE_ROLE} node ${CURRENT_NODE}'
        sudo cp -f -n \$CONFIG_FILE \${CONFIG_FILE}.bak

        log -f ${CURRENT_FUNC} 'Configuring containerD for our cluster on ${NODE_ROLE} node ${CURRENT_NODE}'
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

        log -f ${CURRENT_FUNC} 'Starting and enabling containerD on ${NODE_ROLE} node ${CURRENT_NODE}'
        sudo systemctl enable --now containerd > /dev/null 2>&1
        sudo systemctl daemon-reload
        sudo systemctl restart containerd

        sleep 10
        # Check if the containerd service is active
        if systemctl is-active --quiet containerd.service; then
            log -f ${CURRENT_FUNC} 'ContainerD configuration updated successfully on ${NODE_ROLE} node ${CURRENT_NODE}'
        else
            log -f ${CURRENT_FUNC} 'ERROR' 'ContainerD configuration failed, containerd service is not running...'
            exit 1
        fi
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} "ERROR" "Error occurred while enabling containerD NRI with systemD and cgroups for ${role} node ${CURRENT_NODE}"
        return 1  # continue to next node and skip this one
    fi
    log -f ${CURRENT_FUNC} "ContainerD NRI with systemD and cgroups enabled successfully for ${role} node ${CURRENT_NODE}"
    #############################################################################
    if [ -z "$HTTP_PROXY" ]; then
        log -f ${CURRENT_FUNC} 'HTTP_PROXY is not set, skipping proxy configuration for containerD'
        ssh -q $CURRENT_NODE <<< """
            sudo mkdir -p /etc/systemd/system/containerd.service.d
            sudo rm -rf /etc/systemd/system/containerd.service.d/http-proxy.conf
        """
    else
        ssh -q $CURRENT_NODE <<< """
            set -euo pipefail # Exit on error
            sudo mkdir -p /etc/systemd/system/containerd.service.d
            if [ -z \"$HTTP_PROXY\" ]; then
                log -f ${CURRENT_FUNC} 'HTTP_PROXY is not set, skipping proxy configuration for containerD on ${NODE_ROLE} node $CURRENT_NODE'
            else
                log -f ${CURRENT_FUNC} 'Configuring HTTP_PROXY for containerD on ${NODE_ROLE} node $CURRENT_NODE'
                cat <<EOF | sudo tee /etc/systemd/system/containerd.service.d/http-proxy.conf  > /dev/null
[Service]
    Environment=\"HTTP_PROXY=$HTTP_PROXY\"
    Environment=\"HTTPS_PROXY=$HTTPS_PROXY\"
    Environment=\"NO_PROXY=$NO_PROXY\"
EOF
            log -f ${CURRENT_FUNC} 'Finished configuring HTTP_PROXY for containerD on ${NODE_ROLE} node $CURRENT_NODE'

            fi
        """
        if [ $? -ne 0 ]; then
            log -f ${CURRENT_FUNC} 'ERROR' "Failed to configure HTTP_PROXY for containerD on ${NODE_ROLE} node $CURRENT_NODE"
            return 1
        fi
    fi

    #############################################################################
    ssh -q "$CURRENT_NODE" <<< """
        set -euo pipefail # Exit on error

        log -f ${CURRENT_FUNC} 'Starting and enabling containerD for ${NODE_ROLE} node $CURRENT_NODE'
        sudo systemctl enable containerd
        sudo systemctl daemon-reload
        sudo systemctl restart containerd
        sleep 10
        # Check if the containerd service is active
        if systemctl is-active --quiet containerd.service; then
            log -f ${CURRENT_FUNC} 'ContainerD configuration updated successfully for ${NODE_ROLE} node $CURRENT_NODE'
        else
            log -f ${CURRENT_FUNC} 'ERROR' 'ContainerD configuration failed, containerd service is not running for ${NODE_ROLE} node $CURRENT_NODE...'
            exit 1
        fi

        # ensure changes have been applied
        if sudo containerd config dump | grep -q 'SystemdCgroup = true'; then
            log -f ${CURRENT_FUNC} 'Cgroups configured accordingly for containerD for ${NODE_ROLE} node $CURRENT_NODE'
        else
            log -f ${CURRENT_FUNC} 'ERROR' 'Failed to configure Cgroups configured for containerD for ${NODE_ROLE} node $CURRENT_NODE'
            exit 1
        fi

        if sudo containerd config dump | grep -q 'sandbox_image = \"registry.k8s.io/pause:${PAUSE_VERSION}\"'; then
            log -f ${CURRENT_FUNC} \"sandbox_image is set accordingly to pause version ${PAUSE_VERSION} for ${NODE_ROLE} node $CURRENT_NODE\"
        else
            log -f ${CURRENT_FUNC} 'ERROR' \"Failed to set sandbox_image to pause version ${PAUSE_VERSION} for ${NODE_ROLE} node $CURRENT_NODE\"
            exit 1
        fi
        #############################################################################
        log -f ${CURRENT_FUNC} 'Configuring containerD socket permissions for ${NODE_ROLE} node $CURRENT_NODE for sudo group wheel,${SUDO_GROUP}'
        sudo setfacl -m g:${SUDO_GROUP}:rw /var/run/containerd/containerd.sock
        sudo setfacl -m g:wheel:rw /var/run/containerd/containerd.sock
    """
    if [ $? -ne 0 ]; then
        log -f ${CURRENT_FUNC} 'ERROR' 'Failed to configure containerD'
        return 1
    fi
}


update_firewall() {

    CURRENT_NODE="$1"

    ssh $CURRENT_NODE <<< """
        # check zone:
        if \$\(sudo firewall-cmd --get-zones | grep -q "k8s"\); then
            echo firewallD 'k8s' zone already exists
        else
            echo creating firewallD 'k8s' zone
            sudo firewall-cmd --permanent --new-zone=k8s
            # apply changes:
            sudo firewall-cmd --reload
        fi
        # set k8s as default zone
        sudo firewall-cmd --set-default-zone=k8s
        # #################################################################*
        # # allow http and k8s zones to use 22 and ICMP

        # # Open port 53 (DNS) for all networks (public zone)
        # sudo firewall-cmd --zone=public --add-service=dns --permanent
        # sudo firewall-cmd --zone=k8s --add-service=dns --permanent

        # sudo firewall-cmd --zone=public --add-port=53/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=53/udp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=53/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=53/udp --permanent


        # # Open port 22 (SSH) for all networks (public zone)
        # sudo firewall-cmd --zone=k8s --add-port=22/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=22/tcp --permanent

        # # Allow ICMP echo-reply/request  for all networks (public zone)
        # sudo firewall-cmd  --zone=k8s --permanent --add-icmp-block-inversion
        # sudo firewall-cmd  --zone=public --permanent --add-icmp-block-inversion

        # # Allow ICMP echo-reply (ping response) for all networks (public zone)
        # sudo firewall-cmd --permanent --zone=public --add-icmp-block=echo-reply
        # sudo firewall-cmd --permanent --zone=k8s --add-icmp-block=echo-reply

        # # Allow ICMP echo-request (ping) for all networks (public zone)
        # sudo firewall-cmd --permanent --zone=public --add-icmp-block=echo-request
        # sudo firewall-cmd --permanent --zone=k8s --add-icmp-block=echo-request

        # sudo firewall-cmd --reload
        # #############################################################################

        # # Kubectl API Server

        # sudo firewall-cmd --zone=public --add-port=${CONTROL_PLANE_API_PORT}/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=${CONTROL_PLANE_API_PORT}/tcp --permanent

        # # Kubelet health and communication
        # sudo firewall-cmd --zone=k8s --add-port=10248/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=10250/tcp --permanent

        # # Control plane services
        # sudo firewall-cmd --zone=k8s --add-port=10251/tcp --permanent  # Scheduler
        # sudo firewall-cmd --zone=k8s --add-port=10252/tcp --permanent  # Controller Manager
        # sudo firewall-cmd --zone=k8s --add-port=10257/tcp --permanent  # Secure Controller Manager
        # sudo firewall-cmd --zone=k8s --add-port=10259/tcp --permanent  # Secure Scheduler


        # sudo firewall-cmd --zone=k8s --add-port=4000/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=4245/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=443/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=80/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=8080/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=9090/tcp --permanent

        # sudo firewall-cmd --zone=public --add-port=4000/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=4245/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=9090/tcp --permanent

        # # BGP for Calico/Cilium
        # sudo firewall-cmd --zone=k8s --add-port=179/tcp --permanent

        # # etcd access
        # sudo firewall-cmd --zone=k8s --add-port=2379-2381/tcp --permanent

        # # VXLAN overlay network communication (used for networking between nodes in Kubernetes with VXLAN encapsulation)
        # sudo firewall-cmd --zone=k8s --add-port=8472/udp --permanent

        # # Health checks
        # sudo firewall-cmd --zone=k8s --add-port=4240/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-icmp-block=echo-request --permanent

        # # Additional required ports for Cilium
        # sudo firewall-cmd --zone=k8s --add-port=4244/tcp --permanent  # Hubble server
        # sudo firewall-cmd --zone=k8s --add-port=4245/tcp --permanent  # Hubble Relay
        # sudo firewall-cmd --zone=k8s --add-port=4250/tcp --permanent  # Mutual Auth
        # sudo firewall-cmd --zone=k8s --add-port=51871/udp --permanent # WireGuard

        # # Spire Agent health check port (listening on 127.0.0.1 or ::1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=4251/tcp

        # # cilium-agent pprof server (debugging, listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=6060/tcp

        # # cilium-operator pprof server (debugging, listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=6061/tcp

        # # Hubble Relay pprof server (debugging, listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=6062/tcp

        # # cilium-envoy health listener (listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9878/tcp

        # # cilium-agent health status API (listening on 127.0.0.1 and/or ::1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9879/tcp

        # # cilium-agent gops server (debugging, listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9890/tcp

        # # cilium-operator gops server (debugging, listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9891/tcp

        # # Hubble Relay gops server (debugging, listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9893/tcp

        # # cilium-envoy Admin API (listening on 127.0.0.1)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9901/tcp

        # # cilium-agent Prometheus metrics
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9962/tcp

        # # cilium-operator Prometheus metrics
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9963/tcp

        # # cilium-envoy Prometheus metrics
        # sudo firewall-cmd --zone=k8s --permanent --add-port=9964/tcp

        # # VXLAN overlay network communication (used by Cilium and other network plugins)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=4789/udp

        # # enable firewallD masquerade
        # sudo firewall-cmd --add-masquerade --permanent


        # #############################################################################
        # # worker nodes ports:
        # # VXLAN overlay network communication (used for networking between nodes in Kubernetes with VXLAN encapsulation)
        # sudo firewall-cmd --zone=k8s --add-port=8472/udp --permanent

        # # Health check port for cluster status (Cilium health checks and similar services)
        # sudo firewall-cmd --zone=k8s --add-port=4240/tcp --permanent

        # # ICMP echo-request (ping) allowed for health checks and diagnostics
        # sudo firewall-cmd --zone=k8s --add-icmp-block=echo-request --permanent

        # # Access to etcd cluster (used for the Kubernetes control plane communication)
        # sudo firewall-cmd --zone=k8s --add-port=2379-2380/tcp --permanent

        # # Kubernetes node ports, including worker and master services and external access (for services like kubelet and external services)
        # sudo firewall-cmd --zone=k8s --add-port=30000-32767/tcp --permanent
        # sudo firewall-cmd --zone=public --add-port=30000-32767/tcp --permanent
        # sudo firewall-cmd --reload

        # # Kubelet health and communication
        # sudo firewall-cmd --zone=k8s --add-port=10250/tcp --permanent

        # # BGP for Calico/Cilium
        # sudo firewall-cmd --zone=k8s --add-port=179/tcp --permanent

        # # Additional required ports for Cilium
        # sudo firewall-cmd --zone=k8s --add-port=4244/tcp --permanent  # Hubble server
        # sudo firewall-cmd --zone=k8s --add-port=4245/tcp --permanent  # Hubble Relay
        # sudo firewall-cmd --zone=k8s --add-port=4250/tcp --permanent  # Mutual Auth
        # sudo firewall-cmd --zone=k8s --add-port=51871/udp --permanent # WireGuard

        # # VXLAN overlay network communication (used for networking between nodes in Kubernetes with VXLAN encapsulation)
        # sudo firewall-cmd --zone=k8s --permanent --add-port=4789/udp
        # #############################################################################
        # # firewall-cmd --list-all
        # sudo firewall-cmd --reload
    """
}


generate_ip_pool() {
    set -euo pipefail

    local ips_array=()
    # Function to generate the IP pool for load balancer
    # This function will create a temporary file with the IP blocks
    # and then render the final output using awk
    # Loop through each node and collect IPs
    while read -r node; do
        # Parse node information using jq
        local hostname=$(echo "$node" | jq -r '.hostname')
        local ip=$(echo "$node" | jq -r '.ip')
        local role=$(echo "$node" | jq -r '.role')
        # Add the IP to the array
        ips_array+=("$ip")
    done < <(echo "$CLUSTER_NODES" | jq -c '.[]')


    local template_file="./cilium/loadbalancer-ip-pool.jinja"
    local output_file="/tmp/loadbalancer-ip-pool.yaml"

    # Create a temporary file to hold the IP blocks
    local tmp_blocks=$(mktemp)

    for ip in "${ips_array[@]}"; do
        echo "  - cidr: \"$ip/32\"" >> "$tmp_blocks"
    done

    # Render the final output by replacing the placeholders in the template using awk
    awk -v cilium_ns="$CILIUM_NS" -v blocks="$(cat "$tmp_blocks")" '
    {
        if ($0 ~ /{{ cilium_ns }}/) {
            gsub("{{ cilium_ns }}", cilium_ns)
            print $0
        } else if ($0 ~ /{{ ip_blocks }}/) {
            print blocks
        } else {
            print $0
        }
    }
    ' "$template_file" > "$output_file"

    # Clean up
    rm "$tmp_blocks"
}


# EXPERIMENTAL
cilium_cleanup () {
    # echo "📌 Unmounting and remounting BPF filesystem..."
    # sudo umount /sys/fs/bpf 2>/dev/null
    # sudo mount -t bpf bpf /sys/fs/bpf

    # echo "📌 Removing Cilium BPF maps..."
    # MAPS=$(sudo bpftool map show | awk '/cilium/ {print $1}')

    # if [ -z "$MAPS" ]; then
    #     echo "✅ No Cilium BPF maps found."
    # else
    #     for MAP_ID in $MAPS; do
    #         echo "Deleting map ID $MAP_ID..."
    #         sudo bpftool map delete id $MAP_ID || echo "⚠️ Failed to delete map $MAP_ID"
    #     done
    # fi

    # echo "📌 Flushing IPVS tables..."
    # sudo ipvsadm --clear

    # echo "✅ Cleanup completed!"

    echo "cleaning up cluster from previous cilium installs"
    kubectl delete crd $(kubectl get crd | grep cilium | awk '{print $1}')  >/dev/null 2>&1 || true
    for ns in $(kubectl get ns | grep cilium | awk '{print $1}'); do
        kubectl delete ns $ns --grace-period=0 --force  >/dev/null 2>&1 || true
    done
    kubectl -n kube-system delete ds cilium --grace-period=0 --force  >/dev/null 2>&1 || true
    kubectl -n kube-system delete ds cilium-operator --grace-period=0 --force  >/dev/null 2>&1 || true
    kubectl delete configmap cilium-config -n kube-system  >/dev/null 2>&1 || true
    for cr in $(kubectl get crd | grep cilium | awk '{print $1}'); do
        kubectl get $cr -A --no-headers | awk '{print $2}' | xargs -I{} kubectl patch $cr {} --type=json -p '[{"op": "remove", "path": "/metadata/finalizers"}]'
    done
    kubectl delete networkpolicy --all -n kube-system
    sudo iptables-save | grep -v CILIUM | sudo iptables-restore
    kubectl -n kube-system delete ds -l k8s-app=cilium >/dev/null 2>&1 || true
    kubectl -n kube-system delete ds -l io.cilium/app >/dev/null 2>&1 || true
    kubectl -n kube-system delete ds -l name=cilium >/dev/null 2>&1 || true
    kubectl -n kube-system delete ds -l app=cilium >/dev/null 2>&1 || true

    kubectl -n kube-system delete deploy -l k8s-app=cilium >/dev/null 2>&1 || true
    kubectl -n kube-system delete deploy -l io.cilium/app >/dev/null 2>&1 || true
    kubectl -n kube-system delete deploy -l name=cilium >/dev/null 2>&1 || true
    kubectl -n kube-system delete deploy -l app=cilium >/dev/null 2>&1 || true
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
