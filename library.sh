#!/bin/bash


optimize_dnf() {
    local CURRENT_NODE=$1
    local VERBOSE=$2

    if [ "$VERBOSE"="1> /dev/null" ]; then
        ECHO_VERBOSE=""
    else
        ECHO_VERBOSE=$VERBOSE
    fi

    local log_prefix=$(date +"%Y-%m-%d %H:%M:%S,%3N - ${FUNCNAME[0]}")

    ssh -q $CURRENT_NODE <<< """
        echo '$log_prefix - $CURRENT_NODE - Enabling Delta RPMs' ${ECHO_VERBOSE}
        sudo sed -i '/^deltarpm=/d' /etc/dnf/dnf.conf
        echo 'deltarpm=true' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Increase Download Threads' ${ECHO_VERBOSE}
        sudo sed -i '/^max_parallel_downloads=/d' /etc/dnf/dnf.conf
        echo 'max_parallel_downloads=10' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Adjust Metadata Expiration' ${ECHO_VERBOSE}
        sudo sed -i '/^metadata_expire=/d' /etc/dnf/dnf.conf
        echo 'metadata_expire=1h' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Enable Fastest Mirror Plugin' ${ECHO_VERBOSE}
        sudo sed -i '/^fastestmirror=/d' /etc/dnf/dnf.conf
        echo 'fastestmirror=true' | sudo tee -a /etc/dnf/dnf.conf > /dev/null

        echo '$log_prefix - $CURRENT_NODE - Clean DNF All' ${ECHO_VERBOSE}
        sudo dnf clean all ${VERBOSE}

        echo '$log_prefix - $CURRENT_NODE - Clean DNF packages' ${ECHO_VERBOSE}
        sudo dnf clean packages ${VERBOSE}

        echo '$log_prefix - $CURRENT_NODE - Clean DNF metadata' ${ECHO_VERBOSE}
        sudo dnf clean metadata ${VERBOSE}

        echo '$log_prefix - $CURRENT_NODE - Update System' ${ECHO_VERBOSE}
        sudo dnf update -y  ${VERBOSE}
        echo '$log_prefix - $CURRENT_NODE - DNF cache cleaned and system updated successfully.' ${ECHO_VERBOSE}
    """
}



# Function to update or add the PATH variable in /etc/environment
update_path() {
    local NEW_PATH="export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    local ENV_FILE="/etc/environment"

    # Check if the PATH variable is already defined in /etc/environment
    if grep -q '^export PATH=' "$ENV_FILE"; then
        # If PATH exists, update it with the new value
        sudo sed -i 's|^export PATH=.*|'"$NEW_PATH"'|' "$ENV_FILE"
        echo "Updated PATH in $ENV_FILE."
    else
        # If PATH does not exist, append it to the file
        echo "$NEW_PATH" | sudo tee -a "$ENV_FILE"
        echo "Added PATH to $ENV_FILE."
    fi
    # Reload the environment variables to apply changes immediately
    source "$ENV_FILE"
    export http_proxy="http://10.66.8.162:3128"
    export https_proxy="http://10.66.8.162:3128"
    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$https_proxy"

    export no_proxy=".pack,.svc,.svc.cluster.local,.cluster.local,lorionstrm01vel,lorionstrm02vel,lorionstrm03vel,localhost,::1,127.0.0.1,10.66.65.7,10.66.65.8,10.66.65.9,10.96.0.0/12,10.244.0.0/16"
    export NO_PROXY="$no_proxy"

    cat <<EOF | sudo tee /etc/environment
export http_proxy="http://10.66.8.162:3128"
export https_proxy="http://10.66.8.162:3128"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$https_proxy"

export no_proxy=".pack,.svc,.svc.cluster.local,.cluster.local,lorionstrm01vel,lorionstrm02vel,lorionstrm03vel,localhost,::1,127.0.0.1,10.66.65.7,10.66.65.8,10.66.65.9,10.96.0.0/12,10.244.0.0/16"
export NO_PROXY="$no_proxy"
EOF
    # Print the updated PATH for verification
    echo "Updated PATH: $PATH"
}


config_check () {
    local command="$1"
    local key="$2"
    local expected_value="$3"

    # Execute the command and get the value for the specified key
    value=$($command | grep -w "$key" | awk '{print $2}' || true)

    # Check if the key was found
    if [ -z "$value" ]; then
        log "ERROR" "Key '$key' not found."
        return 1
    fi

    # Check if the value matches the expected value
    if [ "$value" == "$expected_value" ]; then
        log "INFO" "The value of $key is $expected_value."
    else
        log "ERROR" "The value of '$key' expected to be: '$expected_value'. But Found: '$value'"
        return 1
    fi
}




install_go () {
    CURRENT_NODE=$1
    GO_VERSION=$2
    TINYGO_VERSION=$3
    ECHO_VERBOSE=$4


    ssh -q $CURRENT_NODE """
        cd /tmp

        # install Go
        log -f ${FUNCNAME[0]} \"installing go version: ${GO_VERSION}\" ${ECHO_VERBOSE}
        wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

        # install tinyGo
        wget -q https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo${TINYGO_VERSION}.linux-amd64.tar.gz
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

        log -f ${FUNCNAME[0]} \"Updating paths for GO\" ${ECHO_VERBOSE}
        for file in \"\${files[@]}\"; do
            log -f ${FUNCNAME[0]} \"Updating environment for path: \${file}\" ${ECHO_VERBOSE}

            for path in \"\${extra_paths[@]}\"; do
                log -f ${FUNCNAME[0]} \"Checking path: \$path\" ${ECHO_VERBOSE}

                # Check if the export PATH line exists
                if grep -q 'export PATH=' \"\$file\"; then
                    # Ensure the path is not already appended
                    if ! grep -q \"\$path\" \"\$file\"; then
                        log -f ${FUNCNAME[0]} \"Appending \$path to \$file\" ${ECHO_VERBOSE}
                        sudo sed -i \"s|^export PATH=.*|&:\${path}|\" \"\$file\"
                    else
                        log -f ${FUNCNAME[0]} \"\$path already exists in \$file\" ${ECHO_VERBOSE}
                    fi
                else
                    log -f ${FUNCNAME[0]} \"export PATH not found, adding export line\" ${ECHO_VERBOSE}
                    echo \"export PATH=\\\$PATH:\${path}\" | sudo tee -a \"\$file\" > /dev/null
                fi
            done
        done

    """
}


configure_repos () {
    local CURRENT_HOST=$1
    local VERBOSE=$2
    local ECHO_VERBOSE=$3

    local log_prefix=$(date +"\033[0;32m %Y-%m-%d %H:%M:%S,%3N - ${FUNCNAME[0]} - INFO -")


    scp -q ./almalinux.repo $CURRENT_HOST:/tmp/

    log "INFO" "Configuring AlmaLinux 9 Repositories for node: ${CURRENT_HOST}" ${ECHO_VERBOSE}

    ssh -q $CURRENT_HOST <<< """
        set -e  # Exit on error

        echo -e \"${log_prefix} Updating almalinux repos list\" ${ECHO_VERBOSE}
        sudo mv /tmp/almalinux.repo /etc/yum.repos.d/almalinux.repo
        sudo chown root:root /etc/yum.repos.d/almalinux.repo

        echo -e \"${log_prefix} Fetching and importing AlmaLinux GPG keys...\" ${ECHO_VERBOSE}
        sudo curl -s -o /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
        sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux ${VERBOSE}

        echo -e \"${log_prefix} Cleaning up DNF cache and updating system...\" ${ECHO_VERBOSE}
        sudo dnf clean all  ${VERBOSE}
        sudo dnf makecache  ${VERBOSE}
        sudo dnf -y update  ${VERBOSE}

        echo -e \"${log_prefix} Enabling EPEL & CRB repositories...\" ${ECHO_VERBOSE}
        sudo dnf install -y epel-release  ${VERBOSE}
        sudo dnf config-manager --set-enabled crb  ${VERBOSE}

        echo -e \"${log_prefix} Adding RPM Fusion Free & Non-Free Repositories...\" ${ECHO_VERBOSE}
        # OSS repos:
        sudo dnf install -y https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm  ${VERBOSE}
        # Proprietary repos
        sudo dnf install -y https://mirrors.rpmfusion.org/nonfree/el/rpmfusion-nonfree-release-9.noarch.rpm  ${VERBOSE}

        echo -e \"${log_prefix} Cleaning up DNF cache and updating system...\" ${ECHO_VERBOSE}
        sudo dnf clean all  ${VERBOSE}
        sudo dnf makecache  ${VERBOSE}
        sudo dnf -y update  ${VERBOSE}
    """
}


add_bashcompletion () {
    # Parse the application name as a function argument
    CURRENT_NODE="$1"
    app="$2"
    ECHO_VERBOSE=$3

    if [ -z "$app" ]; then
        log "ERROR" "Application name must be provided."
        exit 1
    fi

    COMPLETION_FILE="/etc/bash_completion.d/$app"

    log "INFO" "Adding $app bash completion for node: ${CURRENT_NODE}" $ECHO_VERBOSE
    # Assuming the application has a completion script available
    ssh -q ${CURRENT_NODE} """
        $app completion bash | sudo tee "$COMPLETION_FILE" >/dev/null
    """
    log "INFO" "$app bash completion added successfully." $ECHO_VERBOSE
}


install_helm () {
    CURRENT_NODE=$1
    ECHO_VERBOSE=$2
    ssh -q $CURRENT_NODE """
        cd /tmp
        curl -s https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash ${ECHO_VERBOSE}
        sudo ln -sf /usr/local/bin/helm /usr/bin/  > /dev/null
    """
}


configure_containerD () {
    #############################################################################
    # configure proxy:
    CURRENT_NODE=$1
    HTTP_PROXY=$2
    HTTPS_PROXY=$3
    NO_PROXY=$4
    PAUSE_VERSION=$5
    SUDO_GROUP=$6
    ECHO_VERBOSE=$7

    ssh -q $CURRENT_NODE """
        sudo mkdir -p /etc/systemd/system/containerd.service.d

        cat <<EOF | sudo tee /etc/systemd/system/containerd.service.d/http-proxy.conf  > /dev/null
[Service]
    Environment=\"HTTP_PROXY=$HTTP_PROXY\"
    Environment=\"HTTPS_PROXY=$HTTPS_PROXY\"
    Environment=\"NO_PROXY=$NO_PROXY\"
EOF
    #############################################################################
    # ensure changes have been applied
    if sudo containerd config dump | grep -q 'SystemdCgroup = true'; then
        log -f ${FUNCNAME[0]} 'Cgroups configured accordingly for containerD'  ${ECHO_VERBOSE}
    else
        log -f ${FUNCNAME[0]} 'ERROR' 'Failed to configure Cgroups configured for containerD'
        exit 1
    fi

    if sudo containerd config dump | grep -q 'sandbox_image = \"registry.k8s.io/pause:${PAUSE_VERSION}\"'; then
        log -f ${FUNCNAME[0]} \"sandbox_image is set accordingly to pause version ${PAUSE_VERSION}\"  ${ECHO_VERBOSE}
    else
        log -f ${FUNCNAME[0]} 'ERROR' \"Failed to set sandbox_image to pause version ${PAUSE_VERSION}\"
        exit 1
    fi
    #############################################################################
    sudo setfacl -m g:${SUDO_GROUP}:rw /var/run/containerd/containerd.sock
    sudo setfacl -m g:wheel:rw /var/run/containerd/containerd.sock
    """
}



update_firewall() {

    CURRENT_NODE="$1"

    ssh $CURRENT_NODE """
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

        # sudo firewall-cmd --zone=public --add-port=${CONTROLPLANE_API_PORT}/tcp --permanent
        # sudo firewall-cmd --zone=k8s --add-port=${CONTROLPLANE_API_PORT}/tcp --permanent

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






########################################################################


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
