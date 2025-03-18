#!/bin/bash

SUDO_USERNAME=ifoughal
SUDO_USER_PASSWORD=password123
SUDO_GROUP=maintainers

CONTROLPLANE_INGRESS_INTER=ens192
HTTP_PROXY="http://10.66.65.10:80"
HTTPS_PROXY="http://10.66.65.10:80"
NO_PROXY=".pack,.svc,.svc.cluster.local,.cluster.local,node-1,node-2,node-3,localhost,::1,127.0.0.1,10.66.65.7,10.66.65.8,10.66.65.9,10.96.0.0/12,10.244.0.0/16"

LONGHORN_VERSION=v1.8.1


set -e  # Exit on error
set -o pipefail  # Fail if any piped command fails

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}




install_cilium () {
    ################################################################################################################
    # if kube-proxy has been installed:
    kubectl -n kube-system delete ds kube-proxy
    # Delete the configmap as well to avoid kube-proxy being reinstalled during a Kubeadm upgrade (works only for K8s 1.19 and newer)
    kubectl -n kube-system delete cm kube-proxy
    # Run on each node with root permissions:
    sudo iptables-save | grep -v KUBE | sudo iptables-restore
    ################################################################################################################
    sudo sysctl -w net.ipv4.conf.ens192.rp_filter=2
    ################################################################################################################
    helm repo add cilium https://helm.cilium.io/ --force-update
    ################################################################################################################
    CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
    CLI_ARCH=amd64
    if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
    curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
    sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
    sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
    rm cilium-linux-*
    ################################################################################################################
    add_bashcompletion cilium
    ################################################################################################################
    cilium install --version 1.17.1 --values ./cilium/values.yaml
    cilium status --wait
    ################################################################################################################
    kubectl apply -f cilium/ingress.yaml
    # delete default ingress
    kubectl delete svc -n kube-system cilium-ingress
    ################################################################################################################

}

add_bashcompletion () {
    # Parse the application name as a function argument
    app="$1"

    if [ -z "$app" ]; then
        echo "Error: Application name must be provided."
        return 1
    fi
    echo "Adding $app bash completion"
    COMPLETION_FILE="/etc/bash_completion.d/$app"

    # Assuming the application has a completion script available
    $app completion bash | sudo tee "$COMPLETION_FILE" >/dev/null

    echo "$app bash completion added successfully."
    source $COMPLETION_FILE
}

update_firewall() {

    # check zone:
    if $(sudo firewall-cmd --get-zones | grep -q "k8s"); then
        echo firewallD 'k8s' zone already exists
    else
        echo creating firewallD 'k8s' zone
        sudo firewall-cmd --permanent --new-zone=k8s
         # apply changes:
        sudo firewall-cmd --reload
    fi
    # set k8s as default zone
    sudo firewall-cmd --set-default-zone=k8s
    #################################################################*
    # allow http and k8s zones to use 22 and ICMP

    # Open port 53 (DNS) for all networks (public zone)
    sudo firewall-cmd --zone=public --add-service=dns --permanent
    sudo firewall-cmd --zone=k8s --add-service=dns --permanent

    sudo firewall-cmd --zone=public --add-port=53/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=53/udp --permanent
    sudo firewall-cmd --zone=k8s --add-port=53/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=53/udp --permanent


    # Open port 22 (SSH) for all networks (public zone)
    sudo firewall-cmd --zone=k8s --add-port=22/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=22/tcp --permanent

    # Allow ICMP echo-reply/request  for all networks (public zone)
    sudo firewall-cmd  --zone=k8s --permanent --add-icmp-block-inversion
    sudo firewall-cmd  --zone=public --permanent --add-icmp-block-inversion

    # Allow ICMP echo-reply (ping response) for all networks (public zone)
    sudo firewall-cmd --permanent --zone=public --add-icmp-block=echo-reply
    sudo firewall-cmd --permanent --zone=k8s --add-icmp-block=echo-reply

    # Allow ICMP echo-request (ping) for all networks (public zone)
    sudo firewall-cmd --permanent --zone=public --add-icmp-block=echo-request
    sudo firewall-cmd --permanent --zone=k8s --add-icmp-block=echo-request

    sudo firewall-cmd --reload
    #############################################################################

    # Kubectl API Server
    sudo firewall-cmd --zone=public --add-port=6443/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=6443/tcp --permanent

    # Kubelet health and communication
    sudo firewall-cmd --zone=k8s --add-port=10248/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=10250/tcp --permanent

    # Control plane services
    sudo firewall-cmd --zone=k8s --add-port=10251/tcp --permanent  # Scheduler
    sudo firewall-cmd --zone=k8s --add-port=10252/tcp --permanent  # Controller Manager
    sudo firewall-cmd --zone=k8s --add-port=10257/tcp --permanent  # Secure Controller Manager
    sudo firewall-cmd --zone=k8s --add-port=10259/tcp --permanent  # Secure Scheduler


    sudo firewall-cmd --zone=k8s --add-port=4000/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=4245/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=443/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=80/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=8080/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=9090/tcp --permanent

    sudo firewall-cmd --zone=public --add-port=4000/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=4245/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=9090/tcp --permanent

    # BGP for Calico/Cilium
    sudo firewall-cmd --zone=k8s --add-port=179/tcp --permanent

    # etcd access
    sudo firewall-cmd --zone=k8s --add-port=2379-2381/tcp --permanent

    # VXLAN overlay network communication (used for networking between nodes in Kubernetes with VXLAN encapsulation)
    sudo firewall-cmd --zone=k8s --add-port=8472/udp --permanent

    # Health checks
    sudo firewall-cmd --zone=k8s --add-port=4240/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-icmp-block=echo-request --permanent

    # Additional required ports for Cilium
    sudo firewall-cmd --zone=k8s --add-port=4244/tcp --permanent  # Hubble server
    sudo firewall-cmd --zone=k8s --add-port=4245/tcp --permanent  # Hubble Relay
    sudo firewall-cmd --zone=k8s --add-port=4250/tcp --permanent  # Mutual Auth
    sudo firewall-cmd --zone=k8s --add-port=51871/udp --permanent # WireGuard

    # Spire Agent health check port (listening on 127.0.0.1 or ::1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=4251/tcp

    # cilium-agent pprof server (debugging, listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=6060/tcp

    # cilium-operator pprof server (debugging, listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=6061/tcp

    # Hubble Relay pprof server (debugging, listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=6062/tcp

    # cilium-envoy health listener (listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=9878/tcp

    # cilium-agent health status API (listening on 127.0.0.1 and/or ::1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=9879/tcp

    # cilium-agent gops server (debugging, listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=9890/tcp

    # cilium-operator gops server (debugging, listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=9891/tcp

    # Hubble Relay gops server (debugging, listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=9893/tcp

    # cilium-envoy Admin API (listening on 127.0.0.1)
    sudo firewall-cmd --zone=k8s --permanent --add-port=9901/tcp

    # cilium-agent Prometheus metrics
    sudo firewall-cmd --zone=k8s --permanent --add-port=9962/tcp

    # cilium-operator Prometheus metrics
    sudo firewall-cmd --zone=k8s --permanent --add-port=9963/tcp

    # cilium-envoy Prometheus metrics
    sudo firewall-cmd --zone=k8s --permanent --add-port=9964/tcp

    # VXLAN overlay network communication (used by Cilium and other network plugins)
    sudo firewall-cmd --zone=k8s --permanent --add-port=4789/udp

    # enable firewallD masquerade
    sudo firewall-cmd --add-masquerade --permanent


    #############################################################################
    # worker nodes ports:
    # VXLAN overlay network communication (used for networking between nodes in Kubernetes with VXLAN encapsulation)
    sudo firewall-cmd --zone=k8s --add-port=8472/udp --permanent

    # Health check port for cluster status (Cilium health checks and similar services)
    sudo firewall-cmd --zone=k8s --add-port=4240/tcp --permanent

    # ICMP echo-request (ping) allowed for health checks and diagnostics
    sudo firewall-cmd --zone=k8s --add-icmp-block=echo-request --permanent

    # Access to etcd cluster (used for the Kubernetes control plane communication)
    sudo firewall-cmd --zone=k8s --add-port=2379-2380/tcp --permanent

    # Kubernetes node ports, including worker and master services and external access (for services like kubelet and external services)
    sudo firewall-cmd --zone=k8s --add-port=30000-32767/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=30000-32767/tcp --permanent
    sudo firewall-cmd --reload

    # Kubelet health and communication
    sudo firewall-cmd --zone=k8s --add-port=10250/tcp --permanent

    # BGP for Calico/Cilium
    sudo firewall-cmd --zone=k8s --add-port=179/tcp --permanent

    # Additional required ports for Cilium
    sudo firewall-cmd --zone=k8s --add-port=4244/tcp --permanent  # Hubble server
    sudo firewall-cmd --zone=k8s --add-port=4245/tcp --permanent  # Hubble Relay
    sudo firewall-cmd --zone=k8s --add-port=4250/tcp --permanent  # Mutual Auth
    sudo firewall-cmd --zone=k8s --add-port=51871/udp --permanent # WireGuard

    # VXLAN overlay network communication (used for networking between nodes in Kubernetes with VXLAN encapsulation)
    sudo firewall-cmd --zone=k8s --permanent --add-port=4789/udp
    #############################################################################
    # firewall-cmd --list-all
    sudo firewall-cmd --reload
}

install_go () {
    cd /tmp
    GO_VERSION=1.24.1
    TINYGO_VERSION=0.36.0

    # install Go
    wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

    # install tinyGo
    wget https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo${TINYGO_VERSION}.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf tinygo${TINYGO_VERSION}.linux-amd64.tar.gz

    # update path:
    files=(
        "/etc/environment"
        "$HOME/.bashrc"
    )

    extra_paths=(
        "/usr/local/go/bin"
        "/usr/local/tinygo/bin"
    )
    echo updating paths for GO
    for file in "${files[@]}"; do
        # update environemnt path:
        for path in "${extra_paths[@]}"; do
            if grep -q '^PATH=' ${file}; then
                sudo sed -i "s|^PATH=.*|&:${path}|" ${file}
            else
                sudo sed -i "1i PATH=\$PATH:${path}" "$file"
            fi
        done
    done
    echo Finished updating paths for GO

    source ~/.bashrc
}


install_helm () {
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    ln -sf /usr/local/bin/helm /usr/bin/

    add_bashcompletion helm
}

configure_containerD () {
    #############################################################################
    # configure proxy:
    sudo mkdir -p /etc/systemd/system/containerd.service.d

    cat <<EOF | sudo tee /etc/systemd/system/containerd.service.d/http-proxy.conf
[Service]
    Environment="HTTP_PROXY=$HTTP_PROXY"
    Environment="HTTPS_PROXY=$HTTP_PROXY"
    Environment="NO_PROXY=$NO_PROXY"
EOF
    #############################################################################
    # Configure containerd so that it uses systemd & cgroups on all nodes:
    #  pause version mismatch:
    containerd config default | sudo tee /etc/containerd/config.toml >/dev/null 2>&1
    sudo sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml

    sudo sed -i 's|sandbox_image = "registry.k8s.io/pause:3.8"|sandbox_image = "registry.k8s.io/pause:3.10"|' /etc/containerd/config.toml


    # ensure changes have been applied
    if sudo containerd config dump | grep -q "SystemdCgroup = true"; then
        echo Cgroups configured for containerD
    else
        echo Failed to configure Cgroups configured for containerD
        exit 1
    fi
    if sudo containerd config dump | grep -q "sandbox_image = \"registry.k8s.io/pause:3.10\""; then
        echo "set sandbox_image to pause version 3.10"
    else
        echo "Failed to set sandbox_image to pause version 3.10"
        exit 1
    fi

    sudo setfacl -m g:maintainers:rw /var/run/containerd/containerd.sock
    sudo setfacl -m g:wheel:rw /var/run/containerd/containerd.sock

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

    # check containerd version:
    containerd --version
}


prerequisites_requirements_checks() {
    # Check if the kernel is recent enough
    kernel_version=$(uname -r)
    echo "Kernel version: $kernel_version"

    # Recommended kernel version
    recommended_version_rehl="4.18"

    # Compare kernel versions
    if [[ "$(printf '%s\n' "$recommended_version" "$kernel_version" | sort -V | head -n1)" == "$recommended_version" ]]; then
        echo "Kernel version is sufficient."
    else
        echo "Kernel version is below the recommended version ($recommended_version)."
        exit 1
    fi

    # Verify eBPF is supported
    echo "Checking eBPF support..."
    sudo bpftool feature

    # Ensure that bpf is mounted
    echo "Checking if bpf is mounted..."
    mount_output=$(mount | grep /sys/fs/bpf)

    if [[ -n "$mount_output" ]]; then
        echo "bpf is mounted: $mount_output"
    else
        echo "bpf is not mounted. You may need to mount it manually."
        exit 1
    fi
    #################################################################
    # Check if the groups exist with the specified GIDs
    SUDO_GROUP=maintainers
    if getent group $SUDO_GROUP | grep -q "${SUDO_GROUP}:"; then
        echo "'${SUDO_GROUP}' Group exists."
    else
        echo "'${SUDO_GROUP}' Group does not exist, creating..."
        sudo groupadd ${SUDO_GROUP}
    fi

    # Create the user and add to groups
    # Check if the user exists
    if id "$SUDO_USERNAME" &>/dev/null; then
        echo "User $SUDO_USERNAME exists."
        sudo usermod $SUDO_USERNAME -aG wheel,${SUDO_GROUP} -s /bin/bash -m -d /home/$SUDO_USERNAME

    else
        echo "User $SUDO_USERNAME does not exist."
        sudo useradd $SUDO_USERNAME -G wheel,${SUDO_GROUP} -s /bin/bash -m
    fi

    # Set the password for the user
    echo "$SUDO_USERNAME:$SUDO_USER_PASSWORD" | sudo chpasswd

    # Append to visudo

    # Check if the visudo entry is appended
    if sudo grep -q "%$SUDO_GROUP       ALL=(ALL)       NOPASSWD:ALL" /etc/sudoers.d/10_sudo_users_groups; then
        echo "Visudo entry for $SUDO_GROUP is appended correctly."
    else
        echo "Visudo entry for $SUDO_GROUP is not found."
        sudo bash -c "echo '%$SUDO_GROUP       ALL=(ALL)       NOPASSWD:ALL' >> /etc/sudoers.d/10_sudo_users_groups"
    fi
    #################################################################
    # /etc/environment proxy:
    # Call the function
    update_path
    #################################################################
    # Disable swap space on All Nodes
    sudo swapoff -a
    sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab

    #################################################################*
    # Disable SELinux temporarily and modify config for persistence
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
    #################################################################*
    update_firewall
    #############################################################################
    # bridge network
    sudo echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/containerd.conf
    sudo modprobe overlay
    sudo modprobe br_netfilter

    sudo echo -e "net.bridge.bridge-nf-call-iptables = 1\nnet.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-ip6tables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
    sudo sysctl --system
    #############################################################################
    # install containerD
    sudo dnf install -y yum-utils
    sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo dnf install containerd.io -y
    #############################################################################
    # enable containerD NRI:
    CONFIG_FILE="/etc/containerd/config.toml"

    # Backup the original config file
    cp -n $CONFIG_FILE "${CONFIG_FILE}.bak"

    # Use sed to edit the config file
    sudo sed -i '/\[plugins."io.containerd.nri.v1.nri"\]/,/^$/{
        s/disable = true/disable = false/
        s/disable_connections = true/disable_connections = false/
        s|plugin_config_path = ".*"|plugin_config_path = "/etc/nri/conf.d"|
        s|plugin_path = ".*"|plugin_path = "/opt/nri/plugins"|
        s|plugin_registration_timeout = ".*"|plugin_registration_timeout = "15s"|
        s|plugin_request_timeout = ".*"|plugin_request_timeout = "12s"|
        s|socket_path = ".*"|socket_path = "/var/run/nri/nri.sock"|
    }' $CONFIG_FILE

    sudo mkdir -p /etc/nri/conf.d /opt/nri/plugins
    sudo chown -R root:root /etc/nri /opt/nri
    #############################################################################
    # install go:
    install_go
    #############################################################################
    # install_helm
    install_helm
    #############################################################################
    # configuration for containerd
    configure_containerD
    # containerd containerd.io 1.7.25 bcc810d6
    #############################################################################
    # Install Kubernetes tools
    # Fetch the latest stable full version (e.g., v1.32.2)
    K8S_VERSION=$(curl -L -s https://dl.k8s.io/release/stable-1.txt)

    # Extract only the major.minor version (e.g., 1.32)
    K8S_MINOR_VERSION=$(echo $K8S_VERSION | cut -d'.' -f1,2)
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






# Initialize variables
CURRENT_HOSTNAME=$(eval hostname)
NODES_FILE=""
NODE_TYPE=""
DRY_RUN=false


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
        -t|--node-type)
            NODE_TYPE="$2"
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
            echo "Usage: $0 --control-plane-hostname <str> --control-plane-port <str> --nodes-file <nodes_file> --node-type <control-plane|worker-node|> --set-hostname-to <str OPTIONAL> [--dry-run] "
            exit 1
            ;;
    esac
done


# Validate that required arguments are provided
if [ -z "$CONTROLPLANE_HOSTNAME" ] || [ -z "$CONTROLPLANE_PORT" ] || [ -z "$NODES_FILE" ] || [ -z "$NODE_TYPE" ]; then
    echo "Error: Missing required arguments."
    echo "Usage: $0 --control-plane-hostname <str> --control-plane-port <str> --nodes-file <nodes_file> --node-type <control-plane|worker-node> --set-hostname-to <str OPTIONAL> [--dry-run]"
    exit 1
fi

# Ensure that 'control-plane' or 'worker-node' is provided as node type
if [[ "$NODE_TYPE" != "control-plane" && "$NODE_TYPE" != "worker-node" ]]; then
    echo "Error: 'control-plane' or 'worker-node' must be provided as the node type."
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

sudo dnf update -y
sudo dnf install -y python3-pip yum-utils bash-completion git wget bind-utils net-tools
pip install yq

# Call the function
# prerequisites_requirements_checks


# Convert YAML to JSON using yq
if ! command_exists yq; then
    echo "Error: 'yq' command not found. Please install yq to parse YAML files."
    exit 1
fi
# Parse YAML file and append node and worker-node details to /etc/hosts
if ! command_exists jq; then
    echo "Error: 'jq' command not found. Please install jq to parse JSON files."
    exit 1
fi


# Path to the YAML file
NODES_FILE=hosts_file.yaml
TARGET_FILE="/etc/hosts"
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
    done < "$TARGET_FILE"

    # Append the line to the target file if it doesn't exist
    if [ "$exists" = false ]; then
        echo "$line" | sudo tee -a "$TARGET_FILE" > /dev/null
        echo "Host added: $line"
    else
        echo "Already exists: $line"
        echo "Host already exists: $line"
    fi
done


# Disable swap for Kubernetes compatibility
if sudo swapoff -a; then
    echo "Swap disabled."
else
    echo "Warning: Failed to disable swap."
fi
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Load required kernel modules for container runtime
sudo tee /etc/modules-load.d/containerd.conf <<EOF
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# Configure sysctl settings for Kubernetes networking
SYSCTL_CONF="/etc/sysctl.d/k8s.conf"
sudo tee "$SYSCTL_CONF" <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
sudo sysctl --system

# Install dependencies
if ! command_exists dnf; then
    echo "Error: DNF package manager not found. Exiting."
    exit 1
fi



# Add Docker repository and install containerd
DOCKER_REPO="https://download.docker.com/linux/centos/docker-ce.repo"
if ! sudo dnf config-manager --add-repo "$DOCKER_REPO"; then
    echo "Error: Failed to add Docker repository."
    exit 1
fi

sudo dnf install -y containerd.io

# Configure containerd to use systemd cgroup driver
CONTAINERD_CONFIG="/etc/containerd/config.toml"
containerd config default | sudo tee "$CONTAINERD_CONFIG" >/dev/null 2>&1
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' "$CONTAINERD_CONFIG"

# Restart and enable containerd
sudo systemctl restart containerd
sudo systemctl enable containerd

# Update Kubernetes repository to the latest minor version
K8S_REPO_FILE="/etc/yum.repos.d/kubernetes.repo"
K8S_VERSION=1.31

echo "[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v$K8S_VERSION/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v$K8S_VERSION/rpm/repodata/repomd.xml.key
exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni" | sudo tee "$K8S_REPO_FILE" > /dev/null

# Install Kubernetes components
sudo dnf install -y kubelet kubeadm kubectl --disableexcludes=kubernetes

# Enable and start kubelet
sudo systemctl enable --now kubelet

echo "Kubernetes prerequisites setup completed successfully."

echo "Adding Kubeadm bash completion"
add_bashcompletion kubeadm

# Kubeadm init logic
KUBE_ADM_COMMAND="sudo kubeadm "

if [ "$NODE_TYPE" == "control-plane" ]; then
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

    # Extract the token and CA hash from the kubeadm init output
    JOIN_TOKEN=$(echo "$KUBEADM_INIT_OUTPUT" | grep -oP 'token \K[^\s]+')
    CA_SHA256=$(echo "$KUBEADM_INIT_OUTPUT" | grep -oP 'discovery-token-ca-cert-hash sha256:\K([a-f0-9]+)' | tr -d '\n')

    if [ "$DRY_RUN" = true ]; then
        echo "Control plane dry-run initialized without errors."
    else
        echo "Control plane initialized successfully."
        # Copy kubeconfig for kubectl access
        mkdir -p $HOME/.kube
        sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
        sudo chown $(id -u):$(id -g) $HOME/.kube/config
    fi

    CONTROLPLANE_ADDRESS=$(eval ip -o -4 addr show $CONTROLPLANE_INGRESS_INTER | awk '{print $4}' | cut -d/ -f1)  # 192.168.66.129


        JOIN_YAML=./worker-node-join.yaml
        cat <<EOF | sudo tee "$JOIN_YAML" > /dev/null
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
    bootstrapToken:
        apiServerEndpoint: ${CONTROLPLANE_HOSTNAME}:${CONTROLPLANE_PORT}
        token: $JOIN_TOKEN
        caCertHashes:
        - sha256:$CA_SHA256

# eg of extra args for a node handling storage
# nodeRegistration:
#   kubeletExtraArgs:
#     enable-controller-attach-detach: "false"
#     node-labels: "node-type=rook"
EOF
    echo "Join YAML files created at $JOIN_YAML."


        JOIN_YAML=./control-plane-join.yaml
        cat <<EOF | sudo tee "$JOIN_YAML" > /dev/null
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
    bootstrapToken:
        apiServerEndpoint: ${CONTROLPLANE_HOSTNAME}:${CONTROLPLANE_PORT}
        token: $JOIN_TOKEN
        caCertHashes:
        - sha256:$CA_SHA256

controlPlane:
    localAPIEndpoint:
        advertiseAddress: ${NEW_CONTROLPLANE_ADDRESS}  # Replace with the IP address of the new control plane node
        bindPort: ${NEW_CONTROLPLANE_API_PORT}
    # certificateKey: "e6a2eb8381237ab72a4fa94f30285ec12a9694d750b9785706a83bfcbbbd2204"  # not sure
EOF
        echo "Join YAML files created at $JOIN_YAML."









# elif [ "$NODE_TYPE" == "worker-node" ]; then
#     echo "Preparing worker-node node..."

#     # Get the join command from the join_command.txt (assumes it was previously created by the control plane node)
#     if [ ! -f join_command.txt ]; then
#         echo "Error: join_command.txt not found. Ensure the control plane has been initialized."
#         exit 1
#     fi

#     JOIN_CMD=$(cat join_command.txt)
#     echo "Running join command for worker-node node: $JOIN_CMD"

#     # Run the join command on the worker-node node
#     sudo $JOIN_CMD

else
    echo "Error: Invalid node type. Use 'control-plane' or 'worker-node'."
    exit 1
fi

echo "Kubernetes node setup completed."


install_cilium

install_longhorn_prerequisites() {
    ##################################################################
    # required utilities
    sudo dnf install curl jq nfs-utils -y
    ##################################################################
    # Create ns for longhorn:
    kubectl create ns longhorn-system
    ##################################################################
    # install NFS/iSCSI on all nodes:
    for service in "nfs" "iscsi"; do
        echo "Started installation of ${service} on all nodes"
        kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml

        upper_service=$(echo ${service} | awk '{print toupper($0)}')

        # Wait for the pods to be in Running state
        echo "Waiting for Longhorn ${upper_service} installation pods to be in Running state..."
        while true; do
            PODS=$(kubectl -n longhorn-system get pod | grep longhorn-${service}-installation)
            RUNNING_COUNT=$(echo "$PODS" | grep -c "Running")
            TOTAL_COUNT=$(echo "$PODS" | wc -l)

            echo "Running Longhorn ${upper_service} install containers: ${RUNNING_COUNT}/${TOTAL_COUNT}"
            if [[ $RUNNING_COUNT -eq $TOTAL_COUNT ]]; then
                break
            fi
            sleep 5
        done

        current_retry=0
        max_retries=3
        while true; do
            current_retry=$((current_retry + 1))
            echo "Checking Longhorn ${upper_service} setup completion... try N: $current_retry"
            all_pods_up=1
            # Get the logs of the service installation container
            for POD_NAME in $(kubectl -n longhorn-system get pod | grep longhorn-${service}-installation | awk '{print $1}'); do
                LOGS=$(kubectl -n longhorn-system logs $POD_NAME -c ${service}-installation)
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
                echo "Reached maximum retry count. Exiting."
                break
            fi
        done

        kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/prerequisite/longhorn-${service}-installation.yaml
    done
    ##################################################################
    # Check if the containerd service is active
    if systemctl is-active --quiet iscsid; then
        echo "iscsi deployed successfully."
    else
        echo "iscsi service is not running..."
        exit 1
    fi
    ##################################################################
    # Ensure kernel support for NFS v4.1/v4.2:
    for ver in 1 2; do
        if $(cat /boot/config-`uname -r`| grep -q "CONFIG_NFS_V4_${ver}=y"); then
            echo NFS v4.${ver} is supported
        else
            echo ERROR: NFS v4.${ver} is not supported
        fi
    done
    ##################################################################
    # Installing Cryptsetup and LUKS
}


install_longhorn () {



}




install_certmanager () {
    ##################################################################
    # install cert-manager cli:
    OS=$(go env GOOS)
    ARCH=$(go env GOARCH)
    VERSION=2.1.1
    curl -fsSL -o cmctl https://github.com/cert-manager/cmctl/releases/download/v${VERSION}/cmctl_${OS}_${ARCH}
    chmod +x cmctl
    sudo mv cmctl /usr/local/bin
    add_bashcompletion cmctl
    ##################################################################
    # deploy cert-manager:
    CM_VERSION=1.17.1
    helm repo add jetstack https://charts.jetstack.io --force-update
    helm upgrade --install cert-manager jetstack/cert-manager  \
        --version v${CM_VERSION} \
        --namespace cert-manager \
        --create-namespace \
        -f certmanager/values.yaml
    ##################################################################
}
