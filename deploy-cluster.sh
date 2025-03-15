#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Fail if any piped command fails

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
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
    export PATH
    # Print the updated PATH for verification
    echo "Updated PATH: $PATH"
}



update_firewall() {
    sudo firewall-cmd --zone=public --add-port=6443/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=10250/tcp --permanent
    sudo firewall-cmd --reload
}

# Call the function
update_path


# Initialize variables
CURRENT_HOSTNAME=$(eval hostname)
NODES_FILE=""
NODE_TYPE=""
DRY_RUN=false

echo 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' | sudo tee -a /etc/environment

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

sestatus


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
COMPLETION_FILE=/etc/bash_completion.d/kubeadm
kubeadm completion bash | sudo tee $COMPLETION_FILE >/dev/null

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
    KUBEADM_INIT_OUTPUT=$(eval "$KUBE_ADM_COMMAND" 2> "/var/log/kubeadm_init_errors.log")

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

    CONTROLPLANE_ADDRESS=$(eval ip -o -4 addr show ens160 | awk '{print $4}' | cut -d/ -f1)  # 192.168.66.129


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
