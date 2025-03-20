

add_bashcompletion () {
    # Parse the application name as a function argument
    app="$1"

    if [ -z "$app" ]; then
        echo "Error: Application name must be provided."
        return 1
    fi

    COMPLETION_FILE="/etc/bash_completion.d/$app"

    for i in $(seq 1 "$NODES_COUNT"); do
        NODE_VAR="NODE_$i"
        CURRENT_NODE=${!NODE_VAR}

        echo "Adding $app bash completion for node: ${CURRENT_NODE}"

        # Assuming the application has a completion script available
        ssh -q ${CURRENT_NODE} """
            $app completion bash | sudo tee "$COMPLETION_FILE" >/dev/null
        """
        echo "$app bash completion added successfully."
    done
    source $COMPLETION_FILE
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

    sudo firewall-cmd --zone=public --add-port=${CONTROLPLANE_API_PORT}/tcp --permanent
    sudo firewall-cmd --zone=k8s --add-port=${CONTROLPLANE_API_PORT}/tcp --permanent

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





