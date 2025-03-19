

# Introduction

This is a step by step guide that has been automated through the [deploy-cluster bash script](./deploy-cluster.sh)

The cluster is based on kubeadm, managed by kubectl.

It relies on [cilium](https://docs.cilium.io/en/stable/) as its [Network Plugin](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/). Cilium is used as L7 loadblancer, as well as ingress controller.

For storage, the cluster relies on [Longhorn](https://longhorn.io/docs/1.8.1/what-is-longhorn/).

For TLS, [CertManager](https://cert-manager.io/docs/)

Currently, there is no Device plugin installation for the cluster. Feel free to explore your [options](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/#examples)


All installations are done through helm when possible.

SSH certficates are generated an propagated through the main control-plane node.

Currently the automated installation supports only 3 nodes with a single control-plane.



# Installation steps
## Manual installations step-by-step
  - [Install and configure your cluster](./cluster-deployment/README.md)

## automated installation

### Step 1:
configure your [.env](./.env) file with your specific parameters.

### Step 2:
Run the deployment script:
```bash
sudo chmod +x ./deployment-script.sh

./deployment-script.sh
```



# Troubleshooting


