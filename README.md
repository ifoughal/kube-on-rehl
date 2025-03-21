

# Introduction

This is a step by step guide that has been automated through the [deploy-cluster bash script](./deploy-cluster.sh)

The cluster is based on kubeadm, managed by kubectl.

It relies on [cilium](https://docs.cilium.io/en/stable/) as its [Network Plugin](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/). Cilium is used as [L7](https://docs.cilium.io/en/stable/network/servicemesh/l7-traffic-management/) loadblancer with [Maglev](https://static.googleusercontent.com/media/research.google.com/ko//pubs/archive/44824.pdf), as well as ingress controller.

For storage, the cluster relies on [Longhorn](https://longhorn.io/docs/1.8.1/what-is-longhorn/).

For TLS, [CertManager](https://cert-manager.io/docs/) will be used with [vault]()

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



# Examples:
To deploy docker built containers:
https://docs.docker.com/guides/kube-deploy/


# Troubleshooting




# TODO list
- The cluster needs to be secured, all HTTP requests to kue-api must be protected, etc as per the [kubernetes cluster administration recommendations](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)

- Vault high availability  [ configuration](https://developer.hashicorp.com/vault/docs/platform/k8s/helm/configuration)
- Vault architecture [recommendations](https://developer.hashicorp.com/vault/docs/platform/k8s/helm/run#architecture)
- Vault production deployment [ checklist](https://developer.hashicorp.com/vault/docs/platform/k8s/helm/run#production-deployment-checklist)

