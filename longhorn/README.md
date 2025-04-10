### [Prerequisites](./prerequisites.md)
Ensure that you have followed through all the [Prerequisites](./prerequisites.md) requirements for Longhorn prior to installing.

### Installation

For our Longhorn deployment, we will be using the [Longhron Helm Chart](https://artifacthub.io/packages/helm/longhorn/longhorn).

```bash
helm repo add longhorn https://charts.longhorn.io
helm repo update

helm install longhorn longhorn/longhorn \
    --namespace longhorn-system --create-namespace \
    --version 1.8.1 -f values.yaml

```

Check longhorn pods state:
```bash
kubectl -n longhorn-system get pod
```

#### Longhorn UI:

**Step 1: Create a basic auth file:**
If you install Longhorn on a Kubernetes cluster with kubectl or Helm, you will need to create an Ingress to allow external traffic to reach the Longhorn UI.

Authentication is not enabled by default for kubectl and Helm installations. In these steps, you’ll learn how to create an Ingress with basic authentication using annotations for the nginx ingress controller.
```bash
USER=admin
PASSWORD=IxVSvwiIVZqt37lYuWqY
echo "${USER}:$(openssl passwd -stdin -apr1 <<< ${PASSWORD})" >> auth
```

Create the secret from the auth file:
```bash
kubectl -n longhorn-system create secret generic basic-auth --from-file=auth
```


Apply the ingress:
```bash
kubectl -n longhorn-system apply -f longhorn-cilium-ingress.yaml
```

Describe cilium ingress:
```bash
kubectl describe ingress -n longhorn-system longhorn-cilium-ingress
```

once the ingress is deployed, you must annotate it with the name of the CA issuer which we created.

```bash
INGRESS_NAME=longhorn-cilium-ingress
kubectl annotate ingress -n longhorn-system ${INGRESS_NAME} cert-manager.io/issuer=ca-issue
```

Ensure the certs and secrets have been created:
```bash
TLS_NAME=longhorn-cert
kubectl get certificate,secret -n longhorn-system $TLS_NAME
```


commands from lab:
INGRESS_IP=$(kubectl get ingress -n longhorn-system longhorn-cilium-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}')


echo $INGRESS_IP

<!--
Expose the ingress with [Nginx-ingress-controller](https://kubernetes.github.io/ingress-nginx/deploy/#bare-metal-clusters):
```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.12.0/deploy/static/provider/baremetal/deploy.yaml
```

Check the nginx controller dpeloyment:
```bash
POD_NAMESPACE=ingress-nginx
POD_NAME=$(kubectl get pods -n $POD_NAMESPACE -l app.kubernetes.io/name=ingress-nginx --field-selector=status.phase=Running -o name)
kubectl exec $POD_NAME -n $POD_NAMESPACE -- /nginx-ingress-controller --version

# to delete the ingress:
# kubectl delete deployments.apps -n ingress-nginx ingress-nginx-controller
# kubectl delete -f nginx-longhorn-ingress.yaml
# kubectl delete svc -n ingress-nginx ingress-nginx-controller
# kubectl delete svc -n ingress-nginx ingress-nginx-controller-admission
# kubectl delete validatingwebhookconfiguration ingress-nginx-admission

``` -->
<!--
Host network mode:

Host network mode allows you to expose the Cilium ingress controller (Envoy listener) directly on the host network. This is useful in cases where a LoadBalancer Service is unavailable, such as in development environments or environments with cluster-external loadbalancers.


Enabling the Cilium ingress controller host network mode automatically disables the LoadBalancer/NodePort type Service mode. They are mutually exclusive.

The listener is exposed on all interfaces (0.0.0.0 for IPv4 and/or :: for IPv6). -->


![alt text](image-1.png)








### configure UI access:

https://longhorn.io/docs/1.8.1/deploy/accessing-the-ui/longhorn-ingress/

https://longhorn.io/docs/1.8.1/deploy/accessing-the-ui/