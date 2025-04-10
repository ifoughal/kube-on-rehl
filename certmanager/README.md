

#### Deploy Cert-manager for TLS:
<!-- install gateway-api CRDS for kubernetes:
```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
``` -->



install cert-manager cli:

```bash
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
VERSION=2.1.1
curl -fsSL -o cmctl https://github.com/cert-manager/cmctl/releases/download/v${VERSION}/cmctl_${OS}_${ARCH}
chmod +x cmctl
sudo mv cmctl /usr/local/bin
```

kubectl expose deployment -n cert-manager cert-manager-webhook --type=ClusterIP --name cert-manager-webhook-service

curl -vsS --resolve cert-manager-webhook.cert-manager.svc.cluster.local:10555:127.0.0.1 \
    --service-name cert-manager-webhook-ca \
    --cacert <(kubectl -n cert-manager get secret cert-manager-webhook-ca -ojsonpath='{.data.ca\.crt}' | base64 -d) \
    https://cert-manager-webhook.cert-manager.svc.cluster.local:10555/validate 2>&1 -d@- <<'EOF' | sed '/^* /d; /bytes data]$/d; s/> //; s/< //'
{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","request":{"requestKind":{"group":"cert-manager.io","version":"v1","kind":"Certificate"},"requestResource":{"group":"cert-manager.io","version":"v1","resource":"certificates"},"name":"foo","namespace":"default","operation":"CREATE","object":{"apiVersion":"cert-manager.io/v1","kind":"Certificate","spec":{"dnsNames":["foo"],"issuerRef":{"group":"cert-manager.io","kind":"Issuer","name":"letsencrypt"},"secretName":"foo","usages":["digital signature"]}}}}
EOF




deploy cert-manager:
```bash
helm repo add jetstack https://charts.jetstack.io --force-update

CM_VERSION=1.17.1

helm upgrade --install cert-manager jetstack/cert-manager  \
    --version v${CM_VERSION} \
    --namespace cert-manager \
    --create-namespace \
    -f values.yaml
```


#### Verifying the installation

Test resources:
```bash
kubectl apply -f test-resources.yaml
```

Check the status:
```bash
kubectl describe certificate -n cert-manager-test
```

Clean up the test resources.
```bash
kubectl delete -f test-resources.yaml
```






#### To uninstall cert-maanger:

```bash
CM_VERSION=1.17.1
helm uninstall -n cert-manager cert-manager
kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/v${CM_VERSION}/cert-manager.yaml

kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/v${CM_VERSION}/cert-manager.crds.yaml

kubectl delete crd \
  issuers.cert-manager.io \
  clusterissuers.cert-manager.io \
  certificates.cert-manager.io \
  certificaterequests.cert-manager.io \
  orders.acme.cert-manager.io \
  challenges.acme.cert-manager.io

kubectl delete apiservice v1beta1.webhook.cert-manager.io


NS=cert-manager
kubectl get namespace "${NS}" -o json \
  | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
  | kubectl replace --raw /api/v1/namespaces/${NS}/finalize -f -
```



kubectl delete validatingwebhookconfiguration cert-manager-webhook
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.16/cert-manager.yaml

Create CA issuer:
```bash
# source: https://raw.githubusercontent.com/cilium/cilium/HEAD/examples/kubernetes/servicemesh/
kubectl apply -f ca-issuer.yaml
```

Deploy the TLS ingress, refer to [Longhorn deployment](../longhorn/README.md#longhorn-ui).
once the ingress is deployed, you must annotate it with the name of the CA issuer which we created.

```bash
INGRESS_NAME=tls-ingress
kubectl annotate ingress ${INGRESS_NAME} cert-manager.io/issuer=ca-issue
```

Ensure the certs and secrets have been created:
```bash
TLS_NAME=example-name
kubectl get certificate,secret $TLS_NAME
```



$ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/HEAD/examples/kubernetes/servicemesh/tls-ingress.yaml
