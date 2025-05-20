#### useful commands:

**force delete:**
**- Force delete a namespace**
```bash
NS=cert-manager

NS=cilium-secrets
kubectl get namespace "${NS}" -o json \
  | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
  | kubectl replace --raw /api/v1/namespaces/${NS}/finalize -f -
```