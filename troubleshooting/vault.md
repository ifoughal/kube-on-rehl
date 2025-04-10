

# force uninstall vault:
```bash
kubectl delete -n $CHART_NS ds/vault-manager ds/vault-nfs-installation deployments/vault-ui deployments/vault-driver-deployer jobs/vault-uninstall >/dev/null 2>&1 || true
```


