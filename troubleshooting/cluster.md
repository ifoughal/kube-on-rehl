


##### Premption/Premptive errors during pods creations:

When nodes get rebooted, they get tainted with NoSchedule.
To remove the taint on worker nodes:

```bash
node_name=lorionstrm03vel
kubectl taint nodes $node_name node.cilium.io/agent-not-ready:NoSchedule-
kubectl taint nodes $node_name node.kubernetes.io/not-ready:NoSchedule-
kubectl taint nodes $node_name node.kubernetes.io/not-ready:NoExecute-
```

on master/controller nodes:
```bash
node_name=lorionstrm01vel
kubectl taint nodes $node_name node-role.kubernetes.io/control-plane:NoSchedule-
```

# ping/curl test container:

```bash
namespace=kube-system
kubectl run curl-test --image=radial/busyboxplus:curl -n ${namespace} --restart=Always -- tail -f /dev/null

kubectl exec -ti -n ${namespace} curl-test -- /bin/sh

# test curl:
curl -4  https://metallb-webhook-service.metallb-system.svc.cluster.local -vvv --insecure

curl -4  https://metallb-webhook-service.metallb-system.svc -vvv --insecure
```


# Generate join token:
```bash
kubeadm token create --print-join-command
```

