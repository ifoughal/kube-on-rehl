# steps:

### step 0: Designating Strimzi administrators



kubectl create -f install/strimzi-admin

kubectl create clusterrolebinding strimzi-admin --clusterrole=strimzi-admin --user=user1 --user=user2


Install admin to operator strimzi CRDS for kafka configuration:

https://strimzi.io/docs/operators/latest/deploying#adding-users-the-strimzi-admin-role-str











## Role types:

Controller nodes operate in the control plane to manage cluster metadata and the state of the cluster using a Raft-based consensus protocol.

- Broker nodes operate in the data plane to manage the streaming of messages, receiving and storing data in topic partitions.

- Dual-role nodes fulfill the responsibilities of controllers and brokers.







## Configuration targers:

- Dynamic controller quorums

- You can configure a deployment where Strimzi manages a single Kafka cluster in the same namespace, suitable for development or testing. Alternatively, Strimzi can manage multiple Kafka clusters across different namespaces in a production environment.

- To avoid the issues associated with installing multiple Strimzi operators in a Kubernetes cluster, the following guidelines are recommended:

Install the Strimzi operator in a separate namespace from the Kafka cluster and other Kafka components it manages, to ensure clear separation of resources and configurations.

Use a single Strimzi operator to manage all your Kafka instances within a Kubernetes cluster.

Update the Strimzi operator and the supported Kafka version as often as possible to reflect the latest features and enhancements.

By following these best practices and ensuring consistent updates for a single Strimzi operator, you can enhance the stability of managing Kafka instances in a Kubernetes cluster. This approach also enables you to make the most of Strimzi’s latest features and capabilities.
<!-- https://strimzi.io/docs/operators/latest/deploying#con-deploy-operator-best-practices-str -->

- create and designate strimzi oeprator admins: https://strimzi.io/docs/operators/latest/deploying#adding-users-the-strimzi-admin-role-str





Retrieving the bootstrap address:
kubectl get kafka my-cluster -o=jsonpath='{.status.listeners[?(@.name=="tls")].bootstrapServers}{"\n"}'





OPTIONAL: Kafka bridge for HTTP client/producer communication
https://strimzi.io/docs/bridge/latest/