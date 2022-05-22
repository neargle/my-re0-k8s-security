#!/bin/bash

kubectl apply -f "k8s_new.yaml"
kubectl cp "1-host-ps.sh" app-shell-test-2:/tmp/1-host-ps.sh
kubectl exec -it app-shell-test-2 -- sh
