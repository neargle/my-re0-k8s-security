./kubectl config set-cluster cfc --server=https://${api_server} --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
./kubectl config set-context cfc --cluster=cfc
./kubectl config set-credentials user --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
./kubectl config set-context cfc --user=user
./kubectl config use-context cfc