# Settings that work with an ILB service with PLS and AFD origins to the PLS (no ingress)

App URL: https://use2-446692-s4-aks-fd-plsfrontdoorendpoint-bqgpc5awhbdjenf8.b01.azurefd.net/

10.0.1.6
azure-vote.test


https://techcommunity.microsoft.com/t5/fasttrack-for-azure/how-to-expose-nginx-ingress-controller-via-azure-front-door-and/ba-p/3767535

I have used NGINX Ingress controller, first I used values file to add annotations while installing the Helm charts for NGINX. Detail about values file is available here: https://github.com/kubernetes/ingress-nginx/blob/main/charts/ingress-nginx/values.yaml

Content of my values.yaml file looks like:

controller:
  service:
    annotations:
        service.beta.kubernetes.io/azure-load-balancer-internal: "true"
        service.beta.kubernetes.io/azure-pls-create: "true"
        service.beta.kubernetes.io/azure-pls-name: "pls-ingress-nginx"
#        service.beta.kubernetes.io/azure-pls-visibility: "*"
        service.beta.kubernetes.io/azure-pls-visibility: "34144584-4817-47a0-a912-bd00bae76495"
        service.beta.kubernetes.io/azure-pls-ip-configuration-subnet: "aks-ilb-snet"
        service.beta.kubernetes.io/azure-pls-ip-configuration-ip-address-count: "1"
        service.beta.kubernetes.io/azure-pls-proxy-protocol: "false"
        service.beta.kubernetes.io/azure-pls-auto-approval: "34144584-4817-47a0-a912-bd00bae76495"


Now install NGINX Ingress using Helm chart. Make sure you refer the values file:

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

helm install nginx-ing ingress-nginx/ingress-nginx -f ingress-nginx-values.yaml --set controller.replicaCount=2

helm upgrade nginx-ing ingress-nginx/ingress-nginx --reuse-values --set defaultBackend.enabled=true

https://aksafdpls-g2dqh6dvctcmgdfb.b01.azurefd.net

https://azvote.ebdemos.info

https://test.ebdemos.info


