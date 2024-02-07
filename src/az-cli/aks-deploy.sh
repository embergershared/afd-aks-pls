#!/bin/bash

# Current AKS cluster deployed by the provided code:
# /mnt/d/Git/GitHub/public/azure-samples/aksfdpls-ebtests-front-door-private-link-service/az-cli/az-aksfdpls-ebtests-show.json

az aks create --name aksfdpls-ebtests-use2-446692-s4-aksfdpls-02 \
              --resource-group rg-use2-446692-s4-aksfdpls-02 \
              # [--aad-admin-group-object-ids]
              --aad-admin-group-object-ids "58d1f6ca-ce56-494a-809d-49ed859447ff" \
              # [--aad-tenant-id]
              # [--aci-subnet-name]
              # [--admin-username]
              # [--aksfdpls-ebtests-custom-headers]
              # [--api-server-authorized-ip-ranges]
              # [--appgw-id]
              # [--appgw-name]
              # [--appgw-subnet-cidr]
              # [--appgw-subnet-id]
              # [--appgw-watch-namespace]
              # [--assign-identity]
              # [--assign-kubelet-identity]
              # [--attach-acr]
              # [--auto-upgrade-channel {node-image, none, patch, rapid, stable}]
              --auto-upgrade-channel node-image \
              # [--azure-keyvault-kms-key-id]
              # [--azure-keyvault-kms-key-vault-network-access {Private, Public}]
              # [--azure-keyvault-kms-key-vault-resource-id]
              # [--azure-monitor-workspace-resource-id]
              # [--ca-profile]
              # [--client-secret]
              # [--crg-id]
              # [--data-collection-settings]
              # [--defender-config]
              # [--disable-disk-driver]
              # [--disable-file-driver]
              # [--disable-local-accounts]
              --disable-local-accounts \
              # [--disable-public-fqdn]
              # [--disable-rbac]
              # [--disable-snapshot-controller]
              # [--dns-name-prefix]
              # [--dns-service-ip]
              --dns-service-ip "10.1.0.10" \
              # [--edge-zone]
              # [--enable-aad]
              --enable-aad \
              # [--enable-addons]
              # [--enable-ahub]
              # [--enable-azure-keyvault-kms]
              # [--enable-azure-monitor-metrics]
              # [--enable-azure-rbac]
              --enable-azure-rbac \
              # [--enable-blob-driver]
              # [--enable-cluster-autoscaler]
              # [--enable-defender]
              # [--enable-encryption-at-host]
              # [--enable-fips-image]
              # [--enable-image-cleaner]
              # [--enable-keda]
              # [--enable-managed-identity]
              # [--enable-msi-auth-for-monitoring {false, true}]
              # [--enable-node-public-ip]
              # [--enable-oidc-issuer]
              # [--enable-private-cluster]
              # [--enable-secret-rotation]
              # [--enable-sgxquotehelper]
              # [--enable-syslog {false, true}]
              # [--enable-ultra-ssd]
              # [--enable-vpa]
              # [--enable-windows-gmsa]
              # [--enable-windows-recording-rules]
              # [--enable-workload-identity]
              # [--fqdn-subdomain]
              # [--generate-ssh-keys]
              # [--gmsa-dns-server]
              # [--gmsa-root-domain-name]
              # [--gpu-instance-profile {MIG1g, MIG2g, MIG3g, MIG4g, MIG7g}]
              # [--grafana-resource-id]
              # [--host-group-id]
              # [--http-proxy-config]
              # [--image-cleaner-interval-hours]
              # [--ip-families]
              # [--k8s-support-plan {AKSLongTermSupport, KubernetesOfficial}]
              # [--ksm-metric-annotations-allow-list]
              # [--ksm-metric-labels-allow-list]
              # [--kubelet-config]
              # [--kubernetes-version]
              --kubernetes-version "1.27.7" \
              # [--linux-os-config]
              # [--load-balancer-backend-pool-type {nodeIP, nodeIPConfiguration}]
              # [--load-balancer-idle-timeout]
              # [--load-balancer-managed-outbound-ip-count]
              # [--load-balancer-managed-outbound-ipv6-count]
              # [--load-balancer-outbound-ip-prefixes]
              # [--load-balancer-outbound-ips]
              # [--load-balancer-outbound-ports]
              # [--load-balancer-sku {basic, standard}]
              --load-balancer-sku standard \
              # [--location]
              --location eastus2 \
              # [--max-count]
              # [--max-pods]
              --max-pods 150
              # [--min-count]
              # [--nat-gateway-idle-timeout]
              # [--nat-gateway-managed-outbound-ip-count]
              # [--network-dataplane {azure, cilium}]
              # [--network-plugin {azure, kubenet, none}]
              --network-plugin azure \
              # [--network-plugin-mode {overlay}]
              # [--network-policy]
              --network-policy azure \
              # [--no-ssh-key]
              --no-ssh-key \
              # [--no-wait]
              --no-wait \
              # [--node-count]
              --node-count 2 \
              # [--node-os-upgrade-channel {NodeImage, None, Unmanaged}]
              --node-os-upgrade-channel NodeImage \
              # [--node-osdisk-diskencryptionset-id]
              # [--node-osdisk-size]
              # [--node-osdisk-type {Ephemeral, Managed}]
              # [--node-public-ip-prefix-id]
              # [--node-public-ip-tags]
              # [--node-resource-group]
              --node-resource-group rg-use2-446692-s4-aksfdpls-02-managed \
              # [--node-vm-size]
              --node-vm-size Standard_B2s \
              # [--nodepool-allowed-host-ports]
              # [--nodepool-asg-ids]
              # [--nodepool-labels]
              # [--nodepool-name]
              --nodepool-name system \
              # [--nodepool-tags]
              # [--nodepool-taints]
              # [--os-sku {AzureLinux, CBLMariner, Mariner, Ubuntu}]
              --os-sku Ubuntu \
              # [--outbound-type {loadBalancer, managedNATGateway, userAssignedNATGateway, userDefinedRouting}]
              --outbound-type loadBalancer \
              # [--pod-cidr]
              # [--pod-cidrs]
              # [--pod-subnet-id]
              --pod-subnet-id "/subscriptions/34144584-4817-47a0-a912-bd00bae76495/resourcegroups/rg-use2-446692-s4-aksfdpls-02/providers/Microsoft.Network/virtualNetworks/vnet-use2-446692-s4-aksfdpls-02/subnets/aksfdpls-ebtests-pod-snet" \
              # [--ppg]
              # [--private-dns-zone]
              # [--rotation-poll-interval]
              # [--service-cidr]
              --service-cidr "10.1.0.0/16" \
              # [--service-cidrs]
              # [--service-principal]
              # [--skip-subnet-role-assignment]
              # [--snapshot-id]
              # [--ssh-key-value]
              # [--tags]
              # [--tier {free, premium, standard}]
              --tier free \
              # [--vm-set-type]
              --vm-set-type VirtualMachineScaleSets \
              # [--vnet-subnet-id]
              --vnet-subnet-id "/subscriptions/34144584-4817-47a0-a912-bd00bae76495/resourcegroups/rg-use2-446692-s4-aksfdpls-02/providers/Microsoft.Network/virtualNetworks/vnet-use2-446692-s4-aksfdpls-02/subnets/aksfdpls-ebtests-systempool-snet"
              # [--windows-admin-password]
              # [--windows-admin-username]
              # [--workspace-resource-id]
              # [--yes]
              # [--zones]

$subscriptionId="34144584-4817-47a0-a912-bd00bae76495"
$clusterName="aksfdpls-ebtests-use2-446692-s4-aksfdpls-ebtests-fd-pls-02"
$resourceGroupName="rg-use2-446692-s4-aksfdpls-02"
$vnetId="/subscriptions/34144584-4817-47a0-a912-bd00bae76495/resourcegroups/rg-use2-446692-s4-aksfdpls-02/providers/Microsoft.Network/virtualNetworks/vnet-use2-446692-s4-aksfdpls-02"

# Login to right subscription
az login
az account set --subscription $subscriptionId

az aks create --name $clusterName \
  --resource-group $resourceGroupName \
  --aad-admin-group-object-ids "58d1f6ca-ce56-494a-809d-49ed859447ff" \
  --auto-upgrade-channel node-image \
  --enable-aad \
  --enable-azure-rbac \
  --kubernetes-version "1.27.7" \
  --location eastus2 \
  --max-pods 150 \
  --network-plugin azure \
  --no-ssh-key \
  --node-count 2 \
  --node-resource-group $resourceGroupName-managed \
  --node-vm-size Standard_B2s \
  --nodepool-name system \
  --os-sku Ubuntu \
  --disable-local-accounts \
  --outbound-type loadBalancer \
  --pod-subnet-id "$vnetId/subnets/aksfdpls-ebtests-pod-snet" \
  --service-cidr "10.1.0.0/16" \
  --dns-service-ip "10.1.0.10" \
  --tier free \
  --vm-set-type VirtualMachineScaleSets \
  --vnet-subnet-id "$vnetId/subnets/aksfdpls-ebtests-systempool-snet"

# Ensure updated kubeconfig
az aks get-credentials --resource-group $resourceGroupName --name $clusterName --overwrite-existing
# Credentials stored in C:\Users\emberger\.kube\config
kubelogin convert-kubeconfig -l azurecli

# Get Cluster resource ID
aksClusterId=$(az aks show --name $clusterName \
  --resource-group $resourceGroupName \
  --query id \
  --output tsv)

# Give AKS MSI Network contributor on AKS Vnet (to create ILB)
aksPrincipalId=$(az aks show --name $clusterName \
  --resource-group $resourceGroupName \
  --query identity.principalId \
  --output tsv)

az role assignment create \
  --role "Network Contributor" \
  --assignee-object-id $aksPrincipalId \
  --assignee-principal-type "ServicePrincipal" \
  --scope $vnetId

# ============>  Deploying NGINX ingress controller
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm pull ingress-nginx/ingress-nginx --untar

# Edit the Helm chart:
# go to the file
# ./ingress-nginx/templates/controller-service.yaml
# Hard insert:
# metadata:
#   annotations:
#     service.beta.kubernetes.io/azure-load-balancer-internal: "true"
#     service.beta.kubernetes.io/azure-pls-create: "true"
#     service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path: "/healthz"

# helm install nginx-ingress ./ingress-nginx \
#     --namespace ingress-nginx \
#     --set controller.config.enable-modsecurity=true \
#     --set controller.config.enable-owasp-modsecurity-crs=true \
#     --set controller.replicaCount=3
    #  \
    # --set controller.service.annotations.\"service\.beta\.kubernetes\.io/azure-load-balancer-internal\"=true \
    # --set controller.service.annotations.\"service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path\"=/healthz

# ============>  Deploying Cert Manager
# It automatically provision Certificates for Ingress resources
# https://cert-manager.io/docs/usage/ingress/
# helm repo add jetstack https://charts.jetstack.io
# helm repo update

# helm install cert-manager jetstack/cert-manager \
#   --namespace cert-manager \
#   --set installCRDs=true
# #  --set nodeSelector.\"kubernetes\.io/os\"=\"linux\"
# #  --create-namespace \

# Install AKS App routing Addon
# Ref: https://learn.microsoft.com/en-us/azure/aks/app-routing?tabs=default%2Cdeploy-app-default

az aks approuting enable -g $resourceGroupName -n $ClusterName

# Deploy test app
cd D:\Git\GitHub\public\azure-samples\aksfdpls-ebtests-front-door-private-link-service\az-cli\aksfdpls-ebtests-app-routing
cd /mnt/d/Git/GitHub/public/azure-samples/aksfdpls-ebtests-front-door-private-link-service/az-cli/aksfdpls-ebtests-app-routing/

k apply -f .\aksapprouting-ns.yaml
k apply -f .\aksapprouting-dep.yaml
k apply -f .\aksapprouting-svc.yaml
k apply -f .\aksapprouting-ing.yaml

20.161.138.33    approuting.akspls.ebtests A record

nslookup approuting.akspls.ebtests
# Resolves to the nginx Public IP:
nslookup approuting.akspls.ebtests
Server:  pfSense.ds.bergerat.org
Address:  192.168.62.1

Name:    approuting.akspls.ebtests
Address:  20.161.138.33

# Http query works:
curl http://approuting.akspls.ebtests
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <link rel="stylesheet" type="text/css" href="/static/default.css">
    <title>Welcome to Azure Kubernetes Service (AKS)</title>

    <script language="JavaScript">
        function send(form){
        }
    </script>

</head>
<body>
    <div id="container">
        <form id="form" name="form" action="/" method="post"><center>
        <div id="logo">Welcome to Azure Kubernetes Service (AKS)</div>
        <div id="space"></div>
        <img src="/static/acs.png" als="acs logo">
        <div id="form">
        </div>
    </div>
</body>
</html>


# Deploy the httpbin app in AKS
namespace="httpbin"

# Create a namespace for the application
command="kubectl create namespace $namespace"
az aks command invoke \
  --name $clusterName \
  --resource-group $resourceGroupName \
  --subscription $subscriptionId \
  --command "$command"
# OR
kubectl apply -f httpbin-ns.yaml


# Create a deployment and service for the application
command="cat <<EOF | kubectl apply -n $namespace -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpbin
spec:
  replicas: 3
  selector:
    matchLabels:
      app: httpbin
  template:
    metadata:
      labels:
        app: httpbin
    spec:
      topologySpreadConstraints:
      - maxSkew: 1
        topologyKey: topology.kubernetes.io/zone
        whenUnsatisfiable: DoNotSchedule
        labelSelector:
          matchLabels:
            app: httpbin
      - maxSkew: 1
        topologyKey: kubernetes.io/hostname
        whenUnsatisfiable: DoNotSchedule
        labelSelector:
          matchLabels:
            app: httpbin
      nodeSelector:
        "kubernetes.io/os": linux
      containers:
      - image: docker.io/kennethreitz/httpbin
        imagePullPolicy: IfNotPresent
        name: httpbin
        resources:
          requests:
            memory: "64Mi"
            cpu: "125m"
          limits:
            memory: "128Mi"
            cpu: "250m"
        ports:
        - containerPort: 80
        env:
        - name: PORT
          value: "80"
---
apiVersion: v1
kind: Service
metadata:
  name: httpbin
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: ClusterIP
  selector:
    app: httpbin
EOF"

az aks command invoke \
  --name $clusterName \
  --resource-group $resourceGroupName \
  --subscription $subscriptionId \
  --command "$command"

# Create an ingress resource for the application
hostName='httpbin.local'
httpPort=80
httpsPort=443
originHostHeader=$hostName

command="cat <<EOF | kubectl apply -n $namespace -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: httpbin
spec:
  # ingressClassName: nginx
  ingressClassName: webapprouting.kubernetes.azure.com
  rules:
  - host: $hostName
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: httpbin
            port:
              number: 80
EOF"

az aks command invoke \
  --name $clusterName \
  --resource-group $resourceGroupName \
  --subscription $subscriptionId \
  --command "$command"

# Test the app with Public IP
curl http://httpbin.akspls.ebtests


# Adding advanced App routing settings
## Auto TLS
# Ref: https://learn.microsoft.com/en-us/azure/aks/app-routing-dns-ssl

### Integrate with Key vault to get certificates:
$KeyVaultName="kv-use2-446692-s4-aksfdp"
$kvTlsCertName="aksfdpls-ebtests-ingress-tls"
$KEYVAULTID=$(az keyvault show --name $KeyVaultName --query "id" --output tsv)
az aks approuting update -g $ResourceGroupName -n $ClusterName --enable-kv --attach-kv ${KEYVAULTID}
# => Creates a "Key Vaul Secrets User" role assignment to the Managed Identity webapprouting-aks-use2-446692-s4-aks-fd-pls-02 on the KV

### Generate a self-signed wildcard certificate
openssl req -new -x509 -nodes -out $kvTlsCertName.crt -keyout $kvTlsCertName.key -subj "/CN=*.akspls.ebtests" -addext "subjectAltName=DNS:*.akspls.ebtests"
openssl pkcs12 -export -in $kvTlsCertName.crt -inkey $kvTlsCertName.key -out $kvTlsCertName.pfx
az keyvault certificate import --vault-name $KeyVaultName -n $kvTlsCertName -f $kvTlsCertName.pfx # [--password <certificate password if specified>]

### Attach the Private DNS Zone to app routing addon
# $ZoneName="akspls.ebtests"
# $ZONEID=$(az network dns zone show -g $ResourceGroupName -n $ZoneName --query "id" --output tsv)
$ZONEID="/subscriptions/34144584-4817-47a0-a912-bd00bae76495/resourceGroups/rg-use2-446692-s4-aksfdpls-02/providers/Microsoft.Network/privateDnsZones/akspls.ebtests"
az aks approuting zone add -g $ResourceGroupName -n $ClusterName --ids=${ZONEID} --attach-zones
# Disable with:
az aks approuting zone delete -g $ResourceGroupName -n $ClusterName --ids=${ZONEID}


### Create an ingress with TLS
# Get the TLS cert KV Id:
az keyvault certificate show --vault-name $KeyVaultName -n $kvTlsCertName --query "id" --output tsv
# Result = https://kv-use2-446692-s4-aksfdp.vault.azure.net/certificates/aksfdpls-ebtests-ingress-tls/d33d696c8c9f4c9bb318b550c449323e

k apply -f .\aksapprouting-ing-approutingtls.yaml






# Test the App in AFD
curl -I http://httpbin.local
curl -I http://use2-446692-s4-aksfdpls-ebtests-fd-plsfrontdoorendpoint-bqgpc5awhbdjenf8.b01.azurefd.net/
curl -I https://use2-446692-s4-aksfdpls-ebtests-fd-plsfrontdoorendpoint-bqgpc5awhbdjenf8.b01.azurefd.net/

