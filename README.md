# How to setup infrastructure

## Prerequisites
Setup authenticate with AWS for pipelines:  
Option 1: Follow this [page](https://aws.amazon.com/blogs/security/use-iam-roles-to-connect-github-actions-to-actions-in-aws/) to setup the IAM roles which used for GitHub Action.  
Option 2: Goto repo settings > Add new secret with the name `AWS_ENV_VARIABLES` and the values copied from the AWS access portal. The format will be:  
```
export AWS_ACCESS_KEY_ID="xxx"
export AWS_SECRET_ACCESS_KEY="yyy"
export AWS_SESSION_TOKEN="zzz"
```

## Step 1
This step need to run from begining by manual, or via GitHub Action.
```
cd ./infrastructure/0_prerequisites
terraform init
terraform apply --auto-approve
```

## Step 2
The pipelines will be auto triggered for each environment as same as the folder name.  
Or we can run it as manual:
```
cd ./infrastructure/dev
terraform init
terraform plan
terraform apply --auto-approve
```

## Step 3
Download and install `kubectl` from this [page](https://kubernetes.io/docs/tasks/tools/).  
Download and install `helm` from this [page](https://helm.sh/docs/intro/install/).  
Add Helm Repository: Add the ArgoCD Helm repository to Helm:
```
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update
helm search repo argocd
helm show values argo/argo-cd --version 3.35.4 > ./charts/argocd/default-values.yaml
```
Create new file for argocd, for example `./minikube/terraform/values/argocd.yaml`
Install ArgoCD with Helm:
```
kubectl create namespace argocd
helm install argocd argo/argo-cd -n argocd -f ./minikube/terraform/values/argocd.yaml
```
Get the link to access to ArgoCD UI:
```
minikube service argocd-server -n argocd
Or:
kubectl port-forward service/argocd-server -n argocd 8080:80
```
Get the password:
```
kubectl -n argocd get secret argocd-secret -o jsonpath="{.data.password}" | base64 -d
```
Access to the ArgoCD admin page: [http://localhost:8080](http://localhost:8080)
Username: `admin`
