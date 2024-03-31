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

## Step 4
Install ArgoCD with Helm:
```
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update
helm search repo argocd
helm show values argo/argo-cd --version 3.35.4 > ./charts/argocd/default-values.yaml
```
Then, install ArgoCD:
```
kubectl create namespace argocd
helm install argocd argo/argo-cd -n argocd
```
Get the link to access to ArgoCD UI:
```
minikube service argocd-server -n argocd
Or:
kubectl port-forward service/argocd-server -n argocd 8080:443
```
Get the password:
```
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```
Access to the ArgoCD admin page: [http://localhost:8080](http://localhost:8080)  
Username: `admin`  
Password: `decoded-above`

## Step 5
Install PostgreSQL with Helm:
```
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
kubectl create namespace postgresql
helm install postgresql bitnami/postgresql -n postgresql
kubectl get pods -n postgresql
kubectl port-forward svc/postgresql 5432:5432
```
The info:
```
Host: postgresql.postgresql.svc.cluster.local - Read/Write connection
User: postgres
Pass: export POSTGRES_PASSWORD=$(kubectl get secret --namespace postgresql postgresql -o jsonpath="{.data.postgres-password}" | base64 -d)
```
To connect to your database run the following command:
```
kubectl run postgresql-client --rm --tty -i --restart='Never' --namespace postgresql --image docker.io/bitnami/postgresql:16.20-debian-12-r10 --env="PGPASSWORD=$POSTGRES_PASSWORD" \
--command -- psql --host postgresql -U postgres -d postgres -p 5432
```
To connect to your database from outside the cluster execute the following commands:
```
kubectl port-forward --namespace postgresql svc/postgresql 5432:5432 & 
PGPASSWORD="$POSTGRES_PASSWORD" psql --host 127.0.0.1 -U postgres -d postgres -p 5432
```

## Step 6
For all application repos (k8s-frontend, k8s-backend):  
Goto repo settings > Add new secret with the name `DOCKER_USERNAME` and `DOCKER_PASSWORD` to access, build and push docker image to DockerHub.  
Generate new SSH key.  
Goto repo k8s-devops settings > Add new secret with the name `DEVOPS_DEPLOY_TOKEN` with content is public-key.   
Goto application repos (k8s-frontend, k8s-backend) settings > Add new secret with the name `DEVOPS_DEPLOY_TOKEN` with content is private-key.  

## Step 7
Create application with ArgoCD
