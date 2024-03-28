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
