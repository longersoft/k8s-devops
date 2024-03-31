#!/bin/bash

if [ ! -f "values.yaml" ]; then
    ./generates-value.sh
fi

helm install argocd . -n argocd
