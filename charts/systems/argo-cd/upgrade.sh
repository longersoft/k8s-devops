#!/bin/bash

if [ ! -f "values.yaml" ]; then
    ./generates-value.sh
fi

helm upgrade argocd . -n argocd
