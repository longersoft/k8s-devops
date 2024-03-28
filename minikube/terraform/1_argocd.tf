resource "helm_release" "argocd" {
  name = "argocd"

  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argocd"
  version          = "3.35.4"
  namespace        = "argocd"
  create_namespace = true
  values           = [file("values/argocd.yaml")]
}
