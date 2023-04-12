# cert-manager-webhook-njalla

cert-manager ACME DNS01 Webhook Solver for Njalla DNS

## Installing

```bash
$ git clone https://github.com/balzanelli/cert-manager-webhook-njalla.git
$ cd cert-manager-webhook-njalla
$ helm install cert-manager-webhook-njalla deploy/cert-manager-webhook-njalla --namespace cert-manager -f deploy/cert-manager-webhook-njalla/values.yaml
```
### Issuer/ClusterIssuer

Create a scecret for your njalla Api token

```bash
$ kubectl create secret generic njalla-credentials -n cert-manager --from-literal=token=<NJALLA_API_TOKEN>
```

An example issuer:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod-njalla
spec:
  acme:
    # The ACME server URL
    server: https://acme-v02.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: example@example.com
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-prod-njalla
    # Enable the HTTP-01 challenge provider
    solvers:
    - dns01:
        webhook:
          groupName: acme.balzanel.li
          solverName: njalla
          config:
            apiKeySecretRef:
              name: njalla-credentials
              key: token
```

Example Ingress with cert request:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress-with-cert          # < name of ingress entry
  namespace: default     # < namespace where place the ingress enty
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod-njalla" # < use letsencrypt-prod application in kubernetes to generate ssl certificate
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix  # pathType no longer has a default value in v1; "Exact", "Prefix", or "ImplementationSpecific" must be specified
        backend:
          service:
            name: example-tcp
            port:
              name: 80  # < same label as the port in the service tcp file
  tls: # < placing a host in the TLS config will indicate a cert should be created
  - hosts:
    - example.com
    secretName: example.com-tls # < cert-manager will store the created certificate in this secret.
```
