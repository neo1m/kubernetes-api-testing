const serverCSR = {
    apiVersion: "certificates.k8s.io/v1",
    kind: "CertificateSigningRequest",
    metadata: {
        name: "<csr-name>"
    },
    spec: {
        groups: [
            "system:nodes",
            "system:authenticated"
        ],
        request: "<csr-base64>",
        signerName: "kubernetes.io/kubelet-serving",
        usages: [
            "digital signature",
            "server auth"
        ],
        username: "system:node:<name>"
    }
}

const clientCSR = {
    apiVersion: "certificates.k8s.io/v1",
    kind: "CertificateSigningRequest",
    metadata: {
        name: "<csr-name>"
    },
    spec: {
        groups: [
            "system:bootstrappers",
            "system:bootstrappers:kubeadm:default-node-token",
            "system:authenticated"
        ],
        request: "<csr-base64>",
        signerName: "kubernetes.io/kube-apiserver-client-kubelet",
        usages: [
            "digital signature",
            "client auth"
        ],
        username: "system:bootstrap:<name>"
    }
}

module.exports = {
    serverCSR,
    clientCSR,
}