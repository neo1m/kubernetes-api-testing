const path = require('path')
const os = require('os')

module.exports = {
  outputDir: path.resolve(__dirname, 'fixtures', 'tmp'),
  kubeAuthFiles: {
    caCrt: path.join(os.homedir(), '.minikube/ca.crt'),
    caKey: path.join(os.homedir(), '.minikube/ca.key'),
    clientCert: path.join(os.homedir(), '.minikube/profiles/minikube/client.crt'),
    clientKey: path.join(os.homedir(), '.minikube/profiles/minikube/client.key'),
  },
  kube: {
    host: require('child_process').execSync('minikube ip').toString().trim(),
    port: 8443,
    csrPath: '/apis/certificates.k8s.io/v1/certificatesigningrequests',
  }
}
