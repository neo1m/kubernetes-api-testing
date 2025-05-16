const path = require('path')
const os = require('os')

const kubeHost = require('child_process').execSync('minikube ip').toString().trim()
const kubePort = 8443

module.exports = {
  // директория для временных файлов во время тестов
  outputDir: path.resolve(__dirname, 'fixtures', 'tmp'),
  // ключи и сертификаты для запросов через mTLS
  kubeAuthFiles: {
    caCrt: path.join(os.homedir(), '.minikube/ca.crt'),
    caKey: path.join(os.homedir(), '.minikube/ca.key'),
    clientCert: path.join(os.homedir(), '.minikube/profiles/minikube/client.crt'),
    clientKey: path.join(os.homedir(), '.minikube/profiles/minikube/client.key'),
  },
  // общие данные для kubernetes API
  kube: {
    host: kubeHost,
    port: kubePort,
  }
}
