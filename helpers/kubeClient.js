const fs = require('fs')
const https = require('https')
const fetch = require('node-fetch')

// Адрес кластера (нужно переопределить во время тестирования на свои значения)
const kubeHost = require('child_process').execSync('minikube ip').toString().trim()
const kubePort = 8443
const baseURL = `https://${kubeHost}:${kubePort}`

// Сертификаты и ключи для настройки mTLS (нужно переопределить во время тестирования на свои значения)
const clientCertPath = `${process.env.HOME}/.minikube/profiles/minikube/client.crt`
const clientKeyPath = `${process.env.HOME}/.minikube/profiles/minikube/client.key`
const caCertPath = `${process.env.HOME}/.minikube/ca.crt`

// Настройка HTTPS агента с mTLS
const httpsAgent = new https.Agent({
  cert: fs.readFileSync(clientCertPath),
  key: fs.readFileSync(clientKeyPath),
  ca: fs.readFileSync(caCertPath),
  rejectUnauthorized: false,
})

// Универсальная обёртка для fetch для запросов в Kubernetes API
async function kubeFetch(path, options = {}) {
  const url = `${baseURL}${path}`
  return await fetch(url, { agent: httpsAgent, ...options })
}

module.exports = {
  kubeFetch,
  baseURL,
}
