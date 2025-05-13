const fs = require('fs')
const path = require('path')
const https = require('https')
const fetch = require('node-fetch')

// Тестовые данные
const { csrTests } = require('#fixtures/testData.js')

// Вспомогательные методы
const {
  createDirectoryIfNotExists,
  removeDirectory,
} = require('#helpers/common.js')

// Методы для работы с openssl
const {
  generateKeys,
  generateCSR,
  encodeCSRToBase64,
  createCnfFile,
  createExtFile,
  signCertificate,
} = require('#helpers/openssl.js')

// Директория для временного хранения файлов
const outputDir = path.resolve(__dirname, '..', '..', 'fixtures', 'tmp')

// Временные openssl файлы
const privateKeyPath = path.join(outputDir, 'client.key')
const publicKeyPath = path.join(outputDir, 'client.pub')
const cnfPath = path.join(outputDir, 'csr_client.cnf')
const clientCSRPath = path.join(outputDir, 'client.csr')
const extPath = path.join(outputDir, 'v3.ext')
const clientCrtPath = path.join(outputDir, 'client.crt')

// Корневой сертификат
const caCrtPath = path.join(process.env.HOME, '.minikube/ca.crt')
const caKeyPath = path.join(process.env.HOME, '.minikube/ca.key')

// Сертификат и ключ для minikube пользователя
const minikubeCertPath = path.join(process.env.HOME, '.minikube/profiles/minikube/client.crt')
const minikubeKeyPath = path.join(process.env.HOME, '.minikube/profiles/minikube/client.key')

// Адрес кластера
const kubeHost = require('child_process').execSync('minikube ip').toString().trim()
const kubePort = 8443
const baseURL = `https://${kubeHost}:${kubePort}`
const csrBasePath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.clientCSRName
const nodeData = csrTests.nodeData
const subject = 'CN=system:node:csr-tests-kuber-node,O=system:nodes'
const sanList = ['DNS:example.com', 'DNS:www.example.com']

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR approved]', () => {
  describe('[when CSR data and API request are valid]', () => {
    test('should prepare openssl files', async () => {
      generateKeys(privateKeyPath, publicKeyPath)
      createCnfFile(cnfPath, subject, sanList)
      createExtFile(extPath, sanList)
      generateCSR(privateKeyPath, clientCSRPath, cnfPath)
      signCertificate(clientCSRPath, clientCrtPath, caCrtPath, caKeyPath, extPath)
    })

    test('should create CSR', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(clientCrtPath),
        key: fs.readFileSync(privateKeyPath),
        ca: fs.readFileSync(caCrtPath),
        rejectUnauthorized: false,
      })

      // CSR в формате base64
      const base64CS = encodeCSRToBase64(clientCSRPath)

      // API
      const clientCSR = {
        apiVersion: "certificates.k8s.io/v1",
        kind: "CertificateSigningRequest",
        metadata: {
          name: csrName
        },
        spec: {
          groups: [
            "system:bootstrappers",
            "system:bootstrappers:kubeadm:default-node-token",
            "system:authenticated"
          ],
          request: base64CS,
          signerName: "kubernetes.io/kube-apiserver-client-kubelet",
          usages: [
            "digital signature",
            "client auth"
          ],
          username: `system:bootstrap:${nodeData.nodeName}`
        }
      }

      // Запрос
      const res = await fetch(`${baseURL}${csrBasePath}`, {
        method: 'POST',
        body: JSON.stringify(clientCSR),
        headers: { 'Content-Type': 'application/json' },
        agent: httpsAgent,
      })
      const body = await res.json()

      // Результат
      console.log('\nres.status:')
      console.log(res.status)
      console.log('\nbody:')
      console.log(body)

      // Проверки
      expect(res.status).toBe(201)
      expect(body.metadata.name).toBe(csrName)
    })

    test('should approve CSR', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(clientCrtPath),
        key: fs.readFileSync(privateKeyPath),
        ca: fs.readFileSync(caCrtPath),
        rejectUnauthorized: false,
      })

      // Максимальное время ожидания
      const maxRetryTime = 60000
      const retryInterval = 5000
      const startTime = Date.now()
      let expectedStatus = 'Approved'
      let lastStatus = ''
      let body

      // Цикл запросов
      while (Date.now() - startTime < maxRetryTime) {
        const res = await fetch(`${baseURL}${csrBasePath}/${csrName}`, {
          method: 'GET',
          agent: httpsAgent,
        })

        body = await res.json()
        lastStatus = body.status?.conditions?.[0]?.type || ''

        if (res.status === 200 && lastStatus === expectedStatus) {
          // Успешный случай
          expect(res.status).toBe(200)
          expect(body.metadata.name).toBe(csrName)
          expect(body.status.conditions[0].type).toBe(expectedStatus)
          return
        }

        // Ждём перед следующим запросом
        await new Promise(resolve => setTimeout(resolve, retryInterval))
      }

      // Если дошли сюда - значит Approved не получен за отведённое время
      throw new Error(`Timeout waiting for CSR "${csrName}" to have status "${expectedStatus}" within ${maxRetryTime / 1000} seconds`)
    })

    test('should delete CSR', async () => {
      // Настройка HTTPS агента с mTLS
      // Для удаления CSR после тестов используем доступы от основного клиента minikube
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(minikubeCertPath),
        key: fs.readFileSync(minikubeKeyPath),
        ca: fs.readFileSync(caCrtPath),
        rejectUnauthorized: false,
      })

      // Запрос на удаление
      const res = await fetch(`${baseURL}${csrBasePath}/${csrName}`, {
        method: 'DELETE',
        agent: httpsAgent,
      })
      const body = await res.json()

      // Результат
      console.log('\nres.status:')
      console.log(res.status)
      console.log('\nbody:')
      console.log(body)

      // Проверки
      expect(res.status).toBe(200)
      expect(body.status).toBe('Success')
      expect(body.details.name).toBe(csrName)
    })
  })
})
