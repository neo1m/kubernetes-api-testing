const fs = require('fs')
const path = require('path')
const https = require('https')
const fetch = require('node-fetch')

// Базовый конфиг
const { outputDir, kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { csrTests } = require('#fixtures/testData.js')

// Вспомогательные методы
const { createDirectoryIfNotExists, removeDirectory } = require('#helpers/common.js')

// Методы для работы с openssl
const {
  generateKeys,
  generateCSR,
  encodeCSRToBase64,
  createCnfFile,
  createExtFile,
  signCertificate,
} = require('#helpers/openssl.js')

// Пути к временным файлам
const testFiles = {
  privateKey: path.join(outputDir, 'client.key'),
  publicKey: path.join(outputDir, 'client.pub'),
  cnf: path.join(outputDir, 'csr_client.cnf'),
  csr: path.join(outputDir, 'client.csr'),
  ext: path.join(outputDir, 'v3.ext'),
  crt: path.join(outputDir, 'client.crt')
}

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const csrPath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.clientCSRName
const nodeData = csrTests.nodeData

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR denied]', () => {
  describe('[when Subject Common Name in CSR is missing]', () => {
    test('should prepare openssl files', async () => {
      // Subject
      const subject = [
        `O=system:nodes`,
      ].join(',')

      // Subject Alternative Names
      const sanList = [
        `IP:${nodeData.externalIP}`,
        `IP:${nodeData.internalIP}`,
      ]

      // Генерируем ключи, конфиги, CSR и сертификат для клиента
      generateKeys(testFiles.privateKey, testFiles.publicKey)
      createCnfFile(testFiles.cnf, subject, sanList)
      createExtFile(testFiles.ext, sanList)
      generateCSR(testFiles.privateKey, testFiles.csr, testFiles.cnf)
      signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey, testFiles.ext)

      // Проверки
      expect(fs.existsSync(testFiles.privateKey)).toBe(true)
      expect(fs.existsSync(testFiles.publicKey)).toBe(true)
      expect(fs.existsSync(testFiles.cnf)).toBe(true)
      expect(fs.existsSync(testFiles.ext)).toBe(true)
      expect(fs.existsSync(testFiles.csr)).toBe(true)
      expect(fs.existsSync(testFiles.crt)).toBe(true)
    })

    test('should not create CSR', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(testFiles.crt),
        key: fs.readFileSync(testFiles.privateKey),
        ca: fs.readFileSync(kubeAuthFiles.caCrt),
        rejectUnauthorized: false,
      })

      // CSR в формате base64
      const base64CSR = encodeCSRToBase64(testFiles.csr)

      // API тело запроса
      const certificateSigningRequest = {
        apiVersion: "certificates.k8s.io/v1",
        kind: "CertificateSigningRequest",
        metadata: {
          name: csrName
        },
        spec: {
          request: base64CSR,
          signerName: "kubernetes.io/kube-apiserver-client-kubelet",
          usages: [
            "digital signature",
            "client auth"
          ],
        }
      }

      // Запрос
      const res = await fetch(`${baseURL}${csrPath}`, {
        method: 'POST',
        body: JSON.stringify(certificateSigningRequest),
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
      expect(res.status).toBe(401)
      expect(body.status).toBe('Failure')
    })
  })

  describe('[when Subject Common Name in CSR contains random characters]', () => {
    test('should prepare openssl files', async () => {
      // Subject
      const subject = [
        `CN=qwerty123`,
        `O=system:nodes`,
      ].join(',')

      // Subject Alternative Names
      const sanList = [
        `IP:${nodeData.externalIP}`,
        `IP:${nodeData.internalIP}`,
      ]

      // Генерируем ключи, конфиги, CSR и сертификат для клиента
      generateKeys(testFiles.privateKey, testFiles.publicKey)
      createCnfFile(testFiles.cnf, subject, sanList)
      createExtFile(testFiles.ext, sanList)
      generateCSR(testFiles.privateKey, testFiles.csr, testFiles.cnf)
      signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey, testFiles.ext)

      // Проверки
      expect(fs.existsSync(testFiles.privateKey)).toBe(true)
      expect(fs.existsSync(testFiles.publicKey)).toBe(true)
      expect(fs.existsSync(testFiles.cnf)).toBe(true)
      expect(fs.existsSync(testFiles.ext)).toBe(true)
      expect(fs.existsSync(testFiles.csr)).toBe(true)
      expect(fs.existsSync(testFiles.crt)).toBe(true)
    })

    test('should not create CSR', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(testFiles.crt),
        key: fs.readFileSync(testFiles.privateKey),
        ca: fs.readFileSync(kubeAuthFiles.caCrt),
        rejectUnauthorized: false,
      })

      // CSR в формате base64
      const base64CSR = encodeCSRToBase64(testFiles.csr)

      // API тело запроса
      const certificateSigningRequest = {
        apiVersion: "certificates.k8s.io/v1",
        kind: "CertificateSigningRequest",
        metadata: {
          name: csrName
        },
        spec: {
          request: base64CSR,
          signerName: "kubernetes.io/kube-apiserver-client-kubelet",
          usages: [
            "digital signature",
            "client auth"
          ],
        }
      }

      // Запрос
      const res = await fetch(`${baseURL}${csrPath}`, {
        method: 'POST',
        body: JSON.stringify(certificateSigningRequest),
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
      expect(res.status).toBe(403)
      expect(body.status).toBe('Failure')
    })
  })

  describe('[when Subject Common Name in CSR contains equal "system:anonymous"]', () => {
    test('should prepare openssl files', async () => {
      // Subject
      const subject = [
        `CN=system:anonymous`,
        `O=system:nodes`,
      ].join(',')

      // Subject Alternative Names
      const sanList = [
        `IP:${nodeData.externalIP}`,
        `IP:${nodeData.internalIP}`,
      ]

      // Генерируем ключи, конфиги, CSR и сертификат для клиента
      generateKeys(testFiles.privateKey, testFiles.publicKey)
      createCnfFile(testFiles.cnf, subject, sanList)
      createExtFile(testFiles.ext, sanList)
      generateCSR(testFiles.privateKey, testFiles.csr, testFiles.cnf)
      signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey, testFiles.ext)

      // Проверки
      expect(fs.existsSync(testFiles.privateKey)).toBe(true)
      expect(fs.existsSync(testFiles.publicKey)).toBe(true)
      expect(fs.existsSync(testFiles.cnf)).toBe(true)
      expect(fs.existsSync(testFiles.ext)).toBe(true)
      expect(fs.existsSync(testFiles.csr)).toBe(true)
      expect(fs.existsSync(testFiles.crt)).toBe(true)
    })

    test('should create CSR', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(testFiles.crt),
        key: fs.readFileSync(testFiles.privateKey),
        ca: fs.readFileSync(kubeAuthFiles.caCrt),
        rejectUnauthorized: false,
      })

      // CSR в формате base64
      const base64CSR = encodeCSRToBase64(testFiles.csr)

      // API тело запроса
      const certificateSigningRequest = {
        apiVersion: "certificates.k8s.io/v1",
        kind: "CertificateSigningRequest",
        metadata: {
          name: csrName
        },
        spec: {
          request: base64CSR,
          signerName: "kubernetes.io/kube-apiserver-client-kubelet",
          usages: [
            "digital signature",
            "client auth"
          ],
        }
      }

      // Запрос
      const res = await fetch(`${baseURL}${csrPath}`, {
        method: 'POST',
        body: JSON.stringify(certificateSigningRequest),
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
      expect(res.status).toBe(403)
      expect(body.status).toBe('Failure')
    })
  })

  describe('[when Subject Common Name in CSR contains equal "system:admin"]', () => {
    test('should prepare openssl files', async () => {
      // Subject
      const subject = [
        `CN=system:admin`,
        `O=system:nodes`,
      ].join(',')

      // Subject Alternative Names
      const sanList = [
        `IP:${nodeData.externalIP}`,
        `IP:${nodeData.internalIP}`,
      ]

      // Генерируем ключи, конфиги, CSR и сертификат для клиента
      generateKeys(testFiles.privateKey, testFiles.publicKey)
      createCnfFile(testFiles.cnf, subject, sanList)
      createExtFile(testFiles.ext, sanList)
      generateCSR(testFiles.privateKey, testFiles.csr, testFiles.cnf)
      signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey, testFiles.ext)

      // Проверки
      expect(fs.existsSync(testFiles.privateKey)).toBe(true)
      expect(fs.existsSync(testFiles.publicKey)).toBe(true)
      expect(fs.existsSync(testFiles.cnf)).toBe(true)
      expect(fs.existsSync(testFiles.ext)).toBe(true)
      expect(fs.existsSync(testFiles.csr)).toBe(true)
      expect(fs.existsSync(testFiles.crt)).toBe(true)
    })

    test('should create CSR', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = new https.Agent({
        cert: fs.readFileSync(testFiles.crt),
        key: fs.readFileSync(testFiles.privateKey),
        ca: fs.readFileSync(kubeAuthFiles.caCrt),
        rejectUnauthorized: false,
      })

      // CSR в формате base64
      const base64CSR = encodeCSRToBase64(testFiles.csr)

      // API тело запроса
      const certificateSigningRequest = {
        apiVersion: "certificates.k8s.io/v1",
        kind: "CertificateSigningRequest",
        metadata: {
          name: csrName
        },
        spec: {
          request: base64CSR,
          signerName: "kubernetes.io/kube-apiserver-client-kubelet",
          usages: [
            "digital signature",
            "client auth"
          ],
        }
      }

      // Запрос
      const res = await fetch(`${baseURL}${csrPath}`, {
        method: 'POST',
        body: JSON.stringify(certificateSigningRequest),
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
      expect(res.status).toBe(403)
      expect(body.status).toBe('Failure')
    })
  })
})
