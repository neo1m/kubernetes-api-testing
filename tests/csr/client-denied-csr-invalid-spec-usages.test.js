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
  signCertificate,
} = require('#helpers/openssl.js')

// Пути к временным файлам
const testFiles = {
  privateKey: path.join(outputDir, 'client.key'),
  publicKey: path.join(outputDir, 'client.pub'),
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

// Для данных spec.groups запрещено создание CSR
const csrCreationForbiddenUsages = [
  {
    name: 'empty usages array',
    usages: [],
  },
]

// Для данных spec.usages отклоняется созданный CSR
const csrDeniedUsages = [
  {
    name: 'only digital signature (missing client auth)',
    usages: ['digital signature'],
  },
  {
    name: 'only client auth (missing digital signature)',
    usages: ['client auth'],
  },
  {
    name: 'usages in reverse order',
    usages: ['client auth', 'digital signature'],
  },
  {
    name: 'additional usage: key encipherment',
    usages: ['digital signature', 'client auth', 'key encipherment'],
  },
  {
    name: 'additional usage: server auth',
    usages: ['digital signature', 'client auth', 'server auth'],
  },
  {
    name: 'missing both required usages',
    usages: ['server auth', 'key encipherment'],
  },
  {
    name: 'only one usage: server auth',
    usages: ['server auth'],
  },
  {
    name: 'empty usages array',
    usages: [],
  },
  {
    name: 'duplicate digital signature only',
    usages: ['digital signature', 'digital signature'],
  },
  {
    name: 'duplicate client auth only',
    usages: ['client auth', 'client auth'],
  },
  {
    name: 'both usages as one string',
    usages: ['digital signature client auth'],
  },
  {
    name: 'case mismatch in usages',
    usages: ['Digital Signature', 'Client Auth'],
  },
  {
    name: 'typo in digital signature',
    usages: ['digital signatur', 'client auth'],
  },
  {
    name: 'typo in client auth',
    usages: ['digital signature', 'client authentication'],
  },
  {
    name: 'wrong casing in one usage',
    usages: ['digital signature', 'Client auth'],
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR denied]', () => {
  describe.each(csrCreationForbiddenUsages)
    ('[when spec.usages equal "$name"]', ({ name, usages }) => {
      test('should prepare openssl files', async () => {
        // Subject
        const subject = [
          `CN=system:bootstrap:${nodeData.nodeName}`,
          `O=system:bootstrappers`,
          `O=system:bootstrappers:kubeadm:default-node-token`,
        ]

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        generateCSR(testFiles.privateKey, testFiles.csr, subject)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
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
            usages: usages,
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

        // Проверки
        expect(res.status).toBe(403)
        expect(body.status).toBe('Failure')
        expect(body.reason).toBe('Forbidden')
      })
    })

  describe.each(csrDeniedUsages)
    ('[when spec.usages equal "$name"]', ({ name, usages }) => {
      test('should prepare openssl files', async () => {
        // Subject
        const subject = [
          `CN=system:bootstrap:${nodeData.nodeName}`,
          `O=system:bootstrappers`,
          `O=system:bootstrappers:kubeadm:default-node-token`,
        ]

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        generateCSR(testFiles.privateKey, testFiles.csr, subject)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
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
            usages: usages,
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

        // Проверки
        expect(res.status).toBe(201)
        expect(body.metadata.name).toBe(csrName)
      })

      test('should deny CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(testFiles.crt),
          key: fs.readFileSync(testFiles.privateKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

        // Максимальное время ожидания
        const maxRetryTime = 60000
        const retryInterval = 5000
        const startTime = Date.now()
        const expectedStatus = 'Denied'

        // Цикл запросов
        while (Date.now() - startTime < maxRetryTime) {
          const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
            method: 'GET',
            agent: httpsAgent,
          })

          const body = await res.json()
          const lastStatus = body.status?.conditions?.[0]?.type || ''

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
        // Настройка HTTPS агента с mTLS (для удаления CSR после тестов используем доступы от основного клиента)
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(kubeAuthFiles.clientCert),
          key: fs.readFileSync(kubeAuthFiles.clientKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

        // Запрос на удаление
        const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
          method: 'DELETE',
          agent: httpsAgent,
        })
        const body = await res.json()

        // Проверки
        expect(res.status).toBe(200)
        expect(body.status).toBe('Success')
        expect(body.details.name).toBe(csrName)
      })
    })
})
