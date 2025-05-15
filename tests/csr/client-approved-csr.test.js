const fs = require('fs')
const path = require('path')
const fetch = require('node-fetch')

// Базовый конфиг
const { outputDir, kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { csrTests } = require('#fixtures/testData.js')

// Вспомогательные методы
const {
  createDirectoryIfNotExists,
  removeDirectory,
  createHttpsAgent,
} = require('#helpers/common.js')

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

// Валидные комбинации данных для одобрения CSR
const validData = [
  {
    name: 'correct subject (CN, O) and usages',
    subject: [
      `CN=system:bootstrap:${nodeData.nodeName}`,
      `O=system:bootstrappers`,
      `O=system:bootstrappers:kubeadm:default-node-token`,
    ],
    usages: ["digital signature", "client auth"]
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR approved]', () => {
  describe.each([
    ...validData,
  ])
    ('[when CSR data and API request equal "$name"]', ({ name, subject, usages }) => {
      test('should prepare openssl files', async () => {
        // Subject
        const subjectList = subject

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        generateCSR(testFiles.privateKey, testFiles.csr, subjectList)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
        expect(fs.existsSync(testFiles.csr)).toBe(true)
        expect(fs.existsSync(testFiles.crt)).toBe(true)
      })

      test('should create CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = createHttpsAgent(testFiles.crt, testFiles.privateKey, kubeAuthFiles.caCrt)

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

        // Запрос на создание CSR
        const res = await fetch(`${baseURL}${csrPath}`, {
          method: 'POST',
          body: JSON.stringify(certificateSigningRequest),
          headers: { 'Content-Type': 'application/json' },
          agent: httpsAgent,
        })
        const body = await res.json()
        console.log(`[CSR CREATE] Received status "${res.status}"`)

        // Проверки
        expect(res.status).toBe(201)
        expect(body.metadata.name).toBe(csrName)
      })

      test('should approve CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = createHttpsAgent(testFiles.crt, testFiles.privateKey, kubeAuthFiles.caCrt)

        // Максимальное время ожидания
        const maxRetryTime = 60000
        const retryInterval = 5000
        const expectedStatus = 'Approved'
        const startTime = Date.now()

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

        // Если дошли сюда - значит искомый статус CSR не получен за отведённое время
        throw new Error(`Timeout waiting for CSR "${csrName}" to have status "${expectedStatus}" within ${maxRetryTime / 1000} seconds`)
      })

      test('should delete CSR', async () => {
        // Настройка HTTPS агента с mTLS (для удаления CSR после тестов используем доступы от основного клиента)
        const httpsAgent = createHttpsAgent(kubeAuthFiles.clientCert, kubeAuthFiles.clientKey, kubeAuthFiles.caCrt)

        // Запрос на удаление CSR
        const res = await fetch(`${baseURL}${csrPath}/${csrName}`, {
          method: 'DELETE',
          agent: httpsAgent,
        })
        const body = await res.json()
        console.log(`[CSR DELETE] Received status "${res.status}"`)

        // Проверки
        expect(res.status).toBe(200)
        expect(body.status).toBe('Success')
        expect(body.details.name).toBe(csrName)
      })
    })
})
