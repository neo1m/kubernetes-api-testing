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
  createExtFile,
  signCertificate,
} = require('#helpers/openssl.js')

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const csrPath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

// Тестовые данные
const csrName = csrTests.serverCSRName
const nodeData = csrTests.nodeData

// Валидные комбинации данных для одобрения CSR
const csrCombinations = [
  {
    name: 'Subject: CN first, SAN with external and internal IPs, Usages: digital signature first',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      `O=system:nodes`,
    ],
    san: [
      `IP:${nodeData.externalIP}`,
      `IP:${nodeData.internalIP}`,
    ],
    usages: [
      "digital signature",
      "server auth",
    ]
  },
  {
    name: 'Subject: O first, SAN with external and internal IPs, Usages: digital signature first',
    subject: [
      `O=system:nodes`,
      `CN=system:node:${nodeData.nodeName}`,
    ],
    san: [
      `IP:${nodeData.externalIP}`,
      `IP:${nodeData.internalIP}`,
    ],
    usages: [
      "digital signature",
      "server auth",
    ]
  },
  {
    name: 'Subject: O first, SAN with external and internal IPs, Usages: server auth first',
    subject: [
      `O=system:nodes`,
      `CN=system:node:${nodeData.nodeName}`,
    ],
    san: [
      `IP:${nodeData.externalIP}`,
      `IP:${nodeData.internalIP}`,
    ],
    usages: [
      "server auth",
      "digital signature",
    ]
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

describe('[CSR approved]', () => {
  describe.each([
    ...csrCombinations,
  ])
    ('[when CSR data and API request equal "$name"]', ({ name, subject, san, usages }) => {
      // Директория и файлы для каждого тестового набора данных
      const fileName = path.basename(__filename, path.extname(__filename))
      const testCaseName = name.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
      const testCaseDir = path.join(outputDir, fileName, testCaseName)
      const testFiles = {
        privateKey: path.join(testCaseDir, 'client.key'),
        publicKey: path.join(testCaseDir, 'client.pub'),
        csr: path.join(testCaseDir, 'client.csr'),
        ext: path.join(testCaseDir, 'v3.ext'),
        crt: path.join(testCaseDir, 'client.crt'),
      }

      beforeAll(() => {
        // Создаем отдельную директорию для каждого тестового набора данных
        createDirectoryIfNotExists(testCaseDir)
      })

      test('should prepare openssl files', async () => {
        // Subject
        const subjectList = subject

        // Subject Alternative Names
        const sanList = san

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        createExtFile(testFiles.ext, sanList)
        generateCSR(testFiles.privateKey, testFiles.csr, subjectList, sanList)
        signCertificate(testFiles.csr, testFiles.crt, kubeAuthFiles.caCrt, kubeAuthFiles.caKey, testFiles.ext)

        // Проверки
        expect(fs.existsSync(testFiles.privateKey)).toBe(true)
        expect(fs.existsSync(testFiles.publicKey)).toBe(true)
        expect(fs.existsSync(testFiles.ext)).toBe(true)
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
            signerName: "kubernetes.io/kubelet-serving",
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

          // CSR отсутствует или нет доступа (не удалось создать ранее)
          if (res.status !== 200) {
            console.log(`[CSR CHECK] Non-200 status "${res.status}" - throwing error`)
            throw new Error(`Unexpected status "${res.status}"`)
          }

          // CSR существует, но статус не соответствует искомому
          if (lastStatus && lastStatus !== expectedStatus) {
            console.log(`[CSR CHECK] Unexpected CSR status "${lastStatus}" - throwing error`)
            throw new Error(`Unexpected CSR status "${lastStatus}"`)
          }

          // CSR существует, статус соответствует искомому
          if (lastStatus === expectedStatus) {
            console.log(`[CSR CHECK] Resource has expected status "${expectedStatus}" - stopping watch`)
            expect(res.status).toBe(200)
            expect(body.metadata.name).toBe(csrName)
            expect(lastStatus).toBe(expectedStatus)
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
