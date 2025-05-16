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
const csrName = csrTests.serverCSRName
const nodeData = csrTests.nodeData

// Для данных Subject Common Name отклоняется созданный CSR
const csrDeniedSubject = [
  {
    name: 'additional OU field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'OU=extra-team',
    ],
  },
  {
    name: 'additional ST field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'ST=California',
    ],
  },
  {
    name: 'additional L field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'L=San Francisco',
    ],
  },
  {
    name: 'additional C field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'C=US',
    ],
  },
  {
    name: 'additional emailAddress field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'emailAddress=node@example.com',
    ],
  },
  {
    name: 'additional DC field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'DC=cluster',
    ],
  },
  {
    name: 'additional STREET field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'STREET=NodeStreet42',
    ],
  },
  {
    name: 'additional SERIALNUMBER field',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'SERIALNUMBER=123456',
    ],
  },
  {
    name: 'valid CN and O with ST and L',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'ST=California',
      'L=San Francisco',
    ],
  },
  {
    name: 'valid CN and O with C and emailAddress',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'C=US',
      'emailAddress=node@example.com',
    ],
  },
  {
    name: 'valid CN and O with UID and DC',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'UID=1001',
      'DC=example',
    ],
  },
  {
    name: 'valid CN and O with all invalid fields',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'O=system:nodes',
      'OU=ops',
      'ST=Texas',
      'L=Austin',
      'C=US',
      'emailAddress=dev@kube.local',
      'UID=dev-1',
      'DC=cluster',
    ],
  },
  {
    name: 'valid CN with all invalid fields',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'OU=ops',
      'ST=Texas',
      'L=Austin',
      'C=US',
      'emailAddress=dev@kube.local',
      'UID=dev-1',
      'DC=cluster',
    ],
  },
  {
    name: 'valid O with all invalid fields',
    subject: [
      'O=system:nodes',
      'OU=ops',
      'ST=Texas',
      'L=Austin',
      'C=US',
      'emailAddress=dev@kube.local',
      'UID=dev-1',
      'DC=cluster',
    ],
  },
  {
    name: 'only OU and ST',
    subject: [
      'OU=dev',
      'ST=New York',
    ],
  },
  {
    name: 'only L, C, and emailAddress',
    subject: [
      'L=Berlin',
      'C=DE',
      'emailAddress=test@wrong.local',
    ],
  },
  {
    name: 'only UID and DC',
    subject: [
      'UID=777',
      'DC=internal',
    ],
  },
  {
    name: 'valid CN and O with repeated CN and O',
    subject: [
      `CN=system:node:${nodeData.nodeName}`,
      'CN=extra',
      'O=system:nodes',
      'O=wronggroup',
    ],
  },
]

beforeAll(() => {
  createDirectoryIfNotExists(outputDir)
})

afterAll(() => {
  removeDirectory(outputDir)
})

describe('[CSR denied]', () => {
  describe.each([
    ...csrDeniedSubject,
  ])
    ('[when Subject in CSR equal "$name"]', ({ name, subject }) => {
      test('should prepare openssl files', async () => {
        // Subject
        const subjectList = subject

        // Subject Alternative Names
        const sanList = [
          `IP:${nodeData.externalIP}`,
          `IP:${nodeData.internalIP}`,
        ]

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
            usages: [
              "digital signature",
              "server auth",
            ],
          }
        }

        // Запрос на создание CSR
        const res = await fetch(`${baseURL}${csrPath}`, {
          method: 'POST',
          body: JSON.stringify(certificateSigningRequest),
          headers: { 'Content-Type': 'application/json' },
          agent: httpsAgent,
        })

        // Возможные статусы ответа
        const expectedStatus = [
          201, // CSR успешно создан (Created)
          401, // CSR не создан (Unauthorized)
          403, // CSR не создан (Forbidden)
          422, // CSR не создан (Unprocessable Entity)
        ]
        console.log(`[CSR CREATE] Received status "${res.status}"`)

        // Проверки
        expect(expectedStatus).toContain(res.status)
      })

      test('should deny CSR', async () => {
        // Настройка HTTPS агента с mTLS
        const httpsAgent = createHttpsAgent(testFiles.crt, testFiles.privateKey, kubeAuthFiles.caCrt)

        // Максимальное время ожидания
        const maxRetryTime = 60000
        const retryInterval = 5000
        const expectedStatus = 'Denied'
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
            console.log(`[CSR CHECK] Non-200 status "${res.status}" - stopping watch`)
            return
          }

          // CSR существует, статус соответствует искомому
          if (lastStatus === expectedStatus) {
            console.log(`[CSR CHECK] Resource has expected status "${expectedStatus}" - stopping watch`)
            expect(res.status).toBe(200)
            expect(body.metadata.name).toBe(csrName)
            expect(lastStatus).toBe(expectedStatus)
            return
          }

          // CSR существует, но статус не соответствует искомому
          if (lastStatus && lastStatus !== expectedStatus) {
            console.log(`[CSR CHECK] Unexpected CSR status "${lastStatus}" - throwing error`)
            throw new Error(`Unexpected CSR status "${lastStatus}"`)
          }

          // CSR существует, но статус ещё не определён — продолжаем ждать
          console.log(`[CSR CHECK] Status not yet set - continuing to wait`)
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

        // Возможные статусы ответа
        const expectedStatus = [
          200, // CSR успешно удален
          403, // CSR не найден (нет доступа)
          404, // CSR не найден (не удалось создать ранее)
        ]
        console.log(`[CSR DELETE] Received status "${res.status}"`)

        // Проверки
        expect(expectedStatus).toContain(res.status)
      })
    })
})
