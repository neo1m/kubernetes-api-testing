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

// При наличии некорректного SAN отклоняется CSR
const csrDeniedSAN = [
  {
    name: 'san with ip and dns name',
    san: [`IP:${nodeData.internalIP}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with full combo of ip and dns',
    san: [`IP:${nodeData.externalIP}`, `IP:${nodeData.internalIP}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with external ip',
    san: [`IP:${nodeData.externalIP}`],
  },
  {
    name: 'san with internal ip',
    san: [`IP:${nodeData.internalIP}`],
  },
  {
    name: 'san with dns name',
    san: [`DNS:${nodeData.nodeName}`],
  },
  {
    name: 'valid ips plus localhost',
    san: [`IP:${nodeData.externalIP}`, `IP:${nodeData.internalIP}`, 'IP:127.0.0.1'],
  },
  {
    name: 'san with duplicate dns entries',
    san: [`DNS:${nodeData.nodeName}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'san with duplicate external ip entries',
    san: [`DNS:${nodeData.externalIP}`, `DNS:${nodeData.externalIP}`],
  },
  {
    name: 'san with duplicate internal ip entries',
    san: [`DNS:${nodeData.internalIP}`, `DNS:${nodeData.internalIP}`],
  },
  {
    name: 'san with internal ip and duplicate external ip entries',
    san: [`DNS:${nodeData.internalIP}`, `DNS:${nodeData.externalIP}`, `DNS:${nodeData.externalIP}`],
  },
  {
    name: 'san with external ip and duplicate internal ip entries',
    san: [`DNS:${nodeData.externalIP}`, `DNS:${nodeData.internalIP}`, `DNS:${nodeData.internalIP}`],
  },
  {
    name: 'san with external ip, duplicate internal ip entries and dns',
    san: [`DNS:${nodeData.externalIP}`, `DNS:${nodeData.internalIP}`, `DNS:${nodeData.internalIP}`, `DNS:${nodeData.nodeName}`],
  },
  {
    name: 'uri instead of ip',
    san: ['URI:https://node.local', `IP:${nodeData.internalIP}`],
  },
  {
    name: 'dns instead of ip',
    san: [`DNS:${nodeData.nodeName}`, `DNS:internal.local`],
  },
  {
    name: 'san with localhost ip',
    san: ['IP:127.0.0.1'],
  },
  {
    name: 'san with localhost dns',
    san: ['DNS:localhost'],
  },
  {
    name: 'san with unusual domain',
    san: ['DNS:node.localdomain.local'],
  },
  {
    name: 'san with internal only dns',
    san: ['DNS:internal.cluster.local'],
  },
  {
    name: 'san with ipv6 localhost',
    san: ['IP:::1'],
  },
  {
    name: 'san with ipv6 example',
    san: ['IP:fe80::1ff:fe23:4567:890a'],
  },
  {
    name: 'san with space in dns',
    san: ['DNS:node name.local'],
  },
  {
    name: 'san with email address',
    san: ['email:user@example.com'],
  },
  {
    name: 'san with URI',
    san: ['URI:https://node.example.com'],
  },
  {
    name: 'san with RID',
    san: ['RID:1.2.3.4.5'],
  },
  {
    name: 'san with otherName',
    san: ['otherName:1.2.3.4;UTF8:user'],
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
      ...csrDeniedSAN,
    ])
    ('[when Subject Alternative Names equal "$name"]', ({ name, san }) => {
      test('should prepare openssl files', async () => {
        // Subject
        const subject = [
          `CN=system:node:${nodeData.nodeName}`,
          `O=system:nodes`,
        ]

        // Subject Alternative Names
        const sanList = san

        // Генерируем ключи, конфиги, CSR и сертификат для клиента
        generateKeys(testFiles.privateKey, testFiles.publicKey)
        createExtFile(testFiles.ext, sanList)
        generateCSR(testFiles.privateKey, testFiles.csr, subject, sanList)
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
            signerName: "kubernetes.io/kubelet-serving",
            usages: [
              "digital signature",
              "server auth"
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
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(testFiles.crt),
          key: fs.readFileSync(testFiles.privateKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

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
            throw new Error(`Unsupported CSR status "${lastStatus}"`)
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
        const httpsAgent = new https.Agent({
          cert: fs.readFileSync(kubeAuthFiles.clientCert),
          key: fs.readFileSync(kubeAuthFiles.clientKey),
          ca: fs.readFileSync(kubeAuthFiles.caCrt),
          rejectUnauthorized: false,
        })

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
