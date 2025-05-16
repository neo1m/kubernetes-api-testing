const fs = require('fs')
const path = require('path')
const fetch = require('node-fetch')

// Базовый конфиг
const { outputDir, kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { csrTests } = require('#fixtures/common-test-data.js')

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

// Для данных spec.groups запрос на создание CSR отклоняется
const csrCreationForbiddenGroups = [
  {
    name: 'no required groups',
    groups: ['system:authenticated', 'system:nodes'],
  },
  {
    name: 'both groups are similar but incorrect',
    groups: ['system:bootstrapers', 'system:bootstrappers:kubeadm:default-node-tokenx'],
  },
  {
    name: 'one correct group and one similar group',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm'],
  },
  {
    name: 'duplicate of one group, missing the other',
    groups: ['system:bootstrappers', 'system:bootstrappers'],
  },
  {
    name: 'empty group list',
    groups: [],
  },
  {
    name: 'random groups',
    groups: ['devs', 'qa'],
  },
  {
    name: 'boolean as group name',
    groups: [true],
  },
  {
    name: 'object instead of string',
    groups: [{}],
  },
  {
    name: 'undefined in group list',
    groups: [undefined],
  },
  {
    name: 'only one incorrect group with typo (system:bootstrapers)',
    groups: ['system:bootstrapers'],
  },
  {
    name: 'only system:bootstrappers',
    groups: ['system:bootstrappers'],
  },
  {
    name: 'similar but invalid suffix',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-tokenx'],
  },
  {
    name: 'one valid, one random',
    groups: ['system:bootstrappers', 'dev-team'],
  },
  {
    name: 'both groups with case mismatch',
    groups: ['System:Bootstrapers', 'System:Bootstrappers:Kubeadm:Default-Node-Token'],
  },
  {
    name: 'duplicated system:bootstrappers',
    groups: ['system:bootstrappers', 'system:bootstrappers'],
  },
  {
    name: 'only unrelated system groups',
    groups: ['system:nodes', 'system:authenticated'],
  },
  {
    name: 'valid groups with swapped casing',
    groups: ['System:Bootstrappers', 'System:Bootstrappers:Kubeadm:Default-Node-Token'],
  },
  {
    name: 'only one group with correct structure but typo',
    groups: ['system:bootstrappers:kubeadm:default-nodetoken'],
  },
  {
    name: 'only one required group (system:bootstrappers) plus one extra (system:nodes)',
    groups: ['system:bootstrappers', 'system:nodes'],
  },
]

// Для данных spec.usages отклоняется созданный CSR
const csrDeniedGroups = [
  {
    name: 'only one required group (default-node-token)',
    groups: ['system:bootstrappers:kubeadm:default-node-token'],
  },
  {
    name: 'required groups plus one extra (extra:group)',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token', 'extra:group'],
  },
  {
    name: 'required groups plus one extra (system:nodes)',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token', 'system:nodes'],
  },
  {
    name: 'required groups plus one extra (system:masters)',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token', 'system:masters'],
  },
  {
    name: 'only one required group (system:bootstrappers:kubeadm:default-node-token) plus one extra (system:nodes)',
    groups: ['system:bootstrappers:kubeadm:default-node-token', 'system:nodes'],
  },
  {
    name: 'required groups with prefix',
    groups: ['kubeadm:system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token'],
  },
  {
    name: 'required groups with suffix',
    groups: ['system:bootstrappersx', 'system:bootstrappers:kubeadm:default-node-token'],
  },
  {
    name: 'only system:bootstrappers:kubeadm:default-node-token (missing first)',
    groups: ['system:bootstrappers:kubeadm:default-node-token'],
  },
  {
    name: 'groups in wrong order',
    groups: ['system:bootstrappers:kubeadm:default-node-token', 'system:bootstrapers'],
  },
  {
    name: 'extra group added',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token', 'extra:group'],
  },
  {
    name: 'similar but invalid prefix',
    groups: ['kubeadm:system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token'],
  },
  {
    name: 'extra controller group',
    groups: ['system:bootstrappers', 'system:bootstrappers:kubeadm:default-node-token', 'system:controller:job-controller'],
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
    ...csrCreationForbiddenGroups,
    ...csrDeniedGroups,
  ])
    ('[when Subject Organization in CSR equal "$name"]', ({ name, groups }) => {
      test('should prepare openssl files', async () => {
        // Преобразуем массив к формату для генерации CSR
        const formatGroups = groups.map((group) => `O=${group}`)

        // Subject
        const subject = [
          `CN=system:bootstrap:${nodeData.nodeName}`,
          ...formatGroups,
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
            usages: [
              "digital signature",
              "client auth"
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
