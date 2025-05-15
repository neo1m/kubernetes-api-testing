const fetch = require('node-fetch')

// Базовый конфиг
const { kubeAuthFiles, kube } = require('#root/config.js')

// Тестовые данные
const { nodeTests } = require('#fixtures/testData.js')

// Вспомогательные методы
const {
  createHttpsAgent,
} = require('#helpers/common.js')

// Адрес API
const baseURL = `https://${kube.host}:${kube.port}`
const nodePath = '/api/v1/nodes'

// Тестовые данные
const { nodeName } = nodeTests.nodeData

describe('[base operations with Node]', () => {
  describe('[when managing node lifecycle]', () => {
    test('should create node', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = createHttpsAgent(kubeAuthFiles.clientCert, kubeAuthFiles.clientKey, kubeAuthFiles.caCrt)

      // API тело запроса
      const nodeManifest = {
        apiVersion: "v1",
        kind: "Node",
        metadata: {
          name: `${nodeName}`
        },
      }

      // Запрос на создание Node
      const res = await fetch(`${baseURL}${nodePath}`, {
        method: 'POST',
        body: JSON.stringify(nodeManifest),
        headers: { 'Content-Type': 'application/json' },
        agent: httpsAgent,
      })

      console.log(`[NODE CREATE] Received status "${res.status}"`)

      // Проверки
      expect(res.status).toBe(201)
    })

    test('should have valid internal and external IP addresses', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = createHttpsAgent(kubeAuthFiles.clientCert, kubeAuthFiles.clientKey, kubeAuthFiles.caCrt)

      // Максимальное время ожидания
      const maxRetryTime = 60000
      const retryInterval = 5000
      const startTime = Date.now()

      // Цикл запросов
      while (Date.now() - startTime < maxRetryTime) {
        const res = await fetch(`${baseURL}${nodePath}/${nodeName}`, {
          method: 'GET',
          agent: httpsAgent,
        })

        const body = await res.json()
        const addresses = body?.status?.addresses || []
        const externalIP = addresses.find(a => a.type === 'ExternalIP')?.address
        const internalIP = addresses.find(a => a.type === 'InternalIP')?.address

        // Node отсутствует или нет доступа (не удалось создать ранее)
        if (res.status !== 200) {
          console.log(`[NODE CHECK] Unexpected status code "${res.status}" - throwing error`)
          throw new Error(`Unexpected response status code "${res.status}"`)
        }

        // Node существует, IP адреса успешно отображаются
        if (externalIP && internalIP) {
          console.log(`[NODE CHECK] Node IPs → Internal: ${internalIP}, External: ${externalIP} - stopping watch`)
          // Проверки
          expect(res.status).toBe(200)
          expect(externalIP.address).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
          expect(internalIP.address).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
          return
        }

        // Node существует, но IP адреса ещё не отображаются — продолжаем ждать
        console.log(`[NODE CHECK] Node doesn't have IP addresses - continuing to wait`)
        await new Promise(resolve => setTimeout(resolve, retryInterval))
      }

      // Если дошли сюда - значит IP адреса не успели отобразиться за отведённое время
      throw new Error(`Timeout waiting for Node "${nodeName}" to have ExternalIP and InternalIP within ${maxRetryTime / 1000} seconds`)
    })

    test('should contain correct labels', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = createHttpsAgent(kubeAuthFiles.clientCert, kubeAuthFiles.clientKey, kubeAuthFiles.caCrt)

      // Запрос на получение Node
      const res = await fetch(`${baseURL}${nodePath}/${nodeName}`, {
        method: 'GET',
        agent: httpsAgent,
      })
      const body = await res.json()

      console.log(`[NODE CHECK] Received status "${res.status}"`)

      // Проверки
      expect(body.metadata.name).toBe(nodeName)
      expect(body.metadata.labels['beta.kubernetes.io/instance-type']).toBe('vps')
      expect(body.metadata.labels['failure-domain.beta.kubernetes.io/region']).toBe('ru1')
      expect(body.metadata.labels['failure-domain.beta.kubernetes.io/zone']).toBe('ru1-dc1')
      expect(body.metadata.labels['node.kubernetes.io/instance-type']).toBe('vps')
      expect(body.metadata.labels['topology.kubernetes.io/region']).toBe('ru1')
      expect(body.metadata.labels['topology.kubernetes.io/zone']).toBe('ru1-dc1')
    })

    test('should delete node', async () => {
      // Настройка HTTPS агента с mTLS
      const httpsAgent = createHttpsAgent(kubeAuthFiles.clientCert, kubeAuthFiles.clientKey, kubeAuthFiles.caCrt)

      // Запрос на удаление Node
      const res = await fetch(`${baseURL}${nodePath}/${nodeName}`, {
        method: 'DELETE',
        agent: httpsAgent,
      })

      console.log(`[NODE DELETE] Received status "${res.status}"`)

      // Проверки
      expect(res.status).toBe(200)
    })
  })
})
