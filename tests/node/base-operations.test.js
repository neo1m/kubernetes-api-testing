const fs = require('fs')
const path = require('path')
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

    })

    test('should contain correct labels', async () => {

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
