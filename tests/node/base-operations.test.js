const { createNode, getNode, deleteNode } = require('#helpers/nodeHelpers.js')
const { waitForNodeReadiness } = require('#helpers/waitForNodeReadiness.js')
const { nodeManifest } = require('#helpers/nodeTemplates.js')
const { nodeTests } = require('#fixtures/testData.js')

const { nodeName } = nodeTests.nodeData
const WAIT_TIMEOUT = 60000

describe('base operations with Node', () => {
  test('should create node', async () => {
    const newNodeManifest = JSON.parse(JSON.stringify(nodeManifest))
    newNodeManifest.metadata.name = nodeName
    const { status } = await createNode(newNodeManifest)
    expect(status).toBe(201)
  })

  test('should verify node internal / external IP', async () => {
    const { status, body } = await waitForNodeReadiness(nodeName, WAIT_TIMEOUT)
    const externalIP = body.status.addresses.find(addr => addr.type === 'ExternalIP')
    const internalIP = body.status.addresses.find(addr => addr.type === 'InternalIP')
    expect(status).toBe(200)
    expect(externalIP).toBeDefined()
    expect(internalIP).toBeDefined()
  })

  test('should verify node labels', async () => {
    const { status, body } = await getNode()
    expect(status).toBe(200)
    expect(body.metadata.name).toBe(nodeName)
    expect(body.metadata.labels['beta.kubernetes.io/instance-type']).toBe('vps')
    expect(body.metadata.labels['failure-domain.beta.kubernetes.io/region']).toBe('ru1')
    expect(body.metadata.labels['failure-domain.beta.kubernetes.io/zone']).toBe('ru1-dc1')
    expect(body.metadata.labels['node.kubernetes.io/instance-type']).toBe('vps')
    expect(body.metadata.labels['topology.kubernetes.io/region']).toBe('ru1')
    expect(body.metadata.labels['topology.kubernetes.io/zone']).toBe('ru1-dc1')
  })

  test('should delete node', async () => {
    const { status } = await deleteNode(nodeName)
    expect(status).toBe(200)
  })
})
