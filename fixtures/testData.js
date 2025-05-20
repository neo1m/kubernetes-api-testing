module.exports = {
  csrTests: {
    serverCSRName: 'test-server-csr',
    clientCSRName: 'test-client-csr',
    nodeData: {
      nodeName: 'csr-tests-kuber-node',
      internalIP: '10.16.0.3',
      externalIP: '31.128.38.32',
    }
  },
  nodeTests: {
    nodeData: {
      nodeName: 'node-tests-kuber-node',
    }
  }
}
