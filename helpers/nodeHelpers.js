const { kubeFetch } = require('#helpers/kubeClient.js')

const nodeBasePath = '/api/v1/nodes'

async function getNodeList() {
  const res = await kubeFetch(nodeBasePath, {
    method: 'GET'
  })
  const body = await res.json()
  return { status: res.status, body }
}

async function getNode(name) {
  const res = await kubeFetch(`${nodeBasePath}/${name}`, {
    method: 'GET'
  })
  const body = await res.json()
  return { status: res.status, body }
}

async function deleteNode(name) {
  const res = await kubeFetch(`${nodeBasePath}/${name}`, { 
    method: 'DELETE',
  })
  const body = await res.json()
  return { status: res.status, body }
}

async function createNode(nodeObject) {
  const res = await kubeFetch(nodeBasePath, {
    method: 'POST',
    body: JSON.stringify(nodeObject),
    headers: { 'Content-Type': 'application/json' },
  })
  const body = await res.json()
  return { status: res.status, body }
}

module.exports = {
  getNodeList,
  getNode,
  deleteNode,
  createNode,
}
