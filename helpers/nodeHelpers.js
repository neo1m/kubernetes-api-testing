const { kubeFetch } = require('#helpers/kubeClient.js')

const nodeBasePath = '/api/v1/nodes'

async function getNodeList() {
  try {
    const res = await kubeFetch(nodeBasePath, {
      method: 'GET'
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

async function getNode(name) {
  try {
    const res = await kubeFetch(`${nodeBasePath}/${name}`, {
      method: 'GET'
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

async function deleteNode(name) {
  try {
    const res = await kubeFetch(`${nodeBasePath}/${name}`, { 
      method: 'DELETE',
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

async function createNode(nodeObject) {
  try {
    const res = await kubeFetch(nodeBasePath, {
      method: 'POST',
      body: JSON.stringify(nodeObject),
      headers: { 'Content-Type': 'application/json' },
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

module.exports = {
  getNodeList,
  getNode,
  deleteNode,
  createNode,
}
