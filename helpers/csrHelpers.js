const { kubeFetch } = require('#helpers/kubeClient.js')

const csrBasePath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

async function getCSRList() {
  try {
    const res = await kubeFetch(csrBasePath, {
      method: 'GET'
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

async function getCSR(name) {
  try {
    const res = await kubeFetch(`${csrBasePath}/${name}`, {
      method: 'GET'
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

async function deleteCSR(name) {
  try {
    const res = await kubeFetch(`${csrBasePath}/${name}`, { 
      method: 'DELETE',
    })
    const body = await res.json()
    return { status: res.status, body }
  } catch (error) {
    console.error(error)
    throw error
  }
}

async function createCSR(csrObject) {
  try {
    const res = await kubeFetch(csrBasePath, {
      method: 'POST',
      body: JSON.stringify(csrObject),
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
  getCSRList,
  getCSR,
  deleteCSR,
  createCSR,
}
