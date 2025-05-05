const { kubeFetch } = require('#helpers/kubeClient.js')

const csrBasePath = '/apis/certificates.k8s.io/v1/certificatesigningrequests'

async function getCSRList() {
  const res = await kubeFetch(csrBasePath, {
    method: 'GET'
  })
  const body = await res.json()
  return { status: res.status, body }
}

async function getCSR(name) {
  const res = await kubeFetch(`${csrBasePath}/${name}`, {
    method: 'GET'
  })
  const body = await res.json()
  return { status: res.status, body }
}

async function deleteCSR(name) {
  const res = await kubeFetch(`${csrBasePath}/${name}`, { 
    method: 'DELETE',
  })
  const body = await res.json()
  return { status: res.status, body }
}

async function createCSR(csrObject) {
  const res = await kubeFetch(csrBasePath, {
    method: 'POST',
    body: JSON.stringify(csrObject),
    headers: { 'Content-Type': 'application/json' },
  })
  const body = await res.json()
  return { status: res.status, body }
}

module.exports = {
  getCSRList,
  getCSR,
  deleteCSR,
  createCSR,
}
