const console = require("console")
global.console = console

let testStartTime = 0

beforeEach(() => {
  const name = expect.getState().currentTestName
  console.log(`🟡 START: ${name}`)
  testStartTime = Date.now()
})

afterEach(() => {
  const name = expect.getState().currentTestName
  const duration = Date.now() - testStartTime
  console.log(`✅ DONE: ${name} (${duration} ms)\n`)
})
