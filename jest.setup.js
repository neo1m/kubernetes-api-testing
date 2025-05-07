const console = require("console")
global.console = console

beforeEach(() => {
  const currentTest = expect.getState().currentTestName
  console.log(`🟡 START: ${currentTest}`)
  console.time(`⏱ TIME: ${currentTest}`)
})

afterEach(() => {
  const currentTest = expect.getState().currentTestName
  console.timeEnd(`⏱ TIME: ${currentTest}`)
  console.log(`✅ DONE: ${currentTest}\n`)
})
