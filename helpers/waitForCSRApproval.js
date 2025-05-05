const { getCSR } = require('#helpers/csrHelpers.js')

/**
 * Ожидает определённый статус CSR.
 *
 * @param {string} name - Имя CSR.
 * @param {string} expectedStatus - Ожидаемый статус (например, "Approved", "Denied").
 * @param {number} timeoutMs - Максимальное время ожидания в миллисекундах.
 * @param {number} intervalMs - Интервал между запросами в миллисекундах.
 * @returns {Promise<{ status: number, body: object }>} - Возвращает результат последнего запроса.
 * 
 */
async function waitForCSRStatus(name, expectedStatus, timeoutMs = 60000, intervalMs = 5000) {
    const deadline = Date.now() + timeoutMs

    while (Date.now() < deadline) {
        const { status, body } = await getCSR(name)

        if (status !== 200) {
            console.warn(`[wait] Could not get CSR "${name}", status: ${status}`)
        } else {
            const conditions = body?.status?.conditions || []

            if (!Array.isArray(conditions)) {
                console.log(`[wait] CSR "${name}" has no conditions yet. Retrying...`)
            } else {
                const matchingCondition = conditions.find(
                    c => c.type === expectedStatus && c.status === 'True'
                )

                if (matchingCondition) {
                    console.log(`[wait] CSR "${name}" is ${expectedStatus}`)
                    return { status, body }
                }

                console.log(
                    `[wait] CSR "${name}" found but don't have status ${expectedStatus}. Conditions:`,
                    JSON.stringify(conditions, null, 2)
                )
            }
        }

        await new Promise(resolve => setTimeout(resolve, intervalMs))
    }

    throw new Error(`CSR "${name}" did not reach status "${expectedStatus}" within ${timeoutMs / 1000} seconds`)
}

module.exports = { waitForCSRStatus }
