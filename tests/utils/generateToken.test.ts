import crypto from 'crypto'

import { generateToken } from '../../src'

beforeEach((): void => {
  jest.clearAllMocks()
})

describe(generateToken, (): void => {
  it('generates an irrepealable random token', async (): Promise<void> => {
    const generatedTokens: Set<string> = new Set()

    for (let i = 0; i < (process.env['CI'] ? 100_000 : 10_000); i++) {
      const token = generateToken()

      expect(token.length).toEqual(88)

      generatedTokens.add(token)

      expect(generatedTokens.size).toEqual(i + 1)
    }
  })

  it('can take concern and/or a seed to generate the token based on context', async (): Promise<void> => {
    jest.spyOn(crypto, 'randomBytes').mockImplementation((): Buffer => Buffer.from('123456789'))

    const token = generateToken()
    const tokenConcerned = generateToken({ concern: 'testing' })
    const tokenSeeded = generateToken({ seed: 'machine-1' })
    const tokenBoth = generateToken({ concern: 'testing', seed: 'machine-1' })

    expect(token).not.toEqual(tokenConcerned)
    expect(tokenConcerned).not.toEqual(tokenSeeded)
    expect(tokenSeeded).not.toEqual(tokenBoth)
    expect(tokenBoth).not.toEqual(token)
  })
})
