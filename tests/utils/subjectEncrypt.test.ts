import { decryptSubject, encryptSubject } from '../../src'

describe('encryptSubject + decryptSubject', (): void => {
  it('encrypts an object using a secret that can be decrypted later', async (): Promise<void> => {
    const subject = { a: 'super value' }
    const secret = 'this is a special secret'
    const encrypted = encryptSubject(subject, secret)

    expect(typeof encrypted).toEqual('string')

    const decrypted = decryptSubject(encrypted, secret)

    expect(decrypted).toEqual(subject)
    expect(decryptSubject(encrypted, 'other secret')).toBeUndefined()
    expect(decryptSubject('erratic', secret)).toBeUndefined()
  })

  describe('tweeting options', (): void => {
    it('needs to be decrypted with the same options', async (): Promise<void> => {
      const subject = { a: 'super value' }
      const secret = 'this is a special secret'
      const encrypted = encryptSubject(subject, secret, { algorithm: 'aes-128-gcm', authTagLength: 16, byteSize: 64, format: 'hex' })

      expect(typeof encrypted).toEqual('string')

      const decrypted = decryptSubject(encrypted, secret, { algorithm: 'aes-128-gcm', authTagLength: 16, byteSize: 64, format: 'hex' })

      expect(decrypted).toEqual(subject)
      expect(decryptSubject(encrypted, 'other secret', { algorithm: 'aes-128-gcm', authTagLength: 16, byteSize: 64, format: 'hex' })).toBeUndefined()
      expect(decryptSubject(encrypted, secret)).toBeUndefined()
    })
  })

  describe('set to expire', (): void => {
    it('does only finish the decryption if has not expired', async (): Promise<void> => {
      const subject = { a: 'super value' }
      const secret = 'this is a special secret'
      const encrypted = encryptSubject(subject, secret, { expiresAt: Date.now() + 10000 })
      const decrypted = decryptSubject(encrypted, secret)

      expect(decrypted).toEqual(subject)

      const encryptedExpired = encryptSubject(subject, secret, { expiresAt: Date.now() - 10000 })
      const decryptedExpired = decryptSubject(encryptedExpired, secret)

      expect(decryptedExpired).toBeUndefined()
    })
  })

  describe('concerned encryption', (): void => {
    it('does only finish the decryption if the concern match', async (): Promise<void> => {
      const subject = { a: 'super value' }
      const secret = 'this is a special secret'
      const encrypted = encryptSubject(subject, secret, { concern: 'testing' })
      const decrypted = decryptSubject(encrypted, secret, { concern: 'testing' })

      expect(decrypted).toEqual(subject)

      const encryptedInvalid = encryptSubject(subject, secret, { concern: 'testing' })
      const decryptedInvalid = decryptSubject(encryptedInvalid, secret)

      expect(decryptedInvalid).toBeUndefined()
    })
  })
})
