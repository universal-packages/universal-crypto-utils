import { checkSubjectHash, hashSubject } from '../../src'

describe('crypto-utils', (): void => {
  describe('hashSubject + checkSubjectHash', (): void => {
    it('hashes a string that can be checked later against the resulted hash', async (): Promise<void> => {
      const subject = 'this is a subject'
      const hash = hashSubject(subject)

      expect(typeof hash).toEqual('string')
      expect(hash.length).toEqual(172)

      const hashMatch = checkSubjectHash(subject, hash)

      expect(hashMatch).toEqual(true)
      expect(checkSubjectHash('other subject', hash)).not.toEqual(true)
    })

    describe('tweeting options', (): void => {
      it('need to be checked with same options', async (): Promise<void> => {
        const subject = 'this is a subject'
        const hash = hashSubject(subject, { byteSize: 32, scryptOptions: { N: 1024 * 32, maxmem: 1024 * 1024 * 32 * 2 }, format: 'hex' })

        expect(typeof hash).toEqual('string')
        expect(hash.length).toEqual(128)

        const hashMatch = checkSubjectHash(subject, hash, { byteSize: 32, scryptOptions: { N: 1024 * 32, maxmem: 1024 * 1024 * 32 * 2 }, format: 'hex' })

        expect(hashMatch).toEqual(true)
        expect(checkSubjectHash('other subject', hash, { byteSize: 32, scryptOptions: { N: 1024 * 32, maxmem: 1024 * 1024 * 32 * 2 }, format: 'hex' })).not.toEqual(true)
        expect(checkSubjectHash(subject, hash)).not.toEqual(true)
      })
    })
  })
})
