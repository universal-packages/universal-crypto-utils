import { digestSubject } from '../../src'

describe(digestSubject, (): void => {
  it('hashes a subject in the same way always depending the secret', async (): Promise<void> => {
    const subject = 'this is a subject'
    const digest1 = digestSubject(subject, 'secret')
    const digest2 = digestSubject(subject, 'secret')

    expect(digest1).toEqual(digest2)

    const digest3 = digestSubject(subject, 'secret-other')

    expect(digest1).not.toEqual(digest3)
  })
})
