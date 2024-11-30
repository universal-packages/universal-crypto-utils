import crypto from 'crypto'

import { DigestSubjectOptions, GenerateTokenOptions, SubjectDecryptionOptions, SubjectEncryptionOptions, SubjectHashOptions } from './types'

export function checkSubjectHash(subject: string, hashedSubject: string, options?: SubjectHashOptions): boolean {
  const finalOptions: SubjectHashOptions = {
    byteSize: 64,
    format: 'base64',
    scryptOptions: {
      N: 1024 * (options?.byteSize || 64),
      maxmem: 1024 * 1024 * (options?.byteSize || 64) * 2
    },
    ...options
  }

  const encryptedSubjectBuffer = new Uint8Array(Buffer.from(hashedSubject, finalOptions.format))
  const salt = encryptedSubjectBuffer.subarray(0, finalOptions.byteSize)
  const hash = encryptedSubjectBuffer.subarray(-finalOptions.byteSize)
  const hashForSubject = crypto.scryptSync(subject, salt, finalOptions.byteSize, finalOptions.scryptOptions)

  return hashForSubject.equals(hash)
}

export function hashSubject(subject: string, options?: SubjectHashOptions): string {
  const finalOptions: SubjectHashOptions = {
    byteSize: 64,
    format: 'base64',
    scryptOptions: {
      N: 1024 * (options?.byteSize || 64),
      maxmem: 1024 * 1024 * (options?.byteSize || 64) * 2
    },
    ...options
  }
  const salt = new Uint8Array(crypto.randomBytes(finalOptions.byteSize))
  const hash = new Uint8Array(crypto.scryptSync(subject, salt, finalOptions.byteSize, finalOptions.scryptOptions))

  return Buffer.concat([salt, hash]).toString(finalOptions.format)
}

export function encryptSubject(subject: Record<string, any>, secret: string, options?: SubjectEncryptionOptions): string {
  const finalOptions: SubjectEncryptionOptions = {
    algorithm: 'aes-256-gcm',
    authTagLength: 16,
    byteSize: 64,
    format: 'base64',
    ...options
  }

  const payload = { subject, expiresAt: finalOptions.expiresAt, concern: finalOptions.concern }
  const serializedPayload = JSON.stringify(payload)

  const keyLength = finalOptions.algorithm === 'aes-128-gcm' ? 16 : finalOptions.algorithm === 'aes-192-gcm' ? 24 : 32
  const iv = new Uint8Array(crypto.randomBytes(finalOptions.byteSize))
  const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, keyLength)
  const cipher = crypto.createCipheriv(finalOptions.algorithm, key, iv, { authTagLength: finalOptions.authTagLength } as any)

  const encryptedPayload = new Uint8Array(Buffer.concat([new Uint8Array(cipher.update(serializedPayload)), new Uint8Array(cipher.final())]))

  return Buffer.concat([iv, encryptedPayload, new Uint8Array(cipher.getAuthTag())]).toString(finalOptions.format)
}

export function decryptSubject(encryptedSubject: string, secret: string, options?: SubjectDecryptionOptions): any {
  const finalOptions: SubjectDecryptionOptions = {
    algorithm: 'aes-256-gcm',
    authTagLength: 16,
    byteSize: 64,
    format: 'base64',
    ...options
  }

  try {
    const encryptedSubjectBuffer = Buffer.from(encryptedSubject, finalOptions.format)
    const authTag = new Uint8Array(encryptedSubjectBuffer.subarray(-finalOptions.authTagLength))
    const iv = new Uint8Array(encryptedSubjectBuffer.subarray(0, finalOptions.byteSize))
    const encryptedPayload = new Uint8Array(encryptedSubjectBuffer.subarray(finalOptions.byteSize, -finalOptions.authTagLength))

    const keyLength = finalOptions.algorithm === 'aes-128-gcm' ? 16 : finalOptions.algorithm === 'aes-192-gcm' ? 24 : 32
    const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, keyLength)
    const decipher = crypto.createDecipheriv(finalOptions.algorithm, key, iv, { authTagLength: finalOptions.authTagLength })

    decipher.setAuthTag(authTag)

    try {
      const serializedPayload = Buffer.concat([new Uint8Array(decipher.update(encryptedPayload)), new Uint8Array(decipher.final())]).toString()
      const payload = JSON.parse(serializedPayload)

      if (payload.expiresAt && payload.expiresAt < Date.now()) return
      if (payload.concern && payload.concern !== finalOptions.concern) return

      return payload.subject
    } catch {}
  } catch {}
}

export function generateToken(options?: GenerateTokenOptions): string {
  const finalOptions: GenerateTokenOptions = {
    byteSize: 64,
    format: 'base64',
    ...options
  }

  const randomBytes = new Uint8Array(crypto.randomBytes(finalOptions.byteSize))
  let additional = new Uint8Array(Buffer.from(''))

  if (finalOptions.concern || finalOptions.seed) {
    const hash = crypto.createHash('sha256')

    if (finalOptions.seed) hash.update(finalOptions.seed)
    if (finalOptions.concern) hash.update(finalOptions.concern)

    additional = new Uint8Array(hash.digest())
  }

  return Buffer.concat([randomBytes, additional]).toString(finalOptions.format)
}

export function digestSubject(subject: string, secret: string, options?: DigestSubjectOptions): string {
  const finalOptions: DigestSubjectOptions = {
    format: 'base64',
    ...options
  }

  const baseString = `${secret}.${subject}`
  const hash = crypto.createHash('sha512')

  hash.update(baseString)

  return hash.digest().toString(finalOptions.format)
}
