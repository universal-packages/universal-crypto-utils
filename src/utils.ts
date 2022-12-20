import crypto from 'crypto'
import { GenerateTokenOptions, SubjectDecryptionOptions, SubjectEncryptionOptions, SubjectHashOptions } from './types'

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

  const encryptedSubjectBuffer = Buffer.from(hashedSubject, finalOptions.format)
  const salt = encryptedSubjectBuffer.slice(0, finalOptions.byteSize)
  const hash = encryptedSubjectBuffer.slice(-finalOptions.byteSize)
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
  const salt = crypto.randomBytes(finalOptions.byteSize)
  const hash = crypto.scryptSync(subject, salt, finalOptions.byteSize, finalOptions.scryptOptions)

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
  const iv = crypto.randomBytes(finalOptions.byteSize)
  const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, keyLength)
  const cipher = crypto.createCipheriv(finalOptions.algorithm, key, iv, { authTagLength: finalOptions.authTagLength } as any)

  const encryptedPayload = Buffer.concat([cipher.update(serializedPayload), cipher.final()])

  return Buffer.concat([iv, encryptedPayload, cipher.getAuthTag()]).toString(finalOptions.format)
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
    const authTag = encryptedSubjectBuffer.slice(-finalOptions.authTagLength)
    const iv = encryptedSubjectBuffer.slice(0, finalOptions.byteSize)
    const encryptedPayload = encryptedSubjectBuffer.slice(finalOptions.byteSize, -finalOptions.authTagLength)

    const keyLength = finalOptions.algorithm === 'aes-128-gcm' ? 16 : finalOptions.algorithm === 'aes-192-gcm' ? 24 : 32
    const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, keyLength)
    const decipher = crypto.createDecipheriv(finalOptions.algorithm, key, iv, { authTagLength: finalOptions.authTagLength })

    decipher.setAuthTag(authTag)

    try {
      const serializedPayload = Buffer.concat([decipher.update(encryptedPayload), decipher.final()]).toString()
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

  const randomBytes = crypto.randomBytes(finalOptions.byteSize)
  let hash = finalOptions.concern || finalOptions.seed ? crypto.createHash('sha256').update(randomBytes) : randomBytes

  if (finalOptions.concern) (hash as crypto.Hash).update(finalOptions.concern)
  if (finalOptions.seed) (hash as crypto.Hash).update(finalOptions.seed)
  if (finalOptions.concern || finalOptions.seed) hash = (hash as crypto.Hash).digest()

  return hash.toString(finalOptions.format)
}
