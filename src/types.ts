import { CipherGCMTypes, ScryptOptions } from 'crypto'

export interface SubjectHashOptions {
  byteSize?: number
  format?: BufferEncoding
  scryptOptions?: ScryptOptions
}

export interface SubjectEncryptionOptions {
  algorithm?: CipherGCMTypes
  authTagLength?: number
  byteSize?: number
  concern?: string
  expiresAt?: number
  format?: BufferEncoding
}

export interface SubjectDecryptionOptions {
  algorithm?: CipherGCMTypes
  authTagLength?: number
  byteSize?: number
  concern?: string
  format?: BufferEncoding
}

export interface GenerateTokenOptions {
  byteSize?: number
  concern?: string
  format?: BufferEncoding
  seed?: string
}

export interface DigestSubjectOptions {
  format?: BufferEncoding
}

