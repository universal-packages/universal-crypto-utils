# Crypto utils

[![npm version](https://badge.fury.io/js/@universal-packages%2Fcrypto-utils.svg)](https://www.npmjs.com/package/@universal-packages/crypto-utils)
[![Testing](https://github.com/universal-packages/universal-crypto-utils/actions/workflows/testing.yml/badge.svg)](https://github.com/universal-packages/universal-crypto-utils/actions/workflows/testing.yml)
[![codecov](https://codecov.io/gh/universal-packages/universal-crypto-utils/branch/main/graph/badge.svg?token=CXPJSN8IGL)](https://codecov.io/gh/universal-packages/universal-crypto-utils)

Extended functionality for crypto, basic methods for hashing, encrypting and generating randomness.

## Install

```shell
npm install @universal-packages/crypto-utils
```

## hashSubject `(subject: string, [options])`

Generates a random digested and salted string from a an original subject that can be tested against the final hash later.

```js
import { hashSubject } from '@universal-packages/crypto-utils'

const hash = hashSubject('my password', { format: 'base64' })

console.log(hash)

// > Yra32DP6G6eRfcLVGLbMmqCoBnM062KVzIrGZnsqeiE=
```

### Options

- **`byteSize`** `Number` `Default: 64`
  Number of bytes to use to generate randomness.
- **`format`** `BufferEncoding` `Default: base64`
  Format in which final string hash should be generated.
- **`scryptOptions`** `ScryptOptions`
  See [Node scryptSync](https://nodejs.org/api/crypto.html#cryptoscryptsyncpassword-salt-keylen-options) in case you want to specify these.

## checkSubjectHash `(subject: string, hashed: string, [options])`

Checks against a previously generated hash and the original subject and check if they match. It imperative to use the same options as when previously hashing the subject.

```js
import { checkSubjectHash, hashSubject } from '@universal-packages/crypto-utils'

const hash = hashSubject('my password')

console.log(checkSubjectHash('my password', hash))
console.log(checkSubjectHash('other thing', hash))

// > true
// > false
```

### Options

- **`byteSize`** `Number` `Default: 64`
  Number of bytes to use to generate randomness.
- **`format`** `BufferEncoding` `Default: base64`
  Format in which final string hash should be generated.
- **`scryptOptions`** `ScryptOptions`
  See [Node scryptSync](https://nodejs.org/api/crypto.html#cryptoscryptsyncpassword-salt-keylen-options) in case you want to specify these.

## encryptSubject `(subject: Object, secret: string, [options])`

Encrypts a subject object into a string that can be decrypted later into the original subject object.

```js
import { encryptSubject } from '@universal-packages/crypto-utils'

const encrypted = encryptSubject({ id: 1 }, 'my secret', { format: 'base64' })

console.log(encrypted)

// > Yra32DLVGLbMmqCoBnM0P6ra32DG6era32DRfcLVGLbMra32DmqCoBnM06ra32D2KVLVGLbMmqCoBnM0zIrGZnsqeiE=
```

### Options

- **`algorithm`** `CipherGCMTypes` `Default: aes-256-gcm`
  Algorithm used to encrypt the subject.
- **`authTagLength`** `Number` `Default: 16`
  Specifies the length of the authentication tag in bytes.
- **`byteSize`** `Number` `Default: 64`
  Number of bytes to use to generate randomness.
- **`concern`** `String`
  Used to discriminate against encrypted objects used under different context.
- **`expiresAt`** `Number`
  Date in milliseconds, if provided the subject will not be able to be decrypted after this date.
- **`format`** `BufferEncoding` `Default: base64`
  Format in which final string should be generated.

## decryptSubject `(encrypted: string, secret: string, [options])`

Decrypts a previously generated subject. It imperative to use the same secret and options as when previously encrypting the subject.

```js
import { decryptSubject, encryptSubject } from '@universal-packages/crypto-utils'

const encrypted = encryptSubject({ id: 1 }, 'my secret')

console.log(decryptSubject(encrypted, 'my secret'))
console.log(decryptSubject(encrypted, 'other secret'))

// > { id: 1 }
// > undefined
```

### Options

- **`algorithm`** `CipherGCMTypes` `Default: aes-256-gcm`
  Algorithm used to encrypt the subject.
- **`authTagLength`** `Number` `Default: 16`
  Specifies the length of the authentication tag in bytes.
- **`byteSize`** `Number` `Default: 64`
  Number of bytes to use to generate randomness.
- **`concern`** `String`
  Used to discriminate against encrypted objects used under different context.

## generateToken `([options])`

Generates a random token.

```js
import { generateToken } from '@universal-packages/crypto-utils'

const token = generateToken({ format: 'base64' })

console.log(token)

// > Yra32DLVGLbMmqCoBnM0P6ra32DG6era32DRf6ra32D2KVLVGLbMmqCoBnM0zIrGZnsqeiE=
```

### Options

- **`byteSize`** `Number` `Default: 64`
  Number of bytes to use to generate randomness.
- **`concern`** `String`
  Used to add randomness based on context.
- **`format`** `BufferEncoding` `Default: base64`
  Format in which final string should be generated.
- **`seed`** `String`
  Used to add randomness based on additional context like machine id, process id and so on.

## digestSubject `(subject: string, secret: string, [options])`

Hashes a subject in the same way always with the same secret.

```js
import { digestSubject } from '@universal-packages/crypto-utils'

const digested1 = digestSubject('subject', 'secret')
const digested2 = digestSubject('subject', 'secret')

console.log(digested1)
console.log(digested2)

// > Yra32DLVGLbMmqCoBnM0P6ra32DG6era32DRf6ra32D2KVLVGLbMmqCoBnM0zIrGZnsqeiE=
// > Yra32DLVGLbMmqCoBnM0P6ra32DG6era32DRf6ra32D2KVLVGLbMmqCoBnM0zIrGZnsqeiE=
```

### Options

- **`format`** `BufferEncoding` `Default: base64`
  Format in which final string should be generated.

## Typescript

This library is developed in TypeScript and shipped fully typed.

## Contributing

The development of this library happens in the open on GitHub, and we are grateful to the community for contributing bugfixes and improvements. Read below to learn how you can take part in improving this library.

- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Contributing Guide](./CONTRIBUTING.md)

### License

[MIT licensed](./LICENSE).
