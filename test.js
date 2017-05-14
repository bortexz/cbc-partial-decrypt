const crypto = require('crypto')
const test = require('tape')
const randstring = require('randomstring')
const streamifier = require('streamifier')
const partialDecrypt = require('./')
const mode = 'aes-256-cbc'

function encrypt (text, password) {
  const cipher = crypto.createCipher(mode, password)
  const buffer = Buffer.from(text)
  const crypted = Buffer.concat([cipher.update(buffer), cipher.final()])
  return crypted
}

function partialStream (buf, { start, end }) {
  buf = end ? buf.slice(0, end + 1) : buf
  buf = start ? buf.slice(start) : buf
  return streamifier.createReadStream(buf)
}

test('should work with the whole content when multiple 16', t => {
  t.plan(1)
  const password = 'test'
  const toEncrypt = randstring.generate(128)
  const encrypted = encrypt(toEncrypt, password)
  const opts = {
    mode,
    keyLength: 256,
    password,
    end: 127,
    encrypted (opts) {
      return partialStream(encrypted, opts)
    }
  }

  let string = ''
  const stream = partialDecrypt(opts)
  stream.on('data', chunk => {
    string += chunk.toString('utf8')
  })
  stream.on('end', () => t.equal(string, toEncrypt,
      'Decrypted should be equal to the slice of toEncrypt asked')
    )
})

test('should work with whole content when not multiple 16', t => {
  t.plan(1)
  const password = 'test'
  const toEncrypt = randstring.generate(132)
  const encrypted = encrypt(toEncrypt, password)
  const opts = {
    mode,
    keyLength: 256,
    password,
    end: 131,
    encrypted (opts) {
      return partialStream(encrypted, opts)
    }
  }

  let string = ''
  const stream = partialDecrypt(opts)
  stream.on('data', chunk => {
    string += chunk.toString('utf8')
  })
  stream.on('end', () => t.ok(string, toEncrypt,
      'Decrypted should be equal to the slice of toEncrypt asked')
    )
})

test('should work when start < 16', t => {
  t.plan(1)
  const password = 'test'
  const toEncrypt = randstring.generate(132)
  const encrypted = encrypt(toEncrypt, password)
  const opts = {
    mode,
    keyLength: 256,
    password,
    start: 12,
    end: 131,
    encrypted (opts) {
      return partialStream(encrypted, opts)
    }
  }

  let string = ''
  const stream = partialDecrypt(opts)
  stream.on('data', chunk => {
    string += chunk.toString('utf8')
  })
  stream.on('end', () => t.equal(string, toEncrypt.substring(12),
      'Decrypted should be equal to the slice of toEncrypt asked')
    )
})

test('should work when start >= 16', t => {
  t.plan(1)
  const password = 'test'
  const toEncrypt = randstring.generate(132)
  const encrypted = encrypt(toEncrypt, password)
  const opts = {
    mode,
    keyLength: 256,
    password,
    start: 85,
    end: 131,
    encrypted (opts) {
      return partialStream(encrypted, opts)
    }
  }

  let string = ''
  const stream = partialDecrypt(opts)
  stream.on('data', chunk => {
    string += chunk.toString('utf8')
  })
  stream.on('end', () => t.equal(string, toEncrypt.substring(85),
      'Decrypted should be equal to the slice of toEncrypt asked')
    )
})

test('should work if end specified and multiple of 16', t => {
  t.plan(1)
  const password = 'test'
  const toEncrypt = randstring.generate(128)
  const encrypted = encrypt(toEncrypt, password)
  const opts = {
    mode,
    keyLength: 256,
    password,
    end: 64,
    encrypted (opts) {
      return partialStream(encrypted, opts)
    }
  }

  let string = ''
  const stream = partialDecrypt(opts)
  stream.on('data', chunk => {
    string += chunk.toString('utf8')
  })
  stream.on('end', () => t.equal(string, toEncrypt.substring(0, 65),
      'Decrypted should be equal to the slice of toEncrypt asked')
    )
})

test('should work if end specified and not multiple of 16', t => {
  t.plan(1)
  const password = 'test'
  const toEncrypt = randstring.generate(130)
  const encrypted = encrypt(toEncrypt, password)
  const opts = {
    mode,
    keyLength: 256,
    password,
    end: 89,
    encrypted (opts) {
      return partialStream(encrypted, opts)
    }
  }

  let string = ''
  const stream = partialDecrypt(opts)
  stream.on('data', chunk => {
    string += chunk.toString('utf8')
  })
  stream.on('end', () => t.equal(string, toEncrypt.substring(0, 90),
      'Decrypted should be equal to the slice of toEncrypt asked')
    )
})
