var crypto = require('crypto')
var evp = require('evp_bytestokey')
var Readable = require('readable-stream').Readable
const inherits = require('util').inherits

module.exports = PartialDecryptStream

inherits(PartialDecryptStream, Readable)

function PartialDecryptStream (opts) {
  if (!(this instanceof PartialDecryptStream)) {
    return new PartialDecryptStream(opts)
  }
  Readable.call(this, opts)

  if (!opts || !opts.password || !opts.mode ||
    !(typeof opts.encrypted === 'function')) {
    throw new Error('Incorrect options')
  }

  this._sourceEnded = false
  this._decipherEnded = false
  this._destroyed = false

  this._mode = opts.mode
  this._start = opts.start || 0
  this._end = opts.end

  this._toSkip = this._start % 16
  this._left = this._end ? this._end - this._start + 1 : Infinity

  var keys = evp(opts.password, false, opts.keyLength, 16)

  this._password = Buffer.isBuffer(opts.password)
    ? opts.password
    : Buffer.from(keys.key)

  var initIv = opts.iv
    ? Buffer.isBuffer(opts.iv) ? opts.iv : Buffer.from(opts.iv)
    : Buffer.from(keys.iv)

  var needIvFromFile = this._start >= 16
  this._ivLength = needIvFromFile ? 0 : 16
  this._iv = needIvFromFile ? new Uint8Array(16) : initIv

  var sourceStart = Math.max(this._start - (this._start % 16) - 16, 0)
  var sourceEnd = opts.end
    ? (opts.end + 1) % 16 === 0
      ? opts.end
      : Math.floor(opts.end / 16) * 16 + 15
    : undefined

  this._sourceStream = opts.encrypted({ start: sourceStart, end: sourceEnd })

  var self = this
  this._sourceStream.on('end', function () {
    self._sourceEnded = true
  })
  this._sourceStream.on('readable', function () {
    self._read()
  })
}

PartialDecryptStream.prototype.destroy = function (err, onclose) {
  if (typeof this._sourceStream.destroy === 'function') {
    this._sourceStream.destroy(err)
  }
  if (this._decipherStream) this._decipherStream.end()

  this._destroyed = true

  if (err) this.emit('error', err)
  this.emit('close')

  if (onclose) onclose()
}

PartialDecryptStream.prototype._read = function (size) {
  if (this._destroyed) return

  if (!this.sourceEnd) {
    var srcChunk = this._sourceStream.read(size)
    if (!srcChunk || srcChunk.length === 0) return

    if (this._ivLength < 16) {
      var ivPiece = Math.min(srcChunk.length, 16 - this._ivLength)
      this._iv.set(srcChunk.slice(0, ivPiece), this._ivLength)
      this._ivLength += ivPiece
      if (this._ivLength !== 16) return // Not finished reading IV

      this._iv = Buffer.from(this._iv)
      srcChunk = srcChunk.slice(ivPiece)
    }

    if (!this._decipherStream) {
      this._decipherStream = crypto
        .createDecipheriv(this._mode, this._password, this._iv)
        .setAutoPadding(false)

      var self = this
      this._decipherStream.on('end', function () {
        self.push(null)
        self._decipherEnded = true
      })
    }
    this._decipherStream.write(srcChunk)
  }

  if (this._decipherStream && !this._decipherEnded) {
    var decryptChunk = this._decipherStream.read()
    if (!decryptChunk || decryptChunk.length === 0) return
    if (this._toSkip > 0) {
      var skipLength = Math.min(decryptChunk.length, this._toSkip)
      decryptChunk = decryptChunk.slice(skipLength)
      this._toSkip -= skipLength
      if (decryptChunk.length === 0) return
    }
    if (decryptChunk.length > this._left) decryptChunk = decryptChunk.slice(0, this._left)
    this._left -= decryptChunk.length
    this.push(decryptChunk)
    if (this._left === 0) this.push(null)
  }
}
