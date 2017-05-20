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
}

PartialDecryptStream.prototype.destroy = function (err) {
  if (typeof this._sourceStream.destroy === 'function') {
    this._sourceStream.destroy(err)
  }
  this._destroyed = true
  if (err) this.emit('error', err)
  this.emit('close')
}

PartialDecryptStream.prototype._read = function () {
  this._sourceStream.on('data', chunk => {
    if (this._ivLength < 16) {
      var ivPiece = Math.min(chunk.length, 16 - this._ivLength)
      this._iv.set(chunk.slice(0, ivPiece), this._ivLength)
      this._ivLength += ivPiece
      if (this._ivLength !== 16) return // Not finished reading IV

      this._iv = Buffer.from(this._iv)
      chunk = chunk.slice(ivPiece)
    }
    if (!this._decipherStream) {
      this._decipherStream = crypto
        .createDecipheriv(this._mode, this._password, this._iv)
        .setAutoPadding(false)

      this._sourceStream.on('end', () => this._decipherStream.end())
      this._output()
    }
    this._decipherStream.write(chunk)
  })
}

PartialDecryptStream.prototype._output = function () {
  this._decipherStream.on('data', chunk => {
    console.log(this._toSkip)
    if (this._toSkip > 0) {
      var skipLength = Math.min(chunk.length, this._toSkip)
      chunk = chunk.slice(skipLength)
      this._toSkip -= skipLength
      if (chunk.length === 0) return
    }
    if (chunk.length > this._left) chunk = chunk.slice(0, this._left)
    this._left -= chunk.length
    this.push(chunk)
  })

  this._decipherStream.on('end', () => this.push(null))
}
