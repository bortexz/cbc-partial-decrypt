var crypto = require('crypto')
var evp = require('evp_bytestokey')
var through = require('through2')

module.exports = PartialDecryptStream

/**
 * Returns a stream of partially decrypted content, originally encrypted with
 * aes-cbc mode
 * @param opts options object
 * @param opts.encrypted { function } function that should return a stream to
 * the encrypted resource, and should have a signature like
 * createReadStream of fs. Because of how aes-cbc works, it will ask for
 * previous blocks than the one in `start`.
 * @param opts.start from where of the original file to receive
 * @param opts.end until where of the original file to receive
 * @param opts.mode the algorithm to pass to the internal resource.
 * Currently only aes-cbc-{128|192|256} supported.
 * @param opts.keyLength The original keylength to use, when generating the
 * Buffer from the password if string is specified. optional if password already
 * a Buffer
 * @param opts.password String or buffer
 * @param opts.iv The initial IV used to encrypt, if any
 */
function PartialDecryptStream (opts) {
  if (!opts || !opts.password || !opts.mode ||
    !(typeof opts.encrypted === 'function')
  ) {
    throw new Error('Incorrect options')
  }

  if (!opts.start) opts.start = 0

  var keys = evp(opts.password, false, opts.keyLength, 16)
  var password = Buffer.isBuffer(opts.password)
    ? opts.password
    : Buffer.from(keys.key)

  var initIv = opts.iv
    ? Buffer.isBuffer(opts.iv) ? opts.iv : Buffer.from(opts.iv)
    : Buffer.from(keys.iv)

  var start = Math.max(opts.start - (opts.start % 16) - 16, 0)
  var end = opts.end
    ? (opts.end + 1) % 16 === 0 ? opts.end : Math.floor(opts.end / 16) * 16 + 15
    : undefined

  // Prepare output stream
  var toSkip = opts.start % 16
  var left = opts.end
    ? opts.end - opts.start + 1
    : Infinity

  var outputStream = through(function (chunk, _, cb) {
    if (toSkip > 0) {
      var skipLength = Math.min(chunk.length, toSkip)
      chunk = chunk.slice(skipLength)
      toSkip -= skipLength
      if (chunk.length === 0) return
    }
    if (chunk.length > left) chunk = chunk.slice(0, left)
    left -= chunk.length
    cb(null, chunk)
  })

  var needIvFromFile = opts.start >= 16
  var ivLength = needIvFromFile ? 0 : 16
  var iv = needIvFromFile ? new Uint8Array(16) : initIv

  // read from the source
  var readFileStream = opts.encrypted({ start: start, end: end })
  var decipherStream
  readFileStream.on('data', function (chunk) {
    if (ivLength < 16) {
      var ivPiece = Math.min(chunk.length, 16 - ivLength)
      iv.set(chunk.slice(0, ivPiece), ivLength)
      ivLength += ivPiece
      if (ivLength !== 16) return // Not finished reading IV

      iv = Buffer.from(iv)
      chunk = chunk.slice(ivPiece)
    }
    if (!decipherStream) {
      decipherStream = crypto
        .createDecipheriv(opts.mode, password, iv)
        .setAutoPadding(false)

      readFileStream.on('end', () => decipherStream.end())
      decipherStream.pipe(outputStream)
    }
    decipherStream.write(chunk)
  })
  return outputStream
}
