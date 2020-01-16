const crypto = require('crypto')
const key = 'ABCDEF123456' // Must be 256 bits (32 characters) // get this from some .env or some other file
const algorithm = 'aes-256-ctr'
const inputEncoding = 'utf8'
const outputEncoding = 'hex'
const encryptedKey = crypto
  .createHash('sha256')
  .update(String(key))
  .digest('base64')
  .substr(0, 32)

const encryptString = stringToBeEncrypted => {
  const iv = crypto
    .randomBytes(16)
    .toString('hex')
    .slice(0, 16)
  // const iv = Buffer.alloc(random)
  const cipher = crypto.createCipheriv(algorithm, encryptedKey, iv)
  let crypted = cipher.update(
    stringToBeEncrypted,
    inputEncoding,
    outputEncoding
  )
  crypted += cipher.final(outputEncoding)
  return `${iv.toString('hex')}:${crypted.toString()}`
}

const decryptString = stringToBeDecrypted => {
  const textParts = stringToBeDecrypted.split(':')
  // extract the IV from the first half of the value
  const IV = textParts
    .shift()
    .toString('hex')
    .slice(0, 16)
  // extract the encrypted text without the IV
  // const encryptedText = new Buffer(textParts.join(':'), outputEncoding)
  const encryptedText = textParts
    .join(':')
    .toString('hex')
    .slice(0, 16)
  // decipher the string
  const decipher = crypto.createDecipheriv(algorithm, encryptedKey, IV)
  let decrypted = decipher.update(encryptedText, outputEncoding, inputEncoding)
  decrypted += decipher.final(inputEncoding)
  return decrypted.toString()
}
module.exports = { encryptString, decryptString }
