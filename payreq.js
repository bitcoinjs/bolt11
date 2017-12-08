'use strict'

const crypto = require('crypto')
const bech32 = require('bech32')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const BigNumber = require('bignumber.js')
const bitcoinjs = require('bitcoinjs-lib')

const BECH32CODES = {
  bc: 'bitcoin',
  tb: 'testnet'
}

const MULTIPLIERS = {
  m: BigNumber('0.001'),
  u: BigNumber('0.000001'),
  n: BigNumber('0.000000001'),
  p: BigNumber('0.000000000001')
}

const reduceWordsToIntBE = (total, item, index) => { return total + item * Math.pow(32, index) }

const wordsToIntBE = (words) => words.reverse().reduce(reduceWordsToIntBE, 0)

const sha256 = (data) => crypto.createHash('sha256').update(data).digest()

const convert = (data, inBits, outBits, pad) => {
  let value = 0
  let bits = 0
  let maxV = (1 << outBits) - 1

  let result = []
  for (let i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i]
    bits += inBits

    while (bits >= outBits) {
      bits -= outBits
      result.push((value >> bits) & maxV)
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((value << (outBits - bits)) & maxV)
    }
  } else {
    if (bits >= inBits) throw new Error('Excess padding')
    if ((value << (outBits - bits)) & maxV) throw new Error('Non-zero padding')
  }

  return result
}

const wordsTrimmedToBuffer = (words) => {
  let buffer = Buffer.from(convert(words, 5, 8, true))
  if (words.length * 5 % 8 !== 0) {
    buffer = buffer.slice(0,-1)
  }
  return buffer
}

const fallbackAddressParser = (words, network) => {
  let version = words[0]
  words = words.slice(1)

  let addressHash = wordsTrimmedToBuffer(words)

  let address

  switch (version) {
    case 17:
      address = bitcoinjs.address.toBase58Check(addressHash, network.pubKeyHash)
      break
    case 18:
      address = bitcoinjs.address.toBase58Check(addressHash, network.scriptHash)
      break
    case 0:
      address = bitcoinjs.address.toBech32(addressHash, version, network.bech32)
      break
    default:
      address = null
      break
  }

  return {
    code: version,
    address,
    addressHash: addressHash.toString('hex')
  }
}

const routingInfoParser = (words) => {
  let routes = []
  let pubkey, short_channel_id, fee_mSats, cltv_expiry_delta
  let routesBuffer = wordsTrimmedToBuffer(words)
  while (routesBuffer.length > 0) {
    pubkey = routesBuffer.slice(0,33).toString('hex') // 33 bytes
    short_channel_id = routesBuffer.slice(33,41).toString('hex') // 8 bytes
    fee_mSats = parseInt(routesBuffer.slice(41,49).toString('hex'),16) // 8 bytes
    cltv_expiry_delta = parseInt(routesBuffer.slice(49,51).toString('hex'),16) // 2 bytes

    routesBuffer = routesBuffer.slice(51)

    routes.push({
      pubkey,
      short_channel_id,
      fee_mSats,
      cltv_expiry_delta
    })
  }
  return routes
}

const TAGNAMES = {
  '1': 'payment_hash',
  '13': 'description',
  '19': 'payee_node_key',
  '23': 'purpose_commit_hash', // commit to longer descriptions (like a website)
  '6': 'expire_time', // default: 3600 (1 hour)
  '24': 'min_final_cltv_expiry', // default: 9
  '9': 'fallback_address',
  '3': 'routing_info' // for extra routing info (private etc.)
}

const TAGPARSERS = {
  '1': ((words) => wordsTrimmedToBuffer(words).toString('hex')), // 256 bits
  '13': ((words) => wordsTrimmedToBuffer(words).toString('utf8')), // string variable length
  '19': ((words) => wordsTrimmedToBuffer(words).toString('hex')), // 264 bits
  '23': ((words) => wordsTrimmedToBuffer(words).toString('hex')), // 256 bits
  '6': wordsToIntBE, // default: 3600 (1 hour)
  '24': wordsToIntBE, // default: 9
  '9': fallbackAddressParser,
  '3': routingInfoParser // for extra routing info (private etc.)
}

function encode (dataObj) {

}

function decode (paymentRequest) {
  if (paymentRequest.slice(0,2) !== 'ln') throw new Error('Not a proper lightning payment request')
  let { prefix, words } = bech32.decode(paymentRequest, 1023)

  let sigWords = words.slice(-104)
  let wordsNoSig = words.slice(0,-104)
  words = words.slice(0,-104)

  let sigBuffer = wordsTrimmedToBuffer(sigWords)
  let recoveryFlag = sigBuffer.slice(-1)[0]
  sigBuffer = sigBuffer.slice(0,-1)

  if (!(recoveryFlag in [0, 1, 2, 3]) || sigBuffer.length !== 64) {
    throw new Error('Signature is missing or incorrect')
  }

  let prefixMatches = prefix.match(/^ln(\S*?)(\d*)([munp]?)$/)

  let coinType = prefixMatches[1]
  let coinNetwork = bitcoinjs.networks['bitcoin']
  if (BECH32CODES[coinType]) {
    coinType = BECH32CODES[coinType]
    coinNetwork = bitcoinjs.networks[coinType]
  }

  let value = prefixMatches[2]
  let satoshis
  if (value) {
    let valueInt = parseInt(value)
    let multiplier = prefixMatches[3]
    satoshis = multiplier ? MULTIPLIERS[multiplier].mul(valueInt).mul(1e8).toNumber() : valueInt * 1e8
  } else {
    satoshis = null
  }

  let timestamp = wordsToIntBE(words.slice(0,7))
  let timestampString = new Date(timestamp * 1000).toISOString()
  words = words.slice(7)

  let tags = {}
  let tagName, parser, tagLength, tagWords, tag
  while (words.length > 0) {
    tagName = TAGNAMES[words[0].toString()]
    parser = TAGPARSERS[words[0].toString()]
    words = words.slice(1)

    tagLength = wordsToIntBE(words.slice(0,2))
    words = words.slice(2)

    tagWords = words.slice(0,tagLength)
    words = words.slice(tagLength)

    tags[tagName] = parser(tagWords, coinNetwork)
  }

  let expireDate, expireDateString
  if (tags.expire_time) {
    expireDate = timestamp + tags.expire_time
    expireDateString = new Date(expireDate * 1000).toISOString()
  }

  let toSign = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(convert(wordsNoSig, 5, 8, true))])
  let payReqHash = sha256(toSign)
  let sigPubkey = secp256k1.recover(payReqHash, sigBuffer, recoveryFlag, true)
  if (tags[TAGNAMES['19']] && tags[TAGNAMES['19']] !== sigPubkey.toString('hex')) {
    throw new Error('Lightning Payment Request signature pubkey does not match payee pubkey')
  }

  let finalResult = {
    coinType,
    satoshis,
    timestamp,
    timestampString
  }

  if (expireDate) {
    finalResult = Object.assign(finalResult, {expireDate, expireDateString})
  }

  finalResult = Object.assign(finalResult, {
    payeeNodeKey: sigPubkey.toString('hex'),
    tags
  })

  return finalResult
}


module.exports = {
  encode,
  decode
}
