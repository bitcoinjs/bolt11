'use strict'

const crypto = require('crypto')
const bech32 = require('bech32')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const BigNumber = require('bignumber.js')
const bitcoinjs = require('bitcoinjs-lib')

const VALIDWITNESSVERSIONS = [0]

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

const wordsToIntBE = (words) => words.reverse().reduce((total, item, index) => { return total + item * Math.pow(32, index) }, 0)

const intBEToWords = (intBE, bits) => {
  let words = []
  if (bits === undefined) bits = 5
  while (intBE > 0) {
    words.push(intBE & (Math.pow(2, bits) - 1))
    intBE = intBE >> bits
  }
  return words.reverse()
}

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

const hexToBuffer = (hex) => {
  if (hex !== undefined
      && (typeof hex === 'string' || hex instanceof String)
      && hex.match(/^([a-zA-Z0-9]{2})*$/)) {
    return Buffer.from(hex, 'hex')
  }
  return hex
}

const textToBuffer = (text) => {
  if (text !== undefined
      && (typeof text === 'string' || text instanceof String)) {
    return Buffer.from(text, 'utf8')
  }
  return text
}

const hexToWord = (hex) => {
  let buffer = hexToBuffer(hex)
  let words = convert(buffer, 8, 5, true)
  return words
}

const textToWord = (text) => {
  let buffer = textToBuffer(text)
  let words = convert(buffer, 8, 5, true)
  return words
}

const fallbackAddressParser = (words, network) => {
  let version = words[0]
  words = words.slice(1)

  let addressHash = wordsTrimmedToBuffer(words)

  let address = null

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
  }

  return {
    code: version,
    address,
    addressHash: addressHash.toString('hex')
  }
}

const fallbackAddressEncoder = (data, network) => {
  if (data.code !== undefined && data.addressHash !== undefined) {
    return [data.code].concat(hexToWord(data.addressHash))
  } else if (data.address !== undefined) {

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

const routingInfoEncoder = (datas) => {
  let buffer = Buffer(0)
  datas.forEach(data => {
    buffer = Buffer.concat([buffer, hexToBuffer(data.pubkey)])
    buffer = Buffer.concat([buffer, hexToBuffer(data.short_channel_id)])
    buffer = Buffer.concat([buffer, Buffer([0,0,0,0,0,0,0].concat(intBEToWords(data.fee_mSats, 8)).slice(-8))])
    buffer = Buffer.concat([buffer, Buffer([0].concat(intBEToWords(data.cltv_expiry_delta, 8)).slice(-2))])
  })
  return hexToWord(buffer)
}

const purposeCommitEncoder = (data) => {
  let buffer
  if (data !== undefined && (typeof data === 'string' || data instanceof String)) {
    if (data.match(/^([a-zA-Z0-9]{2})*$/)) {
      buffer = Buffer.from(data, 'hex')
    } else {
      buffer = sha256(Buffer.from(data, 'utf8'))
    }
  }
  return convert(buffer, 8, 5, true)
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

const TAGCODES = {
  'payment_hash': 1,
  'description': 13,
  'payee_node_key': 19,
  'purpose_commit_hash': 23, // commit to longer descriptions (like a website)
  'expire_time': 6, // default: 3600 (1 hour)
  'min_final_cltv_expiry': 24, // default: 9
  'fallback_address': 9,
  'routing_info': 3 // for extra routing info (private etc.)
}

const TAGENCODERS = {
  'payment_hash': hexToWord, // 256 bits
  'description': textToWord, // string variable length
  'payee_node_key': hexToWord, // 264 bits
  'purpose_commit_hash': purposeCommitEncoder, // 256 bits
  'expire_time': intBEToWords, // default: 3600 (1 hour)
  'min_final_cltv_expiry': intBEToWords, // default: 9
  'fallback_address': fallbackAddressEncoder,
  'routing_info': routingInfoEncoder // for extra routing info (private etc.)
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

const tagsItems = (tags, tagName) => tags.filter(item => item.tagName === tagName)

const tagsContainItem = (tags, tagName) => (tagsItems(tags, tagName).length > 0)

/* MUST but default OK:
  coinType  (default: testnet OK)
  timestamp   (default: current time OK)

  MUST:
  signature OR privatekey
  tags[TAGNAMES['1']] (payment hash)
  tags[TAGNAMES['13']] OR tags[TAGNAMES['23']] (description or description for hashing (or description hash))

  MUST CHECK:
  IF tags[TAGNAMES['19']] THEN MUST CHECK THAT PUBKEY = PUBKEY OF PRIVATEKEY / SIGNATURE
  IF tags[TAGNAMES['9']] THEN MUST CHECK THAT THE ADDRESS IS A VALID TYPE
  IF tags[TAGNAMES['3']] THEN MUST CHECK FOR ALL INFO IN EACH
*/
const encode  = (data) => {
  data = Object.assign({}, data)
  if (data.coinType === undefined) {
    data.coinType = bitcoinjs.networks.testnet
  } else {
    if (!bitcoinjs.networks[data.coinType]) throw new Error('Unknown coin type')
    data.coinType = bitcoinjs.networks[data.coinType]
  }

  if (data.timestamp === undefined) data.timestamp = Math.floor(new Date().getTime() / 1000)
  if (!tagsContainItem(data.tags, TAGNAMES['1'])) {
    throw new Error('Lightning Payment Request needs a payment hash')
  }
  if (!tagsContainItem(data.tags, TAGNAMES['13']) && !tagsContainItem(data.tags, TAGNAMES['23'])) {
    throw new Error('Lightning Payment Request needs a description or a purpose commit hash (or message)')
  }
  if ((data.signature === undefined || data.recoveryFlag === undefined) && data.privateKey === undefined) {
    throw new Error('Lightning Payment Request needs signature OR privateKey buffer')
  }

  let privateKey, publicKey, nodePublicKey
  if (tagsContainItem(data.tags, TAGNAMES['19'])) nodePublicKey = hexToBuffer(tagsItems(data.tags, TAGNAMES['19'])[0].data)
  if (data.privateKey) {
    privateKey = hexToBuffer(data.privateKey)
    if (privateKey.length !== 32 || !secp256k1.privateKeyVerify(privateKey)) {
      throw new Error('The private key given is not valid for SECP256K1')
    }
    // Check if pubkey matches for private key here.
    // For signature we must wait until all the info is ready for writing.
    if (tagsContainItem(data.tags, TAGNAMES['19'])) {
      publicKey = secp256k1.publicKeyCreate(privateKey)
      if (!publicKey.equals(nodePublicKey)) {
        throw new Error('The private key given is not the private key of the node public key given')
      }
    }
  }

  let code, addressHash, address
  if (tagsContainItem(data.tags, TAGNAMES['9'])) {
    let addrData = tagsItems(data.tags, TAGNAMES['9'])[0].data
    address = addrData.address
    addressHash = addrData.addressHash
    code = addrData.code

    if (addressHash === undefined || code === undefined) {
      try {
        let bech32addr = bitcoinjs.address.fromBech32(address)
        if (!(bech32addr.version in VALIDWITNESSVERSIONS)) {
          throw new Error('Fallback address witness version is unknown')
        }
        if (bech32addr.prefix !== data.coinType.bech32) {
          throw new Error('Fallback address network type does not match payment request network type')
        }
        addressHash = bech32addr.data
        code = bech32addr.version
      } catch (e) {
        try {
          let base58addr = bitcoinjs.address.fromBase58Check(address)
          if (base58addr.version === data.coinType.pubKeyHash) {
            code = 17
          } else if (base58addr.version === data.coinType.scriptHash) {
            code = 18
          } else {
            throw new Error('Fallback address version (base58) is unknown or the network type is incorrect')
          }
          addressHash = base58addr.hash
        } catch (f) {
          throw new Error('Fallback address type is unknown')
        }
      }

      addrData.addressHash = addressHash
      addrData.code = code
    }
  }

  if (tagsContainItem(data.tags, TAGNAMES['3'])) {
    let routing_info = tagsItems(data.tags, TAGNAMES['3'])[0].data
    routing_info.forEach(route => {
      if (route.pubkey === undefined
        || route.short_channel_id === undefined
        || route.fee_mSats === undefined
        || route.cltv_expiry_delta === undefined) {
          throw new Error('Routing info is incomplete')
      }
      if (!secp256k1.publicKeyVerify(hexToBuffer(route.pubkey))) {
        throw new Error('Routing info pubkey is not a valid pubkey')
      }
      let shortId = hexToBuffer(route.short_channel_id)
      if (!(shortId instanceof Buffer) || shortId.length !== 8) {
        throw new Error('Routing info short channel id must be 8 bytes')
      }
      if (typeof route.fee_mSats !== 'number'
        || Math.floor(route.fee_mSats) !== route.fee_mSats) {
          throw new Error('Routing info fee is not an integer')
      }
      if (typeof route.cltv_expiry_delta !== 'number'
        || Math.floor(route.cltv_expiry_delta) !== route.cltv_expiry_delta) {
          throw new Error('Routing info cltv expiry delta is not an integer')
      }
    })
  }

  let prefix = 'ln'
  prefix += data.coinType.bech32

  let multiplier, value
  if (data.satoshis) {
    let mSats = BigNumber(1000).mul(data.satoshis)
    let mSatsString = mSats.toString(10).replace(/\.\d*$/,'')
    let mSatsLength = mSatsString.length
    if (mSatsLength > 11 && mSatsString.slice(-11) === '00000000000') {
      multiplier = ''
      value = mSats.div(1e11).toString(10)
    } else if (mSatsLength > 8 && mSatsString.slice(-8) === '00000000') {
      multiplier = 'm'
      value = mSats.div(1e8).toString(10)
    } else if (mSatsLength > 5 && mSatsString.slice(-5) === '00000') {
      multiplier = 'u'
      value = mSats.div(1e5).toString(10)
    } else if (mSatsLength > 2 && mSatsString.slice(-2) === '00') {
      multiplier = 'n'
      value = mSats.div(1e2).toString(10)
    } else {
      multiplier = 'p'
      value = mSats.mul(10).toString(10)
    }
  } else {
    multiplier = ''
    value = ''
  }

  prefix += value + multiplier

  let timestampWords = intBEToWords(data.timestamp)

  let tags = data.tags
  let tagWords = []
  tags.forEach(tag => {
    if (Object.keys(TAGENCODERS).indexOf(tag.tagName) === -1) {
      throw new Error('Unknown tag key: ' + tag.tagName)
    }
    tagWords.push(TAGCODES[tag.tagName])
    let encoder = TAGENCODERS[tag.tagName]
    let words = encoder(tag.data)
    tagWords = tagWords.concat([0].concat(intBEToWords(words.length)).slice(-2))
    tagWords = tagWords.concat(words)
  })

  let dataWords = timestampWords.concat(tagWords)

  let toSign = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(convert(dataWords, 5, 8, true))])
  let payReqHash = sha256(toSign)

  let sigWords
  if (data.privateKey) {
    let sigObj = secp256k1.sign(payReqHash, privateKey)
    sigWords = hexToWord(sigObj.signature.toString('hex') + '0' + sigObj.recovery)
  } else {
    if (data.payeeNodeKey) {
      let recoveredPubkey = secp256k1.recover(payReqHash, Buffer.from(data.signature, 'hex'), data.recoveryFlag, true)
      if (data.payeeNodeKey && data.payeeNodeKey !== recoveredPubkey.toString('hex')) {
        throw new Error('Signature, message, and recoveryID did not produce the same pubkey as payeeNodeKey')
      }
      sigWords = hexToWord(data.signature + '0' + data.recoveryFlag)
    } else {
      throw new Error('Reconstruction with signature and recoveryID requires payeeNodeKey to verify correctness of input data.')
    }
  }

  dataWords = dataWords.concat(sigWords)

  return bech32.encode(prefix, dataWords, 999999999)
}

const decode = (paymentRequest) => {
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

  let prefixMatches = prefix.match(/^ln(\S*?)(\d*)([a-zA-Z]?)$/)
  if (!prefixMatches[2]) prefixMatches = prefix.match(/^ln(\S*)$/)
  if (!prefixMatches) throw new Error('Not a proper lightning payment request')

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
    if (!multiplier.match(/^[munp]$/)) throw new Error('Unknown multiplier used in amount')
    satoshis = multiplier ? MULTIPLIERS[multiplier].mul(valueInt).mul(1e8).toNumber() : valueInt * 1e8
  } else {
    satoshis = null
  }

  let timestamp = wordsToIntBE(words.slice(0,7))
  let timestampString = new Date(timestamp * 1000).toISOString()
  words = words.slice(7)

  let tags = []
  let tagName, parser, tagLength, tagWords
  while (words.length > 0) {
    tagName = TAGNAMES[words[0].toString()]
    parser = TAGPARSERS[words[0].toString()]
    words = words.slice(1)

    tagLength = wordsToIntBE(words.slice(0,2))
    words = words.slice(2)

    tagWords = words.slice(0,tagLength)
    words = words.slice(tagLength)

    tags.push({
      tagName,
      data: parser(tagWords, coinNetwork)
    })
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
    paymentRequest,
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
    signature: sigBuffer.toString('hex'),
    recoveryFlag,
    tags
  })

  return finalResult
}


module.exports = {
  encode,
  decode
}
