'use strict'

const crypto = require('crypto')
const bech32 = require('bech32')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const BigNumber = require('bignumber.js')
const bitcoinjs = require('bitcoinjs-lib')
const _ = require('lodash')

// defaults for encode; default timestamp is current time at call
const DEFAULTNETWORK = bitcoinjs.networks.testnet
const DEFAULTEXPIRETIME = 3600
const DEFAULTCLTVEXPIRY = 9
const DEFAULTDESCRIPTION = ''

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
  if (intBE > Number.MAX_SAFE_INTEGER) throw new Error('integer too large to convert')
  if (bits > 31 || bits < 1) throw new Error('bits must be a value between 1 and 31')
  if (intBE === 0) return [0]
  while (intBE > 0) {
    words.push(intBE & (Math.pow(2, bits) - 1))
    intBE = Math.floor(intBE / Math.pow(2, bits))
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
    buffer = buffer.slice(0, -1)
  }
  return buffer
}

const hexToBuffer = (hex) => {
  if (hex !== undefined &&
      (typeof hex === 'string' || hex instanceof String) &&
      hex.match(/^([a-zA-Z0-9]{2})*$/)) {
    return Buffer.from(hex, 'hex')
  }
  return hex
}

const textToBuffer = (text) => {
  if (text !== undefined &&
      (typeof text === 'string' || text instanceof String)) {
    return Buffer.from(text, 'utf8')
  }
  return text
}

const hexToWord = (hex) => {
  let buffer = hexToBuffer(hex)
  let words = bech32.toWords(buffer)
  return words
}

const textToWord = (text) => {
  let buffer = textToBuffer(text)
  let words = bech32.toWords(buffer)
  return words
}

// see encoder for details
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

// the code is the witness version OR 17 for P2PKH OR 18 for P2SH
// anything besides code 17 or 18 should be bech32 encoded address.
// 1 word for the code, and right pad with 0 if necessary for the addressHash
// (address parsing for encode is done in the encode function)
const fallbackAddressEncoder = (data, network) => {
  return [data.code].concat(hexToWord(data.addressHash))
}

// first convert from words to buffer, trimming padding where necessary
// parse in 51 byte chunks. See encoder for details.
const routingInfoParser = (words) => {
  let routes = []
  let pubkey, shortChannelId, feeMSats, cltvExpiryDelta
  let routesBuffer = wordsTrimmedToBuffer(words)
  while (routesBuffer.length > 0) {
    pubkey = routesBuffer.slice(0, 33).toString('hex') // 33 bytes
    shortChannelId = routesBuffer.slice(33, 41).toString('hex') // 8 bytes
    feeMSats = parseInt(routesBuffer.slice(41, 49).toString('hex'), 16) // 8 bytes
    cltvExpiryDelta = parseInt(routesBuffer.slice(49, 51).toString('hex'), 16) // 2 bytes

    routesBuffer = routesBuffer.slice(51)

    routes.push({
      pubkey,
      short_channel_id: shortChannelId,
      fee_mSats: feeMSats,
      cltv_expiry_delta: cltvExpiryDelta
    })
  }
  return routes
}

// routing info is encoded first as a large buffer
// 51 bytes for each channel
// 33 byte pubkey, 8 byte short_channel_id, 8 byte millisatoshi fee (left padded)
// and a 2 byte left padded CLTV expiry delta.
// after encoding these 51 byte chunks and concatenating them
// convert to words right padding 0 bits.
const routingInfoEncoder = (datas) => {
  let buffer = Buffer(0)
  datas.forEach(data => {
    buffer = Buffer.concat([buffer, hexToBuffer(data.pubkey)])
    buffer = Buffer.concat([buffer, hexToBuffer(data.short_channel_id)])
    buffer = Buffer.concat([buffer, Buffer([0, 0, 0, 0, 0, 0, 0].concat(intBEToWords(data.fee_mSats, 8)).slice(-8))])
    buffer = Buffer.concat([buffer, Buffer([0].concat(intBEToWords(data.cltv_expiry_delta, 8)).slice(-2))])
  })
  return hexToWord(buffer)
}

// if text, return the sha256 hash of the text as words.
// if hex, return the words representation of that data.
const purposeCommitEncoder = (data) => {
  let buffer
  if (data !== undefined && (typeof data === 'string' || data instanceof String)) {
    if (data.match(/^([a-zA-Z0-9]{2})*$/)) {
      buffer = Buffer.from(data, 'hex')
    } else {
      buffer = sha256(Buffer.from(data, 'utf8'))
    }
  }
  return bech32.toWords(buffer)
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
  '1': (words) => wordsTrimmedToBuffer(words).toString('hex'), // 256 bits
  '13': (words) => wordsTrimmedToBuffer(words).toString('utf8'), // string variable length
  '19': (words) => wordsTrimmedToBuffer(words).toString('hex'), // 264 bits
  '23': (words) => wordsTrimmedToBuffer(words).toString('hex'), // 256 bits
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
  IF tags[TAGNAMES['19']] (payee_node_key) THEN MUST CHECK THAT PUBKEY = PUBKEY OF PRIVATEKEY / SIGNATURE
  IF tags[TAGNAMES['9']] (fallback_address) THEN MUST CHECK THAT THE ADDRESS IS A VALID TYPE
  IF tags[TAGNAMES['3']] (routing_info) THEN MUST CHECK FOR ALL INFO IN EACH
*/
const encode = (inputData) => {
  // we don't want to affect the data being passed in, so we copy the object
  let data = _.cloneDeep(inputData)

  let canReconstruct = !(data.signature === undefined || data.recoveryFlag === undefined)
  let canSign = data.privateKey !== undefined

  // if no cointype is defined, set to testnet
  if (data.coinType === undefined && !canReconstruct) {
    data.coinType = DEFAULTNETWORK
  } else if (data.coinType === undefined && canReconstruct) {
    throw new Error('Need coinType for proper payment request reconstruction')
  } else {
    // if the coinType is not a valid name of a network in bitcoinjs-lib, fail
    if (!bitcoinjs.networks[data.coinType]) throw new Error('Unknown coin type')
    data.coinType = bitcoinjs.networks[data.coinType]
  }

  // use current time as default timestamp (seconds)
  if (data.timestamp === undefined && !canReconstruct) {
    data.timestamp = Math.floor(new Date().getTime() / 1000)
  } else if (data.timestamp === undefined && canReconstruct) {
    throw new Error('Need timestamp for proper payment request reconstruction')
  }

  if (data.tags === undefined) throw new Error('Payment Requests need tags array')

  // If no payment hash, fail
  if (!tagsContainItem(data.tags, TAGNAMES['1'])) {
    throw new Error('Lightning Payment Request needs a payment hash')
  }
  // If no description or purpose commit hash/message, fail
  if (!tagsContainItem(data.tags, TAGNAMES['13']) && !tagsContainItem(data.tags, TAGNAMES['23'])) {
    data.tags.push({
      tagName: TAGNAMES['13'],
      data: DEFAULTDESCRIPTION
    })
  }
  // If we don't have (signature AND recoveryID) OR privateKey, we can't create/reconstruct the signature
  if (!canReconstruct && !canSign) {
    throw new Error('Lightning Payment Request needs signature data OR privateKey buffer')
  }

  // if there's no expire time, and it is not reconstructing (must have private key)
  // default to adding a 3600 second expire time (1 hour)
  if (!tagsContainItem(data.tags, TAGNAMES['6']) && !canReconstruct) {
    data.tags.push({
      tagName: TAGNAMES['6'],
      data: DEFAULTEXPIRETIME
    })
  }

  // if there's no minimum cltv time, and it is not reconstructing (must have private key)
  // default to adding a 9 block minimum cltv time (90 minutes for bitcoin)
  if (!tagsContainItem(data.tags, TAGNAMES['24']) && !canReconstruct) {
    data.tags.push({
      tagName: TAGNAMES['24'],
      data: DEFAULTCLTVEXPIRY
    })
  }

  let privateKey, publicKey, nodePublicKey, tagNodePublicKey
  // If there is a payee_node_key tag convert to buffer
  if (tagsContainItem(data.tags, TAGNAMES['19'])) tagNodePublicKey = hexToBuffer(tagsItems(data.tags, TAGNAMES['19'])[0].data)
  // If there is payeeNodeKey attribute, convert to buffer
  if (data.payeeNodeKey) nodePublicKey = hexToBuffer(data.payeeNodeKey)
  if (nodePublicKey && tagNodePublicKey && !tagNodePublicKey.equals(nodePublicKey)) {
    throw new Error('payeeNodeKey and tag payee node key do not match')
  }
  // in case we have one or the other, make sure it's in nodePublicKey
  nodePublicKey = nodePublicKey || tagNodePublicKey
  if (canSign) {
    privateKey = hexToBuffer(data.privateKey)
    if (privateKey.length !== 32 || !secp256k1.privateKeyVerify(privateKey)) {
      throw new Error('The private key given is not valid for SECP256K1')
    }
    // Check if pubkey matches for private key
    if (nodePublicKey) {
      publicKey = secp256k1.publicKeyCreate(privateKey)
      if (!publicKey.equals(nodePublicKey)) {
        throw new Error('The private key given is not the private key of the node public key given')
      }
    }
  }

  let code, addressHash, address
  // If there is a fallback address tag we must check it is valid
  if (tagsContainItem(data.tags, TAGNAMES['9'])) {
    let addrData = tagsItems(data.tags, TAGNAMES['9'])[0].data
    // Most people will just provide address so Hash and code will be undefined here
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

      // FIXME: If addressHash or code is missing, add them to the original Object
      // after parsing the address value... this changes the actual attributes of the data object.
      // Not very clean.
      addrData.addressHash = addressHash
      addrData.code = code
    }
  }

  // If there is route info tag, check that each route has all 4 necessary info
  if (tagsContainItem(data.tags, TAGNAMES['3'])) {
    let routingInfo = tagsItems(data.tags, TAGNAMES['3'])[0].data
    routingInfo.forEach(route => {
      if (route.pubkey === undefined ||
        route.short_channel_id === undefined ||
        route.fee_mSats === undefined ||
        route.cltv_expiry_delta === undefined) {
        throw new Error('Routing info is incomplete')
      }
      if (!secp256k1.publicKeyVerify(hexToBuffer(route.pubkey))) {
        throw new Error('Routing info pubkey is not a valid pubkey')
      }
      let shortId = hexToBuffer(route.short_channel_id)
      if (!(shortId instanceof Buffer) || shortId.length !== 8) {
        throw new Error('Routing info short channel id must be 8 bytes')
      }
      if (typeof route.fee_mSats !== 'number' ||
        Math.floor(route.fee_mSats) !== route.fee_mSats) {
        throw new Error('Routing info fee is not an integer')
      }
      if (typeof route.cltv_expiry_delta !== 'number' ||
        Math.floor(route.cltv_expiry_delta) !== route.cltv_expiry_delta) {
        throw new Error('Routing info cltv expiry delta is not an integer')
      }
    })
  }

  let prefix = 'ln'
  prefix += data.coinType.bech32

  let multiplier, value
  // calculate the smallest possible integer (removing zeroes) and add the best
  // multiplier (m = milli, u = micro, n = nano, p = pico)
  if (data.satoshis) {
    let mSats = BigNumber(1000).mul(data.satoshis)
    let mSatsString = mSats.toString(10).replace(/\.\d*$/, '')
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

  // bech32 human readable part is lnbc2500m (ln + coinbech32 + satoshis (optional))
  // lnbc or lntb would be valid as well. (no value specified)
  prefix += value + multiplier

  // timestamp converted to 5 bit number array (left padded with 0 bits, NOT right padded)
  let timestampWords = intBEToWords(data.timestamp)

  let tags = data.tags
  let tagWords = []
  tags.forEach(tag => {
    // check if the tagName exists in the encoders object, if not throw Error.
    if (Object.keys(TAGENCODERS).indexOf(tag.tagName) === -1) {
      throw new Error('Unknown tag key: ' + tag.tagName)
    }
    // each tag starts with 1 word code for the tag
    tagWords.push(TAGCODES[tag.tagName])
    let encoder = TAGENCODERS[tag.tagName]
    let words = encoder(tag.data)
    // after the tag code, 2 words are used to store the length (in 5 bit words) of the tag data
    // (also left padded, most integers are left padded while buffers are right padded)
    tagWords = tagWords.concat([0].concat(intBEToWords(words.length)).slice(-2))
    // then append the tag data words
    tagWords = tagWords.concat(words)
  })

  // the data part of the bech32 is TIMESTAMP || TAGS || SIGNATURE
  // currently dataWords = TIMESTAMP || TAGS
  let dataWords = timestampWords.concat(tagWords)

  // the preimage for the signing data is the buffer of the prefix concatenated
  // with the buffer conversion of the data words excluding the signature
  // (right padded with 0 bits)
  let toSign = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(convert(dataWords, 5, 8, true))])
  // single SHA256 hash for the signature
  let payReqHash = sha256(toSign)

  // signature is 64 bytes (32 byte r value and 32 byte s value concatenated)
  // PLUS one extra byte appended to the right with the recoveryID in [0,1,2,3]
  // Then convert to 5 bit words with right padding 0 bits.
  let sigWords
  if (canSign) {
    let sigObj = secp256k1.sign(payReqHash, privateKey)
    sigWords = hexToWord(sigObj.signature.toString('hex') + '0' + sigObj.recovery)
  } else {
    /* Since BOLT11 does not require a payee_node_key tag in the specs,
    most parsers will have to recover the pubkey from the signature
    To ensure the tag data has been provided in the right order etc.
    we should check that the data we got and the node key given match when
    reconstructing a payment request from given signature and recoveryID.
    However, if a privatekey is given, the caller is the privkey owner.
    Earlier we check if the private key matches the payee node key IF they
    gave one. */
    if (nodePublicKey) {
      let recoveredPubkey = secp256k1.recover(payReqHash, Buffer.from(data.signature, 'hex'), data.recoveryFlag, true)
      if (nodePublicKey && !nodePublicKey.equals(recoveredPubkey)) {
        throw new Error('Signature, message, and recoveryID did not produce the same pubkey as payeeNodeKey')
      }
      sigWords = hexToWord(data.signature + '0' + data.recoveryFlag)
    } else {
      throw new Error('Reconstruction with signature and recoveryID requires payeeNodeKey to verify correctness of input data.')
    }
  }

  dataWords = dataWords.concat(sigWords)

  // payment requests get pretty long. Nothing in the spec says anything about length.
  // Even though bech32 loses error correction power over 1023 characters.
  return bech32.encode(prefix, dataWords, Number.MAX_SAFE_INTEGER)
}

// decode will only have extra comments that aren't covered in encode comments.
// also if anything is hard to read I'll comment.
const decode = (paymentRequest) => {
  if (paymentRequest.slice(0, 2) !== 'ln') throw new Error('Not a proper lightning payment request')
  let { prefix, words } = bech32.decode(paymentRequest, Number.MAX_SAFE_INTEGER)

  // signature is always 104 words on the end
  // cutting off at the beginning helps since there's no way to tell
  // ahead of time how many tags there are.
  let sigWords = words.slice(-104)
  // grabbing a copy of the words for later, words will be sliced as we parse.
  let wordsNoSig = words.slice(0, -104)
  words = words.slice(0, -104)

  let sigBuffer = wordsTrimmedToBuffer(sigWords)
  let recoveryFlag = sigBuffer.slice(-1)[0]
  sigBuffer = sigBuffer.slice(0, -1)

  if (!(recoveryFlag in [0, 1, 2, 3]) || sigBuffer.length !== 64) {
    throw new Error('Signature is missing or incorrect')
  }

  // Without reverse lookups, can't say that the multipier at the end must
  // have a number before it, so instead we parse, and if the second group
  // doesn't have anything, there's a good chance the last letter of the
  // coin type got captured by the third group, so just re-regex without
  // the number.
  let prefixMatches = prefix.match(/^ln(\S+?)(\d*)([a-zA-Z]?)$/)
  if (!prefixMatches[2]) prefixMatches = prefix.match(/^ln(\S+)$/)
  if (!prefixMatches) throw new Error('Not a proper lightning payment request')

  let coinType = prefixMatches[1]
  let coinNetwork = bitcoinjs.networks['testnet']
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
    // ex. 200m => 0.001 * 200 * 1e8 == 20000000 satoshis (0.2 BTC)
    // ex. 150p => 0.000000000001 * 150 * 1e8 == 0.015 satoshis (0.00000000015 BTC) (15 millisatoshis)
    // (yes, lightning can use millisatoshis)
    satoshis = multiplier ? MULTIPLIERS[multiplier].mul(valueInt).mul(1e8).toNumber() : valueInt * 1e8
  } else {
    satoshis = null
  }

  // reminder: left padded 0 bits
  let timestamp = wordsToIntBE(words.slice(0, 7))
  let timestampString = new Date(timestamp * 1000).toISOString()
  words = words.slice(7) // trim off the left 7 words

  let tags = []
  let tagName, parser, tagLength, tagWords
  // we have no tag count to go on, so just keep hacking off words
  // until we have none.
  while (words.length > 0) {
    tagName = TAGNAMES[words[0].toString()]
    parser = TAGPARSERS[words[0].toString()]
    words = words.slice(1)

    tagLength = wordsToIntBE(words.slice(0, 2))
    words = words.slice(2)

    tagWords = words.slice(0, tagLength)
    words = words.slice(tagLength)

    // See: parsers for more comments
    tags.push({
      tagName,
      data: parser(tagWords, coinNetwork) // only fallback address needs coinNetwork
    })
  }

  let expireDate, expireDateString
  // be kind and provide an absolute expiration date.
  // good for logs
  if (tagsContainItem(tags, TAGNAMES['6'])) {
    expireDate = timestamp + tagsItems(tags, TAGNAMES['6'])[0].data
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

  // split this up just so the expiration date would appear next to the timestamp
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
