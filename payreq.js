'use strict'

const createHash = require('create-hash')
const bech32 = require('bech32')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const BN = require('bn.js')
const bitcoinjsAddress = require('bitcoinjs-lib').address
const cloneDeep = require('lodash/cloneDeep')

// defaults for encode; default timestamp is current time at call
const DEFAULTNETWORK = {
  // default network is bitcoin
  bech32: 'bc',
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  validWitnessVersions: [0]
}
const TESTNETWORK = {
  bech32: 'tb',
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  validWitnessVersions: [0]
}
const REGTESTNETWORK = {
  bech32: 'bcrt',
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  validWitnessVersions: [0]
}
const SIMNETWORK = {
  bech32: 'sb',
  pubKeyHash: 0x3f,
  scriptHash: 0x7b,
  validWitnessVersions: [0]
}
const DEFAULTEXPIRETIME = 3600
const DEFAULTCLTVEXPIRY = 9
const DEFAULTDESCRIPTION = ''
const DEFAULTFEATUREBITS = {
  word_length: 4, // last bit set default is 15
  var_onion_optin: {
    required: false,
    supported: true
  },
  payment_secret: {
    required: false,
    supported: true
  }
}

const FEATUREBIT_ORDER = [
  'option_data_loss_protect',
  'initial_routing_sync',
  'option_upfront_shutdown_script',
  'gossip_queries',
  'var_onion_optin',
  'gossip_queries_ex',
  'option_static_remotekey',
  'payment_secret',
  'basic_mpp',
  'option_support_large_channel'
]

const DIVISORS = {
  m: new BN(1e3, 10),
  u: new BN(1e6, 10),
  n: new BN(1e9, 10),
  p: new BN(1e12, 10)
}

const MAX_MILLISATS = new BN('2100000000000000000', 10)

const MILLISATS_PER_BTC = new BN(1e11, 10)
const MILLISATS_PER_MILLIBTC = new BN(1e8, 10)
const MILLISATS_PER_MICROBTC = new BN(1e5, 10)
const MILLISATS_PER_NANOBTC = new BN(1e2, 10)
const PICOBTC_PER_MILLISATS = new BN(10, 10)

const TAGCODES = {
  payment_hash: 1,
  payment_secret: 16,
  description: 13,
  payee_node_key: 19,
  purpose_commit_hash: 23, // commit to longer descriptions (like a website)
  expire_time: 6, // default: 3600 (1 hour)
  min_final_cltv_expiry: 24, // default: 9
  fallback_address: 9,
  routing_info: 3, // for extra routing info (private etc.)
  feature_bits: 5
}

// reverse the keys and values of TAGCODES and insert into TAGNAMES
const TAGNAMES = {}
for (let i = 0, keys = Object.keys(TAGCODES); i < keys.length; i++) {
  const currentName = keys[i]
  const currentCode = TAGCODES[keys[i]].toString()
  TAGNAMES[currentCode] = currentName
}

const TAGENCODERS = {
  payment_hash: hexToWord, // 256 bits
  payment_secret: hexToWord, // 256 bits
  description: textToWord, // string variable length
  payee_node_key: hexToWord, // 264 bits
  purpose_commit_hash: purposeCommitEncoder, // 256 bits
  expire_time: intBEToWords, // default: 3600 (1 hour)
  min_final_cltv_expiry: intBEToWords, // default: 9
  fallback_address: fallbackAddressEncoder,
  routing_info: routingInfoEncoder, // for extra routing info (private etc.)
  feature_bits: featureBitsEncoder
}

const TAGPARSERS = {
  1: (words) => wordsToBuffer(words, true).toString('hex'), // 256 bits
  16: (words) => wordsToBuffer(words, true).toString('hex'), // 256 bits
  13: (words) => wordsToBuffer(words, true).toString('utf8'), // string variable length
  19: (words) => wordsToBuffer(words, true).toString('hex'), // 264 bits
  23: (words) => wordsToBuffer(words, true).toString('hex'), // 256 bits
  6: wordsToIntBE, // default: 3600 (1 hour)
  24: wordsToIntBE, // default: 9
  9: fallbackAddressParser,
  3: routingInfoParser, // for extra routing info (private etc.)
  5: featureBitsParser // keep feature bits as array of 5 bit words
}

const unknownTagName = 'unknownTag'

function unknownEncoder (data) {
  data.words = bech32.decode(data.words, Number.MAX_SAFE_INTEGER).words
  return data
}

function getUnknownParser (tagCode) {
  return (words) => ({
    tagCode: parseInt(tagCode),
    words: bech32.encode('unknown', words, Number.MAX_SAFE_INTEGER)
  })
}

function wordsToIntBE (words) {
  return words.reverse().reduce((total, item, index) => {
    return total + item * Math.pow(32, index)
  }, 0)
}

function intBEToWords (intBE, bits) {
  const words = []
  if (bits === undefined) bits = 5
  intBE = Math.floor(intBE)
  if (intBE === 0) return [0]
  while (intBE > 0) {
    words.push(intBE & (Math.pow(2, bits) - 1))
    intBE = Math.floor(intBE / Math.pow(2, bits))
  }
  return words.reverse()
}

function sha256 (data) {
  return createHash('sha256').update(data).digest()
}

function convert (data, inBits, outBits) {
  let value = 0
  let bits = 0
  const maxV = (1 << outBits) - 1

  const result = []
  for (let i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i]
    bits += inBits

    while (bits >= outBits) {
      bits -= outBits
      result.push((value >> bits) & maxV)
    }
  }

  if (bits > 0) {
    result.push((value << (outBits - bits)) & maxV)
  }

  return result
}

function wordsToBuffer (words, trim) {
  let buffer = Buffer.from(convert(words, 5, 8, true))
  if (trim && words.length * 5 % 8 !== 0) {
    buffer = buffer.slice(0, -1)
  }
  return buffer
}

function hexToBuffer (hex) {
  if (hex !== undefined &&
      (typeof hex === 'string' || hex instanceof String) &&
      hex.match(/^([a-zA-Z0-9]{2})*$/)) {
    return Buffer.from(hex, 'hex')
  }
  return hex
}

function textToBuffer (text) {
  return Buffer.from(text, 'utf8')
}

function hexToWord (hex) {
  const buffer = hexToBuffer(hex)
  return bech32.toWords(buffer)
}

function textToWord (text) {
  const buffer = textToBuffer(text)
  const words = bech32.toWords(buffer)
  return words
}

// see encoder for details
function fallbackAddressParser (words, network) {
  const version = words[0]
  words = words.slice(1)

  const addressHash = wordsToBuffer(words, true)

  let address = null

  switch (version) {
    case 17:
      address = bitcoinjsAddress.toBase58Check(addressHash, network.pubKeyHash)
      break
    case 18:
      address = bitcoinjsAddress.toBase58Check(addressHash, network.scriptHash)
      break
    case 0:
      address = bitcoinjsAddress.toBech32(addressHash, version, network.bech32)
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
function fallbackAddressEncoder (data, network) {
  return [data.code].concat(hexToWord(data.addressHash))
}

// first convert from words to buffer, trimming padding where necessary
// parse in 51 byte chunks. See encoder for details.
function routingInfoParser (words) {
  const routes = []
  let pubkey, shortChannelId, feeBaseMSats, feeProportionalMillionths, cltvExpiryDelta
  let routesBuffer = wordsToBuffer(words, true)
  while (routesBuffer.length > 0) {
    pubkey = routesBuffer.slice(0, 33).toString('hex') // 33 bytes
    shortChannelId = routesBuffer.slice(33, 41).toString('hex') // 8 bytes
    feeBaseMSats = parseInt(routesBuffer.slice(41, 45).toString('hex'), 16) // 4 bytes
    feeProportionalMillionths = parseInt(routesBuffer.slice(45, 49).toString('hex'), 16) // 4 bytes
    cltvExpiryDelta = parseInt(routesBuffer.slice(49, 51).toString('hex'), 16) // 2 bytes

    routesBuffer = routesBuffer.slice(51)

    routes.push({
      pubkey,
      short_channel_id: shortChannelId,
      fee_base_msat: feeBaseMSats,
      fee_proportional_millionths: feeProportionalMillionths,
      cltv_expiry_delta: cltvExpiryDelta
    })
  }
  return routes
}

function featureBitsParser (words) {
  const bools = words.slice().reverse().map(word =>
    [
      !!(word & 0b1),
      !!(word & 0b10),
      !!(word & 0b100),
      !!(word & 0b1000),
      !!(word & 0b10000)
    ]
  ).reduce((finalArr, itemArr) => finalArr.concat(itemArr), [])
  while (bools.length < FEATUREBIT_ORDER.length * 2) {
    bools.push(false)
  }
  const featureBits = {
    word_length: words.length
  }
  FEATUREBIT_ORDER.forEach((featureName, index) => {
    featureBits[featureName] = {
      required: bools[index * 2],
      supported: bools[index * 2 + 1]
    }
  })
  if (bools.length > FEATUREBIT_ORDER.length * 2) {
    const extraBits = bools.slice(FEATUREBIT_ORDER.length * 2)
    featureBits.extra_bits = {
      start_bit: FEATUREBIT_ORDER.length * 2,
      bits: extraBits,
      has_required: extraBits.reduce(
        (result, bit, index) =>
          index % 2 !== 0
            ? result || false
            : result || bit,
        false
      )
    }
  } else {
    featureBits.extra_bits = {
      start_bit: FEATUREBIT_ORDER.length * 2,
      bits: [],
      has_required: false
    }
  }
  return featureBits
}

function featureBitsEncoder (featureBits) {
  let wordsLength = featureBits.word_length
  let bools = []
  FEATUREBIT_ORDER.forEach(featureName => {
    bools.push(!!(featureBits[featureName] || {}).required)
    bools.push(!!(featureBits[featureName] || {}).supported)
  })
  // Make sure that only minimal number of bits is encoded
  while (bools[bools.length - 1] === false) {
    bools.pop()
  }
  while (bools.length % 5 !== 0) {
    bools.push(false)
  }
  if (
    featureBits.extra_bits &&
    Array.isArray(featureBits.extra_bits.bits) &&
    featureBits.extra_bits.bits.length > 0
  ) {
    while (bools.length < featureBits.extra_bits.start_bit) {
      bools.push(false)
    }
    bools = bools.concat(featureBits.extra_bits.bits)
  }
  if (wordsLength !== undefined && bools.length / 5 > wordsLength) {
    throw new Error('word_length is too small to contain all featureBits')
  } else if (wordsLength === undefined) {
    wordsLength = Math.ceil(bools.length / 5)
  }
  return new Array(wordsLength).fill(0).map((_, index) =>
    bools[index * 5 + 4] << 4 |
    bools[index * 5 + 3] << 3 |
    bools[index * 5 + 2] << 2 |
    bools[index * 5 + 1] << 1 |
    bools[index * 5] << 0
  ).reverse()
}

// routing info is encoded first as a large buffer
// 51 bytes for each channel
// 33 byte pubkey, 8 byte short_channel_id, 4 byte millisatoshi base fee (left padded)
// 4 byte fee proportional millionths and a 2 byte left padded CLTV expiry delta.
// after encoding these 51 byte chunks and concatenating them
// convert to words right padding 0 bits.
function routingInfoEncoder (datas) {
  let buffer = Buffer.from([])
  datas.forEach(data => {
    buffer = Buffer.concat([buffer, hexToBuffer(data.pubkey)])
    buffer = Buffer.concat([buffer, hexToBuffer(data.short_channel_id)])
    buffer = Buffer.concat([buffer, Buffer.from([0, 0, 0].concat(intBEToWords(data.fee_base_msat, 8)).slice(-4))])
    buffer = Buffer.concat([buffer, Buffer.from([0, 0, 0].concat(intBEToWords(data.fee_proportional_millionths, 8)).slice(-4))])
    buffer = Buffer.concat([buffer, Buffer.from([0].concat(intBEToWords(data.cltv_expiry_delta, 8)).slice(-2))])
  })
  return hexToWord(buffer)
}

// if text, return the sha256 hash of the text as words.
// if hex, return the words representation of that data.
function purposeCommitEncoder (data) {
  let buffer
  if (data !== undefined && (typeof data === 'string' || data instanceof String)) {
    if (data.match(/^([a-zA-Z0-9]{2})*$/)) {
      buffer = Buffer.from(data, 'hex')
    } else {
      buffer = sha256(Buffer.from(data, 'utf8'))
    }
  } else {
    throw new Error('purpose or purpose commit must be a string or hex string')
  }
  return bech32.toWords(buffer)
}

function tagsItems (tags, tagName) {
  const tag = tags.filter(item => item.tagName === tagName)
  const data = tag.length > 0 ? tag[0].data : null
  return data
}

function tagsContainItem (tags, tagName) {
  return tagsItems(tags, tagName) !== null
}

function orderKeys (unorderedObj) {
  const orderedObj = {}
  Object.keys(unorderedObj).sort().forEach((key) => {
    orderedObj[key] = unorderedObj[key]
  })
  return orderedObj
}

function satToHrp (satoshis) {
  if (!satoshis.toString().match(/^\d+$/)) {
    throw new Error('satoshis must be an integer')
  }
  const millisatoshisBN = new BN(satoshis, 10)
  return millisatToHrp(millisatoshisBN.mul(new BN(1000, 10)))
}

function millisatToHrp (millisatoshis) {
  if (!millisatoshis.toString().match(/^\d+$/)) {
    throw new Error('millisatoshis must be an integer')
  }
  const millisatoshisBN = new BN(millisatoshis, 10)
  const millisatoshisString = millisatoshisBN.toString(10)
  const millisatoshisLength = millisatoshisString.length
  let divisorString, valueString
  if (millisatoshisLength > 11 && /0{11}$/.test(millisatoshisString)) {
    divisorString = ''
    valueString = millisatoshisBN.div(MILLISATS_PER_BTC).toString(10)
  } else if (millisatoshisLength > 8 && /0{8}$/.test(millisatoshisString)) {
    divisorString = 'm'
    valueString = millisatoshisBN.div(MILLISATS_PER_MILLIBTC).toString(10)
  } else if (millisatoshisLength > 5 && /0{5}$/.test(millisatoshisString)) {
    divisorString = 'u'
    valueString = millisatoshisBN.div(MILLISATS_PER_MICROBTC).toString(10)
  } else if (millisatoshisLength > 2 && /0{2}$/.test(millisatoshisString)) {
    divisorString = 'n'
    valueString = millisatoshisBN.div(MILLISATS_PER_NANOBTC).toString(10)
  } else {
    divisorString = 'p'
    valueString = millisatoshisBN.mul(PICOBTC_PER_MILLISATS).toString(10)
  }
  return valueString + divisorString
}

function hrpToSat (hrpString, outputString) {
  const millisatoshisBN = hrpToMillisat(hrpString, false)
  if (!millisatoshisBN.mod(new BN(1000, 10)).eq(new BN(0, 10))) {
    throw new Error('Amount is outside of valid range')
  }
  const result = millisatoshisBN.div(new BN(1000, 10))
  return outputString ? result.toString() : result
}

function hrpToMillisat (hrpString, outputString) {
  let divisor, value
  if (hrpString.slice(-1).match(/^[munp]$/)) {
    divisor = hrpString.slice(-1)
    value = hrpString.slice(0, -1)
  } else if (hrpString.slice(-1).match(/^[^munp0-9]$/)) {
    throw new Error('Not a valid multiplier for the amount')
  } else {
    value = hrpString
  }

  if (!value.match(/^\d+$/)) throw new Error('Not a valid human readable amount')

  const valueBN = new BN(value, 10)

  const millisatoshisBN = divisor
    ? valueBN.mul(MILLISATS_PER_BTC).div(DIVISORS[divisor])
    : valueBN.mul(MILLISATS_PER_BTC)

  if (((divisor === 'p' && !valueBN.mod(new BN(10, 10)).eq(new BN(0, 10))) ||
      millisatoshisBN.gt(MAX_MILLISATS))) {
    throw new Error('Amount is outside of valid range')
  }

  return outputString ? millisatoshisBN.toString() : millisatoshisBN
}

function sign (inputPayReqObj, inputPrivateKey) {
  const payReqObj = cloneDeep(inputPayReqObj)
  const privateKey = hexToBuffer(inputPrivateKey)
  if (payReqObj.complete && payReqObj.paymentRequest) return payReqObj

  if (privateKey === undefined || privateKey.length !== 32 ||
      !secp256k1.privateKeyVerify(privateKey)) {
    throw new Error('privateKey must be a 32 byte Buffer and valid private key')
  }

  let nodePublicKey, tagNodePublicKey
  // If there is a payee_node_key tag convert to buffer
  if (tagsContainItem(payReqObj.tags, TAGNAMES['19'])) {
    tagNodePublicKey = hexToBuffer(tagsItems(payReqObj.tags, TAGNAMES['19']))
  }
  // If there is payeeNodeKey attribute, convert to buffer
  if (payReqObj.payeeNodeKey) {
    nodePublicKey = hexToBuffer(payReqObj.payeeNodeKey)
  }
  // If they are not equal throw an error
  if (nodePublicKey && tagNodePublicKey && !tagNodePublicKey.equals(nodePublicKey)) {
    throw new Error('payee node key tag and payeeNodeKey attribute must match')
  }

  // make sure if either exist they are in nodePublicKey
  nodePublicKey = tagNodePublicKey || nodePublicKey

  const publicKey = secp256k1.publicKeyCreate(privateKey)

  // Check if pubkey matches for private key
  if (nodePublicKey && !publicKey.equals(nodePublicKey)) {
    throw new Error('The private key given is not the private key of the node public key given')
  }

  const words = bech32.decode(payReqObj.wordsTemp, Number.MAX_SAFE_INTEGER).words

  // the preimage for the signing data is the buffer of the prefix concatenated
  // with the buffer conversion of the data words excluding the signature
  // (right padded with 0 bits)
  const toSign = Buffer.concat([Buffer.from(payReqObj.prefix, 'utf8'), wordsToBuffer(words)])
  // single SHA256 hash for the signature
  const payReqHash = sha256(toSign)

  // signature is 64 bytes (32 byte r value and 32 byte s value concatenated)
  // PLUS one extra byte appended to the right with the recoveryID in [0,1,2,3]
  // Then convert to 5 bit words with right padding 0 bits.
  const sigObj = secp256k1.sign(payReqHash, privateKey)
  const sigWords = hexToWord(sigObj.signature.toString('hex') + '0' + sigObj.recovery)

  // append signature words to the words, mark as complete, and add the payreq
  payReqObj.payeeNodeKey = publicKey.toString('hex')
  payReqObj.signature = sigObj.signature.toString('hex')
  payReqObj.recoveryFlag = sigObj.recovery
  payReqObj.wordsTemp = bech32.encode('temp', words.concat(sigWords), Number.MAX_SAFE_INTEGER)
  payReqObj.complete = true
  payReqObj.paymentRequest = bech32.encode(payReqObj.prefix, words.concat(sigWords), Number.MAX_SAFE_INTEGER)

  return orderKeys(payReqObj)
}

function encode (inputData, addDefaults) {
  // we don't want to affect the data being passed in, so we copy the object
  const data = cloneDeep(inputData)

  // by default we will add default values to description, expire time, and min cltv
  if (addDefaults === undefined) addDefaults = true

  const canReconstruct = !(data.signature === undefined || data.recoveryFlag === undefined)

  // if no cointype is defined, set to testnet
  let coinTypeObj
  if (data.network === undefined && !canReconstruct) {
    data.network = DEFAULTNETWORK
    coinTypeObj = DEFAULTNETWORK
  } else if (data.network === undefined && canReconstruct) {
    throw new Error('Need network for proper payment request reconstruction')
  } else {
    // if the coinType is not a valid name of a network in bitcoinjs-lib, fail
    if (
      !data.network.bech32 ||
      data.network.pubKeyHash === undefined ||
      data.network.scriptHash === undefined ||
      !Array.isArray(data.network.validWitnessVersions)
    ) throw new Error('Invalid network')
    coinTypeObj = data.network
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
  // If no feature bits when payment secret is found, fail
  if (tagsContainItem(data.tags, TAGNAMES['16'])) {
    if (!tagsContainItem(data.tags, TAGNAMES['5'])) {
      if (addDefaults) {
        data.tags.push({
          tagName: TAGNAMES['5'],
          data: DEFAULTFEATUREBITS
        })
      } else {
        throw new Error('Payment request requires feature bits with at least payment secret support flagged if payment secret is included')
      }
    } else {
      const fB = tagsItems(data.tags, TAGNAMES['5'])
      if (!fB.payment_secret || (!fB.payment_secret.supported && !fB.payment_secret.required)) {
        throw new Error('Payment request requires feature bits with at least payment secret support flagged if payment secret is included')
      }
    }
  }
  // If no description or purpose commit hash/message, fail
  if (!tagsContainItem(data.tags, TAGNAMES['13']) && !tagsContainItem(data.tags, TAGNAMES['23'])) {
    if (addDefaults) {
      data.tags.push({
        tagName: TAGNAMES['13'],
        data: DEFAULTDESCRIPTION
      })
    } else {
      throw new Error('Payment request requires description or purpose commit hash')
    }
  }

  // If a description exists, check to make sure the buffer isn't greater than
  // 639 bytes long, since 639 * 8 / 5 = 1023 words (5 bit) when padded
  if (tagsContainItem(data.tags, TAGNAMES['13']) &&
      Buffer.from(tagsItems(data.tags, TAGNAMES['13']), 'utf8').length > 639) {
    throw new Error('Description is too long: Max length 639 bytes')
  }

  // if there's no expire time, and it is not reconstructing (must have private key)
  // default to adding a 3600 second expire time (1 hour)
  if (!tagsContainItem(data.tags, TAGNAMES['6']) && !canReconstruct && addDefaults) {
    data.tags.push({
      tagName: TAGNAMES['6'],
      data: DEFAULTEXPIRETIME
    })
  }

  // if there's no minimum cltv time, and it is not reconstructing (must have private key)
  // default to adding a 9 block minimum cltv time (90 minutes for bitcoin)
  if (!tagsContainItem(data.tags, TAGNAMES['24']) && !canReconstruct && addDefaults) {
    data.tags.push({
      tagName: TAGNAMES['24'],
      data: DEFAULTCLTVEXPIRY
    })
  }

  let nodePublicKey, tagNodePublicKey
  // If there is a payee_node_key tag convert to buffer
  if (tagsContainItem(data.tags, TAGNAMES['19'])) tagNodePublicKey = hexToBuffer(tagsItems(data.tags, TAGNAMES['19']))
  // If there is payeeNodeKey attribute, convert to buffer
  if (data.payeeNodeKey) nodePublicKey = hexToBuffer(data.payeeNodeKey)
  if (nodePublicKey && tagNodePublicKey && !tagNodePublicKey.equals(nodePublicKey)) {
    throw new Error('payeeNodeKey and tag payee node key do not match')
  }
  // in case we have one or the other, make sure it's in nodePublicKey
  nodePublicKey = nodePublicKey || tagNodePublicKey
  if (nodePublicKey) data.payeeNodeKey = nodePublicKey.toString('hex')

  let code, addressHash, address
  // If there is a fallback address tag we must check it is valid
  if (tagsContainItem(data.tags, TAGNAMES['9'])) {
    const addrData = tagsItems(data.tags, TAGNAMES['9'])
    // Most people will just provide address so Hash and code will be undefined here
    address = addrData.address
    addressHash = addrData.addressHash
    code = addrData.code

    if (addressHash === undefined || code === undefined) {
      let bech32addr, base58addr
      try {
        bech32addr = bitcoinjsAddress.fromBech32(address)
        addressHash = bech32addr.data
        code = bech32addr.version
      } catch (e) {
        try {
          base58addr = bitcoinjsAddress.fromBase58Check(address)
          if (base58addr.version === coinTypeObj.pubKeyHash) {
            code = 17
          } else if (base58addr.version === coinTypeObj.scriptHash) {
            code = 18
          }
          addressHash = base58addr.hash
        } catch (f) {
          throw new Error('Fallback address type is unknown')
        }
      }
      if (bech32addr && !(bech32addr.version in coinTypeObj.validWitnessVersions)) {
        throw new Error('Fallback address witness version is unknown')
      }
      if (bech32addr && bech32addr.prefix !== coinTypeObj.bech32) {
        throw new Error('Fallback address network type does not match payment request network type')
      }
      if (base58addr && base58addr.version !== coinTypeObj.pubKeyHash &&
          base58addr.version !== coinTypeObj.scriptHash) {
        throw new Error('Fallback address version (base58) is unknown or the network type is incorrect')
      }

      // FIXME: If addressHash or code is missing, add them to the original Object
      // after parsing the address value... this changes the actual attributes of the data object.
      // Not very clean.
      // Without this, a person can not specify a fallback address tag with only the address key.
      addrData.addressHash = addressHash.toString('hex')
      addrData.code = code
    }
  }

  // If there is route info tag, check that each route has all 4 necessary info
  if (tagsContainItem(data.tags, TAGNAMES['3'])) {
    const routingInfo = tagsItems(data.tags, TAGNAMES['3'])
    routingInfo.forEach(route => {
      if (route.pubkey === undefined ||
        route.short_channel_id === undefined ||
        route.fee_base_msat === undefined ||
        route.fee_proportional_millionths === undefined ||
        route.cltv_expiry_delta === undefined) {
        throw new Error('Routing info is incomplete')
      }
      if (!secp256k1.publicKeyVerify(hexToBuffer(route.pubkey))) {
        throw new Error('Routing info pubkey is not a valid pubkey')
      }
      const shortId = hexToBuffer(route.short_channel_id)
      if (!(shortId instanceof Buffer) || shortId.length !== 8) {
        throw new Error('Routing info short channel id must be 8 bytes')
      }
      if (typeof route.fee_base_msat !== 'number' ||
        Math.floor(route.fee_base_msat) !== route.fee_base_msat) {
        throw new Error('Routing info fee base msat is not an integer')
      }
      if (typeof route.fee_proportional_millionths !== 'number' ||
        Math.floor(route.fee_proportional_millionths) !== route.fee_proportional_millionths) {
        throw new Error('Routing info fee proportional millionths is not an integer')
      }
      if (typeof route.cltv_expiry_delta !== 'number' ||
        Math.floor(route.cltv_expiry_delta) !== route.cltv_expiry_delta) {
        throw new Error('Routing info cltv expiry delta is not an integer')
      }
    })
  }

  let prefix = 'ln'
  prefix += coinTypeObj.bech32

  let hrpString
  // calculate the smallest possible integer (removing zeroes) and add the best
  // divisor (m = milli, u = micro, n = nano, p = pico)
  if (data.millisatoshis && data.satoshis) {
    hrpString = millisatToHrp(new BN(data.millisatoshis, 10))
    const hrpStringSat = satToHrp(new BN(data.satoshis, 10))
    if (hrpStringSat !== hrpString) {
      throw new Error('satoshis and millisatoshis do not match')
    }
  } else if (data.millisatoshis) {
    hrpString = millisatToHrp(new BN(data.millisatoshis, 10))
  } else if (data.satoshis) {
    hrpString = satToHrp(new BN(data.satoshis, 10))
  } else {
    hrpString = ''
  }

  // bech32 human readable part is lnbc2500m (ln + coinbech32 + satoshis (optional))
  // lnbc or lntb would be valid as well. (no value specified)
  prefix += hrpString

  // timestamp converted to 5 bit number array (left padded with 0 bits, NOT right padded)
  const timestampWords = intBEToWords(data.timestamp)

  const tags = data.tags
  let tagWords = []
  tags.forEach(tag => {
    const possibleTagNames = Object.keys(TAGENCODERS)
    if (canReconstruct) possibleTagNames.push(unknownTagName)
    // check if the tagName exists in the encoders object, if not throw Error.
    if (possibleTagNames.indexOf(tag.tagName) === -1) {
      throw new Error('Unknown tag key: ' + tag.tagName)
    }

    let words
    if (tag.tagName !== unknownTagName) {
      // each tag starts with 1 word code for the tag
      tagWords.push(TAGCODES[tag.tagName])

      const encoder = TAGENCODERS[tag.tagName]
      words = encoder(tag.data)
    } else {
      const result = unknownEncoder(tag.data)
      tagWords.push(result.tagCode)
      words = result.words
    }
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
  const toSign = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(convert(dataWords, 5, 8))])
  // single SHA256 hash for the signature
  const payReqHash = sha256(toSign)

  // signature is 64 bytes (32 byte r value and 32 byte s value concatenated)
  // PLUS one extra byte appended to the right with the recoveryID in [0,1,2,3]
  // Then convert to 5 bit words with right padding 0 bits.
  let sigWords
  if (canReconstruct) {
    /* Since BOLT11 does not require a payee_node_key tag in the specs,
    most parsers will have to recover the pubkey from the signature
    To ensure the tag data has been provided in the right order etc.
    we should check that the data we got and the node key given match when
    reconstructing a payment request from given signature and recoveryID.
    However, if a privatekey is given, the caller is the privkey owner.
    Earlier we check if the private key matches the payee node key IF they
    gave one. */
    if (nodePublicKey) {
      const recoveredPubkey = secp256k1.recover(payReqHash, Buffer.from(data.signature, 'hex'), data.recoveryFlag, true)
      if (nodePublicKey && !nodePublicKey.equals(recoveredPubkey)) {
        throw new Error('Signature, message, and recoveryID did not produce the same pubkey as payeeNodeKey')
      }
      sigWords = hexToWord(data.signature + '0' + data.recoveryFlag)
    } else {
      throw new Error('Reconstruction with signature and recoveryID requires payeeNodeKey to verify correctness of input data.')
    }
  }

  if (sigWords) dataWords = dataWords.concat(sigWords)

  if (tagsContainItem(data.tags, TAGNAMES['6'])) {
    data.timeExpireDate = data.timestamp + tagsItems(data.tags, TAGNAMES['6'])
    data.timeExpireDateString = new Date(data.timeExpireDate * 1000).toISOString()
  }
  data.timestampString = new Date(data.timestamp * 1000).toISOString()
  data.complete = !!sigWords
  data.paymentRequest = data.complete ? bech32.encode(prefix, dataWords, Number.MAX_SAFE_INTEGER) : ''
  data.prefix = prefix
  data.wordsTemp = bech32.encode('temp', dataWords, Number.MAX_SAFE_INTEGER)

  // payment requests get pretty long. Nothing in the spec says anything about length.
  // Even though bech32 loses error correction power over 1023 characters.
  return orderKeys(data)
}

// decode will only have extra comments that aren't covered in encode comments.
// also if anything is hard to read I'll comment.
function decode (paymentRequest, network) {
  if (typeof paymentRequest !== 'string') throw new Error('Lightning Payment Request must be string')
  if (paymentRequest.slice(0, 2).toLowerCase() !== 'ln') throw new Error('Not a proper lightning payment request')
  const decoded = bech32.decode(paymentRequest, Number.MAX_SAFE_INTEGER)
  paymentRequest = paymentRequest.toLowerCase()
  const prefix = decoded.prefix
  let words = decoded.words

  // signature is always 104 words on the end
  // cutting off at the beginning helps since there's no way to tell
  // ahead of time how many tags there are.
  const sigWords = words.slice(-104)
  // grabbing a copy of the words for later, words will be sliced as we parse.
  const wordsNoSig = words.slice(0, -104)
  words = words.slice(0, -104)

  let sigBuffer = wordsToBuffer(sigWords, true)
  const recoveryFlag = sigBuffer.slice(-1)[0]
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
  if (prefixMatches && !prefixMatches[2]) prefixMatches = prefix.match(/^ln(\S+)$/)
  if (!prefixMatches) {
    throw new Error('Not a proper lightning payment request')
  }

  const bech32Prefix = prefixMatches[1]
  let coinNetwork
  if (!network) {
    switch (bech32Prefix) {
      case DEFAULTNETWORK.bech32:
        coinNetwork = DEFAULTNETWORK
        break
      case TESTNETWORK.bech32:
        coinNetwork = TESTNETWORK
        break
      case REGTESTNETWORK.bech32:
        coinNetwork = REGTESTNETWORK
        break
      case SIMNETWORK.bech32:
        coinNetwork = SIMNETWORK
        break
    }
  } else {
    if (
      network.bech32 === undefined ||
      network.pubKeyHash === undefined ||
      network.scriptHash === undefined ||
      !Array.isArray(network.validWitnessVersions)
    ) throw new Error('Invalid network')
    coinNetwork = network
  }
  if (!coinNetwork || coinNetwork.bech32 !== bech32Prefix) {
    throw new Error('Unknown coin bech32 prefix')
  }

  const value = prefixMatches[2]
  let satoshis, millisatoshis, removeSatoshis
  if (value) {
    const divisor = prefixMatches[3]
    try {
      satoshis = parseInt(hrpToSat(value + divisor, true))
    } catch (e) {
      satoshis = null
      removeSatoshis = true
    }
    millisatoshis = hrpToMillisat(value + divisor, true)
  } else {
    satoshis = null
    millisatoshis = null
  }

  // reminder: left padded 0 bits
  const timestamp = wordsToIntBE(words.slice(0, 7))
  const timestampString = new Date(timestamp * 1000).toISOString()
  words = words.slice(7) // trim off the left 7 words

  const tags = []
  let tagName, parser, tagLength, tagWords
  // we have no tag count to go on, so just keep hacking off words
  // until we have none.
  while (words.length > 0) {
    const tagCode = words[0].toString()
    tagName = TAGNAMES[tagCode] || unknownTagName
    parser = TAGPARSERS[tagCode] || getUnknownParser(tagCode)
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

  let timeExpireDate, timeExpireDateString
  // be kind and provide an absolute expiration date.
  // good for logs
  if (tagsContainItem(tags, TAGNAMES['6'])) {
    timeExpireDate = timestamp + tagsItems(tags, TAGNAMES['6'])
    timeExpireDateString = new Date(timeExpireDate * 1000).toISOString()
  }

  const toSign = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(convert(wordsNoSig, 5, 8))])
  const payReqHash = sha256(toSign)
  const sigPubkey = secp256k1.recover(payReqHash, sigBuffer, recoveryFlag, true)
  if (tagsContainItem(tags, TAGNAMES['19']) && tagsItems(tags, TAGNAMES['19']) !== sigPubkey.toString('hex')) {
    throw new Error('Lightning Payment Request signature pubkey does not match payee pubkey')
  }

  let finalResult = {
    paymentRequest,
    complete: true,
    prefix,
    wordsTemp: bech32.encode('temp', wordsNoSig.concat(sigWords), Number.MAX_SAFE_INTEGER),
    network: coinNetwork,
    satoshis,
    millisatoshis,
    timestamp,
    timestampString,
    payeeNodeKey: sigPubkey.toString('hex'),
    signature: sigBuffer.toString('hex'),
    recoveryFlag,
    tags
  }

  if (removeSatoshis) {
    delete finalResult.satoshis
  }

  if (timeExpireDate) {
    finalResult = Object.assign(finalResult, { timeExpireDate, timeExpireDateString })
  }

  return orderKeys(finalResult)
}

module.exports = {
  encode,
  decode,
  sign,
  satToHrp,
  millisatToHrp,
  hrpToSat,
  hrpToMillisat
}
