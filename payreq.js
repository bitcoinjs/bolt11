'use strict'

const bech32 = require('bech32')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const BigNumber = require('bn.js')

const MULTIPLIERS = {
  m: BigNumber('0.001'),
  u: BigNumber('0.000001'),
  n: BigNumber('0.000000001'),
  p: BigNumber('0.000000000001')
}

module.exports = () => {
  
  function encode (data) {
    
  }
  
  function decode (paymentRequest) {
    if (paymentRequest.slice(0,2) !== 'ln') throw new Error('Not a proper lightning payment request')
    let { prefix, words } = bech32.decode(paymentRequest, 1023)
    
    let coinType = prefix.slice(2,4)
    switch coinType {
      case 'bc':
        coinType = 'bitcoin'
        break
      case 'tb':
        coinType = 'tbitcoin'
        break
    }
    
    let value = prefix.slice(4)
    let valueInt
    let multiplier = value.slice(-1).match(/[munp]/) ? value.slice(-1) : null
    if (multiplier) {
      valueInt = parseInt(value.slice(0,-1))
    } else {
      valueInt = parseInt(value)
    }
    let satoshis = multiplier ? MULTIPLIERS[multiplier].mul(valueInt).mul(1e8).toNumber() : valueInt * 1e8
    
    let timestamp = Buffer.from(bech32.fromWords([0].concat(words.slice(0,7)))).readUIntBE(1,4)
    let timestampString = new Date(timestamp * 1000).toISOString()
    words = words.slice(7)
    
    
  }
  
  function decodeRaw (rawData) {
    
  }
}
