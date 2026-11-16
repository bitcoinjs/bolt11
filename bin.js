#!/usr/bin/env node

// Call bolt11 decode from the command line.

const decode = require('./payreq').decode

const [,, command, invoice] = process.argv

if (command !== 'decode') {
  throw new Error('Invalid command, expected "bolt11 decode <invoice>"')
}

const results = decode(invoice)

console.log(JSON.stringify(results, null, 2))

