'use strict';

var BN = require('bn.js');
var crypto = require('crypto');
var unorm = require('unorm');
var pbkdf2 = require('./pbkdf2');
var HDPrivateKey = require('./hdprivatekey')

var Mnemonic = function() {
    if (!(this instanceof Mnemonic)) {
        return new Mnemonic();
    }

    var wordlist = Mnemonic.Words;
    var ent = 128;
    var phrase = Mnemonic._mnemonic(ent, wordlist);

    Object.defineProperty(this, 'wordlist', {
        configurable: false,
        value: wordlist
    });

    Object.defineProperty(this, 'phrase', {
        configurable: false,
        value: phrase
    });
};

Mnemonic.Words = require('./words.js');


/**
 * Will generate a seed based on the mnemonic and optional passphrase.
 *
 * @param {String} [passphrase]
 * @returns {Buffer}
 */
Mnemonic.prototype.toSeed = function(passphrase) {
    passphrase = passphrase || '';
    return pbkdf2(unorm.nfkd(this.phrase), unorm.nfkd('mnemonic' + passphrase), 2048, 64);
}

/**
 * Generates a HD Private Key from a Mnemonic
 * Optionally receive a passphrase and bitcoin network.
 *
 * @param {String=} [passphrase]
 * @param {Network|String|number=} [network] - The network: 'livenet' or 'testnet'
 * @returns {HDPrivateKey}
 */
Mnemonic.prototype.toHDPrivateKey = function(passphrase, network) {
    var seed = this.toSeed(passphrase);
    return HDPrivateKey.fromSeed(seed, network);
}

/**
 * Internal function to generate a random mnemonic
 *
 * @param {Number} ENT - Entropy size, defaults to 128
 * @param {Array} wordlist - Array of words to generate the mnemonic
 * @returns {String} Mnemonic string
 */
Mnemonic._mnemonic = function(ENT, wordlist) {
    var buf = crypto.randomBytes(ENT / 8);
    return Mnemonic._entropy2mnemonic(buf, wordlist);
}

/**
 * Internal function to generate mnemonic based on entropy
 *
 * @param {Number} entropy - Entropy buffer
 * @param {Array} wordlist - Array of words to generate the mnemonic
 * @returns {String} Mnemonic string
 */
Mnemonic._entropy2mnemonic = function(entropy, wordlist) {
    var bin = '';
    for (var i = 0; i < entropy.length; i++) {
        bin = bin + ('00000000' + entropy[i].toString(2)).slice(-8);
    }

    bin = bin + Mnemonic._entropyChecksum(entropy);

    if (bin.length % 11 !== 0) {
        return '';
    }
    var mnemonic = [];
    for (i = 0; i < bin.length / 11; i++) {
        var wi = parseInt(bin.slice(i * 11, (i + 1) * 11), 2);
        mnemonic.push(wordlist[wi]);
    }
    var ret;
    ret = mnemonic.join(' ');
    return ret;
}

/**
 * Internal function to create checksum of entropy
 *
 * @param entropy
 * @return {string} Checksum of entropy length / 32
 * @private
 */
Mnemonic._entropyChecksum = function(entropy) {
    var hash = crypto.createHash('sha256').update(entropy).digest();
    var bits = entropy.length * 8;
    var cs = bits / 32;

    var hashbits = new BN(hash.toString('hex'), 16).toString(2);

    // zero pad the hash bits
    while (hashbits.length % 256 !== 0) {
        hashbits = '0' + hashbits;
    }

    var checksum = hashbits.slice(0, cs);

    return checksum;
}

Mnemonic.prototype.toString = function() {
    return this.phrase;
};

module.exports = Mnemonic;
