'use strict';


var assert = require('assert');
var buffer = require('buffer');
var _ = require('lodash');
var BN = require('./crypto/bn');
var Base58Check = require('./encoding/base58check');
var Hash = require('./crypto/hash');
var Network = require('./networks');
var PrivateKey = require('./privatekey');

var errors = require('./errors');
var hdErrors = errors.HDPrivateKey;
var BufferUtil = require('./util/buffer');
var JSUtil = require('./util/js');

var MINIMUM_ENTROPY_BITS = 128;
var BITS_TO_BYTES = 1 / 8;
var MAXIMUM_ENTROPY_BITS = 512;


/**
 * Represents an instance of an hierarchically derived private key.
 *
 * More info on https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * @constructor
 * @param {string|Buffer|Object} arg
 */
function HDPrivateKey(arg) {
    /* jshint maxcomplexity: 10 */
    if (arg instanceof HDPrivateKey) {
        return arg;
    }
    if (!(this instanceof HDPrivateKey)) {
        return new HDPrivateKey(arg);
    }
    if (!arg) {
        return this._generateRandomly();
    }

    if (Network.get(arg)) {
        return this._generateRandomly(arg);
    } else if (_.isString(arg) || BufferUtil.isBuffer(arg)) {
        if (HDPrivateKey.isValidSerialized(arg)) {
            this._buildFromSerialized(arg);
        } else if (JSUtil.isValidJSON(arg)) {
            this._buildFromJSON(arg);
        } else if (BufferUtil.isBuffer(arg) && HDPrivateKey.isValidSerialized(arg.toString())) {
            this._buildFromSerialized(arg.toString());
        } else {
            throw HDPrivateKey.getSerializedError(arg);
        }
    } else if (_.isObject(arg)) {
        this._buildFromObject(arg);
    } else {
        throw new hdErrors.UnrecognizedArgument(arg);
    }
}

HDPrivateKey.prototype._buildFromObject = function(arg) {
    /* jshint maxcomplexity: 12 */
    // TODO: Type validation
    var buffers = {
        version: arg.network ? BufferUtil.integerAsBuffer(Network.get(arg.network).xprivkey) : arg.version,
        depth: _.isNumber(arg.depth) ? BufferUtil.integerAsSingleByteBuffer(arg.depth) : arg.depth,
        parentFingerPrint: _.isNumber(arg.parentFingerPrint) ? BufferUtil.integerAsBuffer(arg.parentFingerPrint) : arg.parentFingerPrint,
        childIndex: _.isNumber(arg.childIndex) ? BufferUtil.integerAsBuffer(arg.childIndex) : arg.childIndex,
        chainCode: _.isString(arg.chainCode) ? BufferUtil.hexToBuffer(arg.chainCode) : arg.chainCode,
        privateKey: (_.isString(arg.privateKey) && JSUtil.isHexa(arg.privateKey)) ? BufferUtil.hexToBuffer(arg.privateKey) : arg.privateKey,
        checksum: arg.checksum ? (arg.checksum.length ? arg.checksum : BufferUtil.integerAsBuffer(arg.checksum)) : undefined
    };
    return this._buildFromBuffers(buffers);
};



/**
 * Generate a private key from a seed, as described in BIP32
 *
 * @param {string|Buffer} hexa
 * @param {*} network
 * @return HDPrivateKey
 */
HDPrivateKey.fromSeed = function(hexa, network) {
    /* jshint maxcomplexity: 8 */
    console.log("KLKSLLSLSLSLLSLSLSLSLSL???????????",hexa)
    if (JSUtil.isHexaString(hexa)) {
        hexa = BufferUtil.hexToBuffer(hexa);
    }
    if (!Buffer.isBuffer(hexa)) {
        throw new hdErrors.InvalidEntropyArgument(hexa);
    }
    if (hexa.length < MINIMUM_ENTROPY_BITS * BITS_TO_BYTES) {
        throw new hdErrors.InvalidEntropyArgument.NotEnoughEntropy(hexa);
    }
    if (hexa.length > MAXIMUM_ENTROPY_BITS * BITS_TO_BYTES) {
        throw new hdErrors.InvalidEntropyArgument.TooMuchEntropy(hexa);
    }
    var hash = Hash.sha512hmac(hexa, new buffer.Buffer('BAC seed'));
    console.log("livenet>>>>>>>>>>>>>>>>>>>",network,Network.defaultNetwork )
    return new HDPrivateKey({
        network: Network.get(network) || Network.defaultNetwork,
        depth: 0,
        parentFingerPrint: 0,
        childIndex: 0,
        privateKey: hash.slice(0, 32),
        chainCode: hash.slice(32, 64)
    });
};



HDPrivateKey.prototype._calcHDPublicKey = function() {
    if (!this._hdPublicKey) {
        var HDPublicKey = require('./hdpublickey');
        this._hdPublicKey = new HDPublicKey(this);
    }
};

/**
 * Receives a object with buffers in all the properties and populates the
 * internal structure
 *
 * @param {Object} arg
 * @param {buffer.Buffer} arg.version
 * @param {buffer.Buffer} arg.depth
 * @param {buffer.Buffer} arg.parentFingerPrint
 * @param {buffer.Buffer} arg.childIndex
 * @param {buffer.Buffer} arg.chainCode
 * @param {buffer.Buffer} arg.privateKey
 * @param {buffer.Buffer} arg.checksum
 * @param {string=} arg.xprivkey - if set, don't recalculate the base58
 *      representation
 * @return {HDPrivateKey} this
 */
HDPrivateKey.prototype._buildFromBuffers = function(arg) {
    /* jshint maxcomplexity: 8 */
    /* jshint maxstatements: 20 */

    HDPrivateKey._validateBufferArguments(arg);

    JSUtil.defineImmutable(this, {
        _buffers: arg
    });

    var sequence = [
        arg.version, arg.depth, arg.parentFingerPrint, arg.childIndex, arg.chainCode,
        BufferUtil.emptyBuffer(1), arg.privateKey
    ];
    var concat = buffer.Buffer.concat(sequence);
    if (!arg.checksum || !arg.checksum.length) {
        arg.checksum = Base58Check.checksum(concat);
    } else {
        if (arg.checksum.toString() !== Base58Check.checksum(concat).toString()) {
            throw new errors.InvalidB58Checksum(concat);
        }
    }

    var network = Network.get(BufferUtil.integerFromBuffer(arg.version));
    var xprivkey;
    xprivkey = Base58Check.encode(buffer.Buffer.concat(sequence));
    arg.xprivkey = Buffer.from(xprivkey);

    var privateKey = new PrivateKey(BN.fromBuffer(arg.privateKey), network);
    var publicKey = privateKey.toPublicKey();
    var size = HDPrivateKey.ParentFingerPrintSize;
    var fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).slice(0, size);

    JSUtil.defineImmutable(this, {
        xprivkey: xprivkey,
        network: network,
        depth: BufferUtil.integerFromSingleByteBuffer(arg.depth),
        privateKey: privateKey,
        publicKey: publicKey,
        fingerPrint: fingerPrint
    });

    this._hdPublicKey = null;

    Object.defineProperty(this, 'hdPublicKey', {
        configurable: false,
        enumerable: true,
        get: function() {
            this._calcHDPublicKey();
            return this._hdPublicKey;
        }
    });
    Object.defineProperty(this, 'xpubkey', {
        configurable: false,
        enumerable: true,
        get: function() {
            this._calcHDPublicKey();
            return this._hdPublicKey.xpubkey;
        }
    });
    return this;
};

HDPrivateKey._validateBufferArguments = function(arg) {
    var checkBuffer = function(name, size) {
        var buff = arg[name];
        assert(BufferUtil.isBuffer(buff), name + ' argument is not a buffer');
        assert(
            buff.length === size,
            name + ' has not the expected size: found ' + buff.length + ', expected ' + size
        );
    };
    checkBuffer('version', HDPrivateKey.VersionSize);
    checkBuffer('depth', HDPrivateKey.DepthSize);
    checkBuffer('parentFingerPrint', HDPrivateKey.ParentFingerPrintSize);
    checkBuffer('childIndex', HDPrivateKey.ChildIndexSize);
    checkBuffer('chainCode', HDPrivateKey.ChainCodeSize);
    checkBuffer('privateKey', HDPrivateKey.PrivateKeySize);
    if (arg.checksum && arg.checksum.length) {
        checkBuffer('checksum', HDPrivateKey.CheckSumSize);
    }
};

/**
 * Returns the string representation of this private key (a string starting
 * with "xprv..."
 *
 * @return string
 */
HDPrivateKey.prototype.toString = function() {
    return this.xprivkey;
};


HDPrivateKey.VersionSize = 4;
HDPrivateKey.DepthSize = 1;
HDPrivateKey.ParentFingerPrintSize = 4;
HDPrivateKey.ChildIndexSize = 4;
HDPrivateKey.ChainCodeSize = 32;
HDPrivateKey.PrivateKeySize = 32;
HDPrivateKey.CheckSumSize = 4;

HDPrivateKey.DataLength = 78;
HDPrivateKey.SerializedByteSize = 82;

module.exports = HDPrivateKey;