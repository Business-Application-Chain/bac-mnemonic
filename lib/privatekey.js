'use strict';

var _ = require('lodash');
var BN = require('./crypto/bn');
var JSUtil = require('./util/js');
var Networks = require('./networks');
var Point = require('./crypto/point');
var PublicKey = require('./publickey');

var $ = require('./util/preconditions');


function PrivateKey(data, network) {

    if (!(this instanceof PrivateKey)) {
        return new PrivateKey(data, network);
    }
    if (data instanceof PrivateKey) {
        return data;
    }

    var info = this._classifyArguments(data, network);

    // validation
    if (!info.bn || info.bn.cmp(new BN(0)) === 0){
        throw new TypeError('Number can not be equal to zero, undefined, null or false');
    }
    if (!info.bn.lt(Point.getN())) {
        throw new TypeError('Number must be less than N');
    }
    if (typeof(info.network) === 'undefined') {
        throw new TypeError('Must specify the network ("livenet" or "testnet")');
    }

    JSUtil.defineImmutable(this, {
        bn: info.bn,
        compressed: info.compressed,
        network: info.network
    });

    Object.defineProperty(this, 'publicKey', {
        configurable: false,
        enumerable: true,
        get: this.toPublicKey.bind(this)
    });

    return this;

};

PrivateKey.prototype._classifyArguments = function(data, network) {
    /* jshint maxcomplexity: 10 */
    var info = {
        compressed: true,
        network: network ? Networks.get(network) : Networks.defaultNetwork
    };

    // detect type of data
    if (_.isUndefined(data) || _.isNull(data)){
        info.bn = PrivateKey._getRandomBN();
    } else if (data instanceof BN) {
        info.bn = data;
    } else if (data instanceof Buffer || data instanceof Uint8Array) {
        info = PrivateKey._transformBuffer(data, network);
    } else if (data.bn && data.network){
        info = PrivateKey._transformObject(data);
    } else if (!network && Networks.get(data)) {
        info.bn = PrivateKey._getRandomBN();
        info.network = Networks.get(data);
    } else if (typeof(data) === 'string'){
        if (JSUtil.isHexa(data)) {
            info.bn = new BN(Buffer.from(data, 'hex'));
        } else {
            info = PrivateKey._transformWIF(data, network);
        }
    } else {
        throw new TypeError('First argument is an unrecognized data type.');
    }
    return info;
};

PrivateKey.prototype.toString = function() {
    return this.toBuffer().toString('hex');
};

PrivateKey.prototype.toBuffer = function(){
    // TODO: use `return this.bn.toBuffer({ size: 32 })` in v1.0.0
    return this.bn.toBuffer();
};


PrivateKey.prototype.toPublicKey = function(){
    if (!this._pubkey) {
        this._pubkey = PublicKey.fromPrivateKey(this);
    }
    return this._pubkey;
};


PrivateKey.prototype.toAddress = function(network) {
    var pubkey = this.toPublicKey();
    return Address.fromPublicKey(pubkey, network || this.network);
};


module.exports = PrivateKey;