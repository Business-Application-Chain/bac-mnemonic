'use strict';

var Point = require('./crypto/point');
var JSUtil = require('./util/js');
var Network = require('./networks');
var _ = require('lodash');
var $ = require('./util/preconditions');

function PublicKey(data, extra) {

    if (!(this instanceof PublicKey)) {
        return new PublicKey(data, extra);
    }

    $.checkArgument(data, 'First argument is required, please include public key data.');

    if (data instanceof PublicKey) {
        // Return copy, but as it's an immutable object, return same argument
        return data;
    }
    extra = extra || {};

    var info = this._classifyArgs(data, extra);

    // validation
    info.point.validate();

    JSUtil.defineImmutable(this, {
        point: info.point,
        compressed: info.compressed,
        network: info.network || Network.defaultNetwork
    });

    return this;
};

PublicKey.prototype._classifyArgs = function(data, extra) {
    /* jshint maxcomplexity: 10 */
    var info = {
        compressed: _.isUndefined(extra.compressed) || extra.compressed
    };

    // detect type of data
    if (data instanceof Point) {
        info.point = data;
    } else if (data.x && data.y) {
        info = PublicKey._transformObject(data);
    } else if (typeof(data) === 'string') {
        info = PublicKey._transformDER(Buffer.from(data, 'hex'));
    } else if (PublicKey._isBuffer(data)) {
        info = PublicKey._transformDER(data);
    } else if (PublicKey._isPrivateKey(data)) {
        info = PublicKey._transformPrivateKey(data);
    } else {
        throw new TypeError('First argument is an unrecognized data format.');
    }
    if (!info.network) {
        info.network = _.isUndefined(extra.network) ? undefined : Network.get(extra.network);
    }
    return info;
};

PublicKey._isPrivateKey = function(param) {
    var PrivateKey = require('./privatekey');
    return param instanceof PrivateKey;
};

PublicKey._transformPrivateKey = function(privkey) {
    $.checkArgument(PublicKey._isPrivateKey(privkey), 'Must be an instance of PrivateKey');
    var info = {};
    info.point = Point.getG().mul(privkey.bn);
    info.compressed = privkey.compressed;
    info.network = privkey.network;
    return info;
};

PublicKey.fromPrivateKey = function(privkey) {
    $.checkArgument(PublicKey._isPrivateKey(privkey), 'Must be an instance of PrivateKey');
    var info = PublicKey._transformPrivateKey(privkey);
    return new PublicKey(info.point, {
        compressed: info.compressed,
        network: info.network
    });
};

PublicKey.prototype.toBuffer = PublicKey.prototype.toDER = function() {
    var x = this.point.getX();
    var y = this.point.getY();
    var xbuf = x.toBuffer({
        size: 32
    });
    var ybuf = y.toBuffer({
        size: 32
    });

    var prefix;
    if (!this.compressed) {
        prefix = Buffer.from([0x04]);
        return Buffer.concat([prefix, xbuf, ybuf]);
    } else {
        var odd = ybuf[ybuf.length - 1] % 2;
        if (odd) {
            prefix = Buffer.from([0x03]);
        } else {
            prefix = Buffer.from([0x02]);
        }
        return Buffer.concat([prefix, xbuf]);
    }
};

PublicKey.prototype.toAddress = function(network) {
    var Address = require('./address');
    return Address.fromPublicKey(this, network || this.network);
};

PublicKey.prototype.toString = function() {
    return this.toDER().toString('hex');
};

module.exports = PublicKey;