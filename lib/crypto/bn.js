'use strict';

var BN = require('bn.js');
var $ = require('../util/preconditions');

var reversebuf = function (buf) {
    var buf2 = new Buffer(buf.length);
    for (var i = 0; i < buf.length; i++) {
        buf2[i] = buf[buf.length - 1 - i];
    }
    return buf2;
};

BN.Zero = new BN(0);
BN.One = new BN(1);
BN.Minus1 = new BN(-1);

BN.Zero = new BN(0);
BN.One = new BN(1);
BN.Minus1 = new BN(-1);


BN.fromBuffer = function (buf, opts) {
    if (typeof opts !== 'undefined' && opts.endian === 'little') {
        buf = reversebuf(buf);
    }
    var hex = buf.toString('hex');
    var bn = new BN(hex, 16);
    return bn;
};

BN.prototype.toBuffer = function (opts) {
    var buf, hex;
    if (opts && opts.size) {
        hex = this.toString(16, 2);
        var natlen = hex.length / 2;
        buf = new Buffer(hex, 'hex');

        if (natlen === opts.size) {
            buf = buf;
        } else if (natlen > opts.size) {
            buf = BN.trim(buf, natlen);
        } else if (natlen < opts.size) {
            buf = BN.pad(buf, natlen, opts.size);
        }
    } else {
        hex = this.toString(16, 2);
        buf = new Buffer(hex, 'hex');
    }

    if (typeof opts !== 'undefined' && opts.endian === 'little') {
        buf = reversebuf(buf);
    }

    return buf;
};

BN.pad = function (buf, natlen, size) {
    var rbuf = new Buffer(size);
    for (var i = 0; i < buf.length; i++) {
        rbuf[rbuf.length - 1 - i] = buf[buf.length - 1 - i];
    }
    for (i = 0; i < size - natlen; i++) {
        rbuf[i] = 0;
    }
    return rbuf;
};

BN.trim = function (buf, natlen) {
    return buf.slice(natlen - buf.length, buf.length);
};


module.exports = BN;