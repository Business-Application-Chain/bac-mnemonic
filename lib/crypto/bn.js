'use strict';

var BN = require('bn.js');

BN.Zero = new BN(0);
BN.One = new BN(1);
BN.Minus1 = new BN(-1);



BN.fromBuffer = function(buf, opts) {
    if (typeof opts !== 'undefined' && opts.endian === 'little') {
        buf = reversebuf(buf);
    }
    var hex = buf.toString('hex');
    var bn = new BN(hex, 16);
    return bn;
};


module.exports = BN;