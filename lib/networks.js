'use strict';
var _ = require('lodash');

var BufferUtil = require('./util/buffer');
var JSUtil = require('./util/js');
var networks = [];
var networkMaps = {};

/**
 * A network is merely a map containing values that correspond to version
 * numbers for each bitcoin network. Currently only supporting "livenet"
 * (a.k.a. "mainnet") and "testnet".
 * @constructor
 */
function Network() {}

Network.prototype.toString = function toString() {
    return this.name;
};

/**
 * @function
 * @member Networks#get
 * Retrieves the network associated with a magic number or string.
 * @param {string|number|Network} arg
 * @param {string|Array} keys - if set, only check if the magic number associated with this name matches
 * @return Network
 */
function get(arg, keys) {
    if (~networks.indexOf(arg)) {
        return arg;
    }
    if (keys) {
        if (!_.isArray(keys)) {
            keys = [keys];
        }
        var containsArg = function(key) {
            return networks[index][key] === arg;
        };
        for (var index in networks) {
            if (_.some(keys, containsArg)) {
                return networks[index];
            }
        }
        return undefined;
    }
    return networkMaps[arg];
}


function addNetwork(data) {

    var network = new Network();

    JSUtil.defineImmutable(network, {
        name: data.name,
        alias: data.alias,
        pubkeyhash: data.pubkeyhash,
        privatekey: data.privatekey,
        scripthash: data.scripthash,
        xpubkey: data.xpubkey,
        xprivkey: data.xprivkey
    });

    if (data.networkMagic) {
        JSUtil.defineImmutable(network, {
            networkMagic: BufferUtil.integerAsBuffer(data.networkMagic)
        });
    }

    if (data.port) {
        JSUtil.defineImmutable(network, {
            port: data.port
        });
    }

    if (data.dnsSeeds) {
        JSUtil.defineImmutable(network, {
            dnsSeeds: data.dnsSeeds
        });
    }
    _.each(network, function(value) {
        if (!_.isUndefined(value) && !_.isObject(value)) {
            networkMaps[value] = network;
        }
    });

    networks.push(network);

    return network;

}

function removeNetwork(network) {
    for (var i = 0; i < networks.length; i++) {
        if (networks[i] === network) {
            networks.splice(i, 1);
        }
    }
    for (var key in networkMaps) {
        if (networkMaps[key] === network) {
            delete networkMaps[key];
        }
    }
}

addNetwork({
    name: 'livenet',
    alias: 'mainnet',
    pubkeyhash: 25,
    privatekey: 0x80,
    xpubkey: 0x0488b21e,
    xprivkey: 0x0488ade4,
});


var livenet = get('livenet');

addNetwork({
    name: 'testnet',
    alias: 'regtest',
    pubkeyhash: 64,
    privatekey: 0xef,
    xpubkey: 0x043587cf,
    xprivkey: 0x04358394
});

/**
 * @instance
 * @member Networks#testnet
 */
var testnet = get('testnet');


var TESTNET = {
    PORT: 18434,
    NETWORK_MAGIC: BufferUtil.integerAsBuffer(0x0b110907)
};

for (var key in TESTNET) {
    if (!_.isObject(TESTNET[key])) {
        networkMaps[TESTNET[key]] = testnet;
    }
}

var REGTEST = {
    PORT: 18525,
    NETWORK_MAGIC: BufferUtil.integerAsBuffer(0xfabfb5da),
    DNS_SEEDS: []
};

for (var key in REGTEST) {
    if (!_.isObject(REGTEST[key])) {
        networkMaps[REGTEST[key]] = testnet;
    }
}

Object.defineProperty(testnet, 'port', {
    enumerable: true,
    configurable: false,
    get: function() {
        if (this.regtestEnabled) {
            return REGTEST.PORT;
        } else {
            return TESTNET.PORT;
        }
    }
});

Object.defineProperty(testnet, 'networkMagic', {
    enumerable: true,
    configurable: false,
    get: function() {
        if (this.regtestEnabled) {
            return REGTEST.NETWORK_MAGIC;
        } else {
            return TESTNET.NETWORK_MAGIC;
        }
    }
});

Object.defineProperty(testnet, 'dnsSeeds', {
    enumerable: true,
    configurable: false,
    get: function() {
        if (this.regtestEnabled) {
            return REGTEST.DNS_SEEDS;
        } else {
            return TESTNET.DNS_SEEDS;
        }
    }
});


module.exports = {
    add: addNetwork,
    remove: removeNetwork,
    defaultNetwork: livenet,
    livenet: livenet,
    mainnet: livenet,
    testnet: testnet,
    get: get,
};