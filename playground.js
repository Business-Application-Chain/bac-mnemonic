 var Mnemonic = require('./lib/mnemonic');


let mnemonic = new Mnemonic();
let a = mnemonic.toHDPrivateKey('');
let priKey = a.privateKey.toString('hex');
let pubKey = a.publicKey.toString('hex');
let addr = a.publicKey.toAddress().toString('hex');

console.log("助记词 -》",mnemonic.toString());
console.log("私钥 -> " + priKey);
console.log("公钥 -> " + pubKey);
console.log("地址 -> " + addr);