
var bignum = require('bignum');
var rsa = require('./modules/rsa.js');


var bitslength = 256; // It must be more than 1028 o equal at least
var keys = rsa.generateKeys(bitslength);


var message = "Message to encrypt";
var m=bignum.fromBuffer(Buffer.from(message));
console.log("My message is: " +message+ " en bignum "+ m.toString());
console.log("Bignum of message: "+ m.toString());

//Encrypt and Decrypt
console.log("\n################ Encrypt and Decrypt a NUMBER ################");

var c = keys.publicKey.encrypt(m);
console.log("Encrypted c: "+ c.toString());
//Decrypt the message
var d = keys.privateKey.decrypt(c);
console.log("Decrypted d :" + d.toString());
console.log(bignum.toBuffer(d).toString());
if (message == bignum.toBuffer(d)){
  console.log("All works!!");
}


console.log("\n");
var m = bignum(2);
console.log("My message is: " + m.toString());

//Encrypt and Decrypt
console.log("\n################ Encrypt and Decrypt ################");

//Encrypt the message
var c = keys.publicKey.encrypt(m);
console.log("Encrypted c: "+ c.toString());
//Decrypt the message
var d = keys.privateKey.decrypt(c);
console.log("Decrypted d :" + d.toString());
if (m.toString() == d.toString()){
  console.log("All works!!");
}

// Blind and Verify
console.log("\n################ Blind and Verfy ################");
// Create a rundom number while the randome isn't a 1
do {
  r = bignum.rand(keys.publicKey.n);
} while(r <= 1)
//Blind the message
  var bm =   m.mul(r.powm(keys.publicKey.e, keys.publicKey.n)).mod(keys.publicKey.n);
  console.log("Blind message bm: "+ bm.toString());
//Sing the message
  var bs = keys.privateKey.sign(bm);
  console.log("Blind signature bs: "+ bs.toString());
//Do the revers of the message (This only can be did it by the user who write the message)
  var s = bs.mul(r.invertm(keys.publicKey.n)).mod(keys.publicKey.n);
  console.log("Message without blind: " + s.toString());
// Verify the signed message to see
  if (m == keys.publicKey.verify(s).toString() ){
    console.log("Verify corretly: My Message: " + keys.publicKey.verify(s).toString());
  }
