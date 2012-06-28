var botan = require(__dirname + '/../build/Release/botan');
var should = require('should');

function concatenate(buffers) {
  if (!Array.isArray(buffers)) {
    buffers = Array.prototype.slice.call(arguments);
  }

  var buffersToConcatenate = [], length = 0;
  buffers.forEach(function (buffer) {
    if (buffer) {
      if (!Buffer.isBuffer(buffer)) {
        buffer = new Buffer(buffer);
      }
      length += buffer.length;
      buffersToConcatenate.push(buffer);
    }
  });

  var concatenatedBuffers = new Buffer(length), index = 0;
  buffersToConcatenate.forEach(function (buffer) {
    buffer.copy(concatenatedBuffers, index, 0, buffer.length);
    index += buffer.length;
  });

  return concatenatedBuffers;
}

describe('RSA key functions', function() {
  var publicKey1;
  var privateKey1;

  it('should generate an RSA key pair', function(done) {
    botan.generateKeys(2048, function(error, publicKey, privateKey) {
      should.not.exist(error);
      should.exist(publicKey);
      should.exist(privateKey);
      publicKey1 = publicKey;
      privateKey1 = privateKey;
      done();
    });
  });

  it('should generate a PEM encoded RSA public key', function(done) {
    publicKey1.toString(function(error, pem) {
      should.not.exist(error);
      should.exist(pem);
      pem.should.include('BEGIN PUBLIC KEY');
      done();
    });
  });

  it('should generate a PEM encoded RSA private key', function(done) {
    privateKey1.toString('test123', function(error, pem, salt, iv) {
      should.not.exist(error);
      should.exist(pem);
      should.exist(salt);
      should.exist(iv);
      done();
    });
  });

  it('should load a PEM encoded RSA public key', function(done) {
    publicKey1.toString(function(error, pem) {
      should.not.exist(error);
      should.exist(pem);
      botan.loadPublicKey(pem, function(error, publicKey) {
        should.not.exist(error);
        should.exist(publicKey);
        done();
      });
    });
  });

  it('should load a PEM encoded RSA private key', function(done) {
    privateKey1.toString('test123', function(error, pem, salt, iv) {
      should.not.exist(error);
      should.exist(pem);
      should.exist(salt);
      should.exist(iv);
      botan.loadPrivateKey(pem, salt, iv, 'test123', function(error, privateKey) {
        should.not.exist(error);
        should.exist(privateKey);
        done();
      });
    });
  });

  it('should load a PEM encoded RSA private key from buffer', function(done) {
    privateKey1.toString('test123', function(error, pem, salt, iv) {
      should.not.exist(error);
      should.exist(pem);
      should.exist(salt);
      should.exist(iv);
      botan.loadPrivateKey(new Buffer(pem), salt, iv, 'test123', function(error, privateKey) {
        should.not.exist(error);
        should.exist(privateKey);
        done();
      });
    });
  });

  it('should fail load a PEM encoded RSA private key I with incorrect passphrase', function(done) {
    privateKey1.toString('test123', function(error, pem, salt, iv) {
      should.not.exist(error);
      should.exist(pem);
      should.exist(salt);
      should.exist(iv);
      botan.loadPrivateKey(pem, salt, iv, 'wrong', function(error, privateKey) {
        should.not.exist(privateKey);
        should.exist(error);
        done();
      });
    });
  });

  it('should encrypt/decrypt with a public/private key pair', function(done) {
    var data = new Buffer("test message");
    publicKey1.encrypt(data, function(error, encryptedData) {
      should.not.exist(error);
      should.exist(encryptedData);
      privateKey1.decrypt(encryptedData, function(error, decryptedData) {
        should.not.exist(error);
        should.exist(decryptedData);
        should.exist(data.toString() == decryptedData);
        done();
      });
    });
  });

  it('should encrypt/decrypt with a public/private key pair loaded from PEMs', function(done) {
    publicKey1.toString(function(error, publicKeyPem) {
      should.not.exist(error);
      should.exist(publicKeyPem);
      privateKey1.toString('test', function(error, privateKeyPem, salt, iv) {
        should.not.exist(error);
        should.exist(privateKeyPem);
        should.exist(salt);
        should.exist(iv);
        botan.loadPublicKey(publicKeyPem, function(error, publicKey) {
          should.not.exist(error);
          should.exist(publicKey);
          var data = new Buffer("test message");
          publicKey.encrypt(data, function(error, encryptedData) {
            should.not.exist(error);
            should.exist(encryptedData);
            botan.loadPrivateKey(privateKeyPem, salt, iv, 'test', function(error, privateKey) {
              privateKey.decrypt(encryptedData, function(error, decryptedData) {
                should.not.exist(error);
                should.exist(decryptedData);
                should.exist(data.toString() == decryptedData);
                done();
              });
            });
          });
        });
      });
    });
  });

  var cipherKey;

  it('should initialise encryptor using AES-256/EAX with built-in MAC', function(done) {
    botan.generateRandomBytes('binary', 32, function(error, key) {
      cipherKey = key;
      botan.initialiseEncryptor(null, null, key, function(error, encryptor, iv) {
        should.not.exist(error);
        should.exist(encryptor);
        should.exist(iv);
        done();
      });
    });
  });

  var cipherIv;

  it('should initialise decryptor using AES-256/EAX with built-in MAC', function(done) {
    botan.generateRandomBytes('hex', 16, function(error, iv) {
      cipherIv = iv;
      botan.initialiseDecryptor(null, null, cipherKey, iv, function(error, decryptor) {
        should.not.exist(error);
        should.exist(decryptor);
        done();
      });
    });
  });

  it('should encrypt/decrypt using AES-256/EAX with built-in MAC', function(done) {
    botan.initialiseEncryptor(null, null, cipherKey, function(error, encryptor, iv) {
      should.not.exist(error);
      should.exist(encryptor);
      should.exist(iv);
      var data = new Buffer("test message");
      encryptor.update(data, null, null, function(error, encryptedData) {
        should.not.exist(error);
        encryptor.final(function(error, finalEncryptedData, mac) {
          should.not.exist(error);
          should.not.exist(mac);
          var encryptedBuffer = concatenate(encryptedData, finalEncryptedData);
          botan.initialiseDecryptor(null, null, cipherKey, iv, function(error, decryptor) {
            should.not.exist(error);
            should.exist(decryptor);
            decryptor.update(encryptedBuffer, null, null, function(error, decryptedData) {
              should.not.exist(error);
              decryptor.final(function(error, finalDecryptedData, mac) {
                should.not.exist(error);
                should.not.exist(mac);
                var decryptedBuffer = concatenate(decryptedData, finalDecryptedData);
                var decryptedDataString = decryptedBuffer.toString();
                console.log(decryptedDataString);
                data.toString().should.equal(decryptedDataString);
                done();
              });
            });
          });
        });
      });
    });
  });

  it('should encrypt/decrypt using AES-256/CTR-BE and produce HMAC(SHA-512)', function(done) {
    botan.initialiseEncryptor("AES-256/CTR-BE", "HMAC(SHA-512)", cipherKey, function(error, encryptor, iv) {
      should.not.exist(error);
      should.exist(encryptor);
      should.exist(iv);
      var data = new Buffer("test message");
      encryptor.update(data, null, null, function(error, encryptedData) {
        should.not.exist(error);
        encryptor.final(function(error, finalEncryptedData, mac) {
          should.not.exist(error);
          should.exist(mac);
          var encryptedBuffer = concatenate(encryptedData, finalEncryptedData);
          botan.initialiseDecryptor("AES-256/CTR-BE", "HMAC(SHA-512)", cipherKey, iv, function(error, decryptor) {
            should.not.exist(error);
            should.exist(decryptor);
            decryptor.update(encryptedBuffer, null, null, function(error, decryptedData) {
              should.not.exist(error);
              decryptor.final(function(error, finalDecryptedData, decryptedMac) {
                should.not.exist(error);
                should.exist(decryptedMac);
                mac.should.equal(decryptedMac);
                var decryptedBuffer = concatenate(decryptedData, finalDecryptedData);
                data.toString().should.equal(decryptedBuffer.toString());
                done();
              });
            });
          });
        });
      });
    });
  });
/*
  it('should fail to update encryptor with buffer that is too small', function(done) {
    botan.initialiseEncryptor(null, null, cipherKey, function(error, encryptor, iv) {
      should.not.exist(error);
      should.exist(encryptor);
      should.exist(iv);
      var data = new Buffer('test message');
      (function() { encryptor.update(data, 0, data.length + 10, function(error, encryptedData) {}); }).should.throw();
      done();
    });
  });

  it('should fail to update encryptor with buffer length that is too small based on position', function(done) {
    botan.initialiseEncryptor(null, null, cipherKey, function(error, encryptor, iv) {
      should.not.exist(error);
      should.exist(encryptor);
      should.exist(iv);
      var data = new Buffer('test message');
      (function() { encryptor.update(data, 10, data.length, function(error, encryptedData) {}); }).should.throw();
      done();
    });
  });

  it('should fail to update decryptor with buffer length that is too small', function(done) {
    botan.initialiseEncryptor(null, null, cipherKey, function(error, encryptor, iv) {
      should.not.exist(error);
      should.exist(encryptor);
      should.exist(iv);
      var data = new Buffer("test message");
      encryptor.update(data, 0, data.length, function(error, encryptedData) {
        should.not.exist(error);
        encryptor.final(function(error, finalEncryptedData, mac) {
          should.not.exist(error);
          should.not.exist(mac);
          botan.initialiseDecryptor(null, null, cipherKey, cipherIv, function(error, decryptor) {
            should.not.exist(error);
            should.exist(decryptor);
            var data = new Buffer('test message');
            (function() { decryptor.update(data, 0, data.length + 10, function(error, decryptedData) {}); }).should.throw();
            done();
          });
        });
      });
    });
  });

  it('should fail to update decryptor with buffer length that is too small based on position', function(done) {
    botan.initialiseEncryptor(null, null, cipherKey, function(error, encryptor, iv) {
      should.not.exist(error);
      should.exist(encryptor);
      should.exist(iv);
      var data = new Buffer("test message");
      encryptor.update(data, 0, data.length, function(error, encryptedData) {
        should.not.exist(error);
        encryptor.final(function(error, finalEncryptedData, mac) {
          should.not.exist(error);
          should.not.exist(mac);
          botan.initialiseDecryptor(null, null, cipherKey, cipherIv, function(error, decryptor) {
            should.not.exist(error);
            should.exist(decryptor);
            var data = new Buffer('test message');
            (function() { decryptor.update(data, 10, data.length, function(error, decryptedData) {}); }).should.throw();
            done();
          });
        });
      });
    });
  });

  var bytes1;
  var encrypted1;
  var iv1;

  it('should encrypt data using AES-256/EAX with built-in MAC', function(done) {
    botan.generateRandomBytes('binary', 8192, function(error, bytes) {
      bytes1 = bytes;
      botan.encrypt(null, null, cipherKey, bytes, function(error, encrypted, mac) {
        should.not.exist(error);
        should.exist(encrypted);
        should.not.exist(mac);
        encrypted1 = encrypted;
        done();
      });
    });
  });

  var bytes3;
  var bytes4;
  var encrypted3;

  it('should encrypt array data using AES-256/EAX with built-in MAC', function(done) {
    botan.generateRandomBytes('binary', 1024, function(error, bytes) {
      bytes3 = bytes;
      botan.generateRandomBytes('binary', 1024, function(error, bytes) {
        bytes4 = bytes;
        botan.encrypt(null, null, cipherKey, [bytes3, bytes4], function(error, encrypted, mac) {
          should.not.exist(error);
          should.exist(encrypted[0]);
          should.exist(encrypted[1]);
          should.not.exist(mac);
          encrypted3 = encrypted;
          done();
        });
      });
    });
  });

  it('should fail to encrypt data using unknown cipher type', function(done) {
    botan.encrypt("wendy", null, cipherKey, bytes1, function(error, encrypted, mac) {
      should.exist(error);
      done();
    });
  });

  it('should fail to encrypt data using unknown mac type', function(done) {
    botan.encrypt(null, "james", cipherKey, bytes1, function(error, encrypted, mac) {
      should.exist(error);
      done();
    });
  });

  it('should fail to encrypt data with short key', function(done) {
    botan.encrypt(null, null, "123", bytes1, function(error, encrypted, mac) {
      should.exist(error);
      done();
    });
  });

  it('should decrypt data using AES-256/EAX with built-in MAC', function(done) {
    botan.decrypt(null, null, cipherKey, encrypted1, function(error, decrypted, mac) {
      should.not.exist(error);
      should.exist(decrypted);
      should.not.exist(mac);
      decrypted.toString('hex').should.equal(bytes1.toString('hex'));
      done();
    });
  });

  it('should decrypt array data using AES-256/EAX with built-in MAC', function(done) {
    botan.decrypt(null, null, cipherKey, encrypted3, function(error, decrypted, mac) {
      should.not.exist(error);
      should.exist(decrypted[0]);
      should.exist(decrypted[1]);
      should.not.exist(mac);
      decrypted[0].toString('hex').should.equal(bytes3.toString('hex'));
      decrypted[1].toString('hex').should.equal(bytes4.toString('hex'));
      done();
    });
  });

  var encrypted2;
  var mac2;

  it('should encrypt data using AES-256/CBC and produce HMAC(SHA-512)', function(done) {
    botan.encrypt("AES-256/CBC", "HMAC(SHA-512)", cipherKey, bytes1, function(error, encrypted, mac) {
      should.not.exist(error);
      should.exist(encrypted);
      should.exist(mac);
      encrypted2 = encrypted;
      mac2 = mac;
      done();
    });
  });

  var encrypted4;
  var mac4;

  it('should encrypt array data using AES-256/CBC and produce HMAC(SHA-512)', function(done) {
    botan.encrypt("AES-256/CBC", "HMAC(SHA-512)", cipherKey, [bytes3, bytes4], function(error, encrypted, mac) {
      should.not.exist(error);
      should.exist(encrypted[0]);
      should.exist(encrypted[1]);
      should.exist(mac[0]);
      should.exist(mac[1]);
      encrypted4 = encrypted;
      mac4 = mac;
      done();
    });
  });

  it('should decrypt data using AES-256/CBC and produce HMAC(SHA-512)', function(done) {
    botan.decrypt("AES-256/CBC", "HMAC(SHA-512)", cipherKey, encrypted2, function(error, decrypted, mac) {
      should.not.exist(error);
      should.exist(decrypted);
      should.exist(mac);
      decrypted.toString('hex').should.equal(bytes1.toString('hex'));
      mac.should.equal(mac2);
      done();
    });
  });

  it('should decrypt array data using AES-256/CBC and produce HMAC(SHA-512)', function(done) {
    botan.decrypt("AES-256/CBC", "HMAC(SHA-512)", cipherKey, encrypted4, function(error, decrypted, mac) {
      should.not.exist(error);
      should.exist(decrypted[0]);
      should.exist(decrypted[1]);
      should.exist(mac[0]);
      should.exist(mac[1]);
      decrypted[0].toString('hex').should.equal(bytes3.toString('hex'));
      decrypted[1].toString('hex').should.equal(bytes4.toString('hex'));
      mac[0].should.equal(mac4[0]);
      mac[1].should.equal(mac4[1]);
      done();
    });
  });

  it('should fail to decrypt data with short key', function(done) {
    botan.decrypt(null, null, "123", bytes1, function(error, encrypted, mac) {
      should.exist(error);
      done();
    });
  });

});

describe('MAC functions', function() {
  var fullLengthSha1 = 'TL1kxNLUQhC9NC8yXw9JDDK5CUk=';
  var partialLengthSha1 = 'BtJxkfKVWdpxhDf6VIHSm2z8Iao=';
  var fullLengthSha256 = 'Xklb1ohc3QyF7sjSDP6qSdMOnJbfLg+qBnIxNQm0bO0=';
  var fullLengthSha512 = 'q7dQBCd4Eq9sn3UgHSA8fpxKkaheO5fDADKNjxd6AmBH9kwQVppd046fzxpp0NQSpnTjzoEQFwnADUli/2g7bA==';

  it('should generate a HMAC(SHA-1) from string with buffer key', function(done) {
    botan.generateMac('HMAC(SHA-1)', '1234567890', null, new Buffer('1234567890123456'), function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha1);
      done();
    });
  });

  it('should generate a HMAC(SHA-1) from string', function(done) {
    botan.generateMac('HMAC(SHA-1)', '1234567890', null, '1234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha1);
      done();
    });
  });

  it('should generate a HMAC(SHA-1) from buffer', function(done) {
    botan.generateMac('HMAC(SHA-1)', new Buffer('1234567890'), null, '1234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha1);
      done();
    });
  });

  it('should generate a HMAC(SHA-1) from string with specified length', function(done) {
    botan.generateMac('HMAC(SHA-1)', '1234567890', 8, '1234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(partialLengthSha1);
      done();
    });
  });

  it('should generate a HMAC(SHA-1) from buffer with specified length', function(done) {
    botan.generateMac('HMAC(SHA-1)', new Buffer('1234567890'), 8, '1234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(partialLengthSha1);
      done();
    });
  });

  it('should generate a HMAC(SHA-256) from string', function(done) {
    botan.generateMac('HMAC(SHA-256)', '1234567890', null, '12345678901234561234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha256);
      done();
    });
  });

  it('should generate a HMAC(SHA-256) from buffer', function(done) {
    botan.generateMac('HMAC(SHA-256)', new Buffer('1234567890'), null, '12345678901234561234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha256);
      done();
    });
  });

  it('should generate a HMAC(SHA-512) from string', function(done) {
    botan.generateMac('HMAC(SHA-512)', '1234567890', null, '1234567890123456123456789012345612345678901234561234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha512);
      done();
    });
  });

  it('should generate a HMAC(SHA-512) from buffer', function(done) {
    botan.generateMac('HMAC(SHA-512)', new Buffer('1234567890'), null, '1234567890123456123456789012345612345678901234561234567890123456', function(error, mac) {
      should.not.exist(error);
      should.exist(mac);
      mac.should.equal(fullLengthSha512);
      done();
    });
  });

});

describe('Hash functions', function() {

  it('should generate a SHA-512 hash with complete buffer', function(done) {
    botan.initialiseHash('SHA-512', function(error, hash) {
      should.not.exist(error);
      should.exist(hash);
      var buffer = new Buffer(100);
      buffer.write('test data');
      hash.update(buffer, 9, function(error) {
        should.not.exist(error);
        hash.final(function(error, hash) {
          should.not.exist(error);
          hash.should.equal('Dh4h7PEF7IU9JNcohnrXBhPCFmOkaTB0sqNhnBvTnWa1iMM3I7tGbHJCToDjymPCSQeKs0e6uUKFAOfuQwWdDQ==');
          done();
        });
      });
    });
  });

  it('should generate a SHA-256 hash with complete buffer', function(done) {
    botan.initialiseHash('SHA-256', function(error, hash) {
      should.not.exist(error);
      should.exist(hash);
      var buffer = new Buffer(100);
      buffer.write('test data');
      hash.update(buffer, 9, function(error) {
        should.not.exist(error);
        hash.final(function(error, hash) {
          should.not.exist(error);
          hash.should.equal('kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk=');
          done();
        });
      });
    });
  });

  it('should generate a SHA-512 hash with string', function(done) {
    botan.initialiseHash('SHA-512', function(error, hash) {
      should.not.exist(error);
      should.exist(hash);
      hash.update('test data', 9, function(error) {
        should.not.exist(error);
        hash.final(function(error, hash) {
          should.not.exist(error);
          hash.should.equal('Dh4h7PEF7IU9JNcohnrXBhPCFmOkaTB0sqNhnBvTnWa1iMM3I7tGbHJCToDjymPCSQeKs0e6uUKFAOfuQwWdDQ==');
          done();
        });
      });
    });
  });

  it('should generate a SHA-256 hash with string', function(done) {
    botan.initialiseHash('SHA-256', function(error, hash) {
      should.not.exist(error);
      should.exist(hash);
      hash.update('test data', 9, function(error) {
        should.not.exist(error);
        hash.final(function(error, hash) {
          should.not.exist(error);
          hash.should.equal('kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk=');
          done();
        });
      });
    });
  });

});

describe('PBKDF functions', function() {
  var ITERATIONS = 30000;
  var salt1;
  var derivedKey1;

  it('should generate a derived key (with salt) for supplied passphrase', function(done) {
    botan.generatePbkdf('PBKDF2(SHA-512)', 'test123', null, ITERATIONS, function(error, derivedKey, salt) {
      should.not.exist(error);
      should.exist(derivedKey);
      should.exist(salt);
      derivedKey1 = derivedKey;
      salt1 = salt;
      done();
    });
  });

  it('should generate a derived key for supplied password and salt', function(done) {
    botan.generatePbkdf('PBKDF2(SHA-512)', 'test123', salt1, ITERATIONS, function(error, derivedKey, salt) {
      should.not.exist(error);
      should.exist(derivedKey);
      derivedKey.should.equal(derivedKey1);
      done();
    });
  });

});

describe('Codec functions', function() {

  it('should encode base64 synchronously', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      var encoding = botan.encodeSync('base64', bytes);
      should.exist(encoding);
      done();
    });
  });

  it('should encode base64', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      botan.encode('base64', bytes, function(error, encoding) {
        should.not.exist(error);
        should.exist(encoding);
        done();
      });
    });
  });

  it('should encode hex synchronously', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      var encoding = botan.encodeSync('hex', bytes);
      should.exist(encoding);
      done();
    });
  });

  it('should encode hex', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      botan.encode('hex', bytes, function(error, encoding) {
        should.not.exist(error);
        should.exist(encoding);
        done();
      });
    });
  });

  it('should fail to encode into unsupported codec', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      (function() { botan.encode('myrhh', bytes, function(error, encoding) {}); }).should.throw();
      done();
    });
  });

  it('should decode base64 synchronously', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      var encoding = botan.encodeSync('base64', bytes);
      should.exist(encoding);
      var decoding = botan.decodeSync('base64', encoding);
      should.exist(decoding);
      bytes.toString('base64').should.equal(decoding.toString('base64'));
      done();
    });
  });

  it('should decode base64', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      botan.encode('base64', bytes, function(error, encoding) {
        should.not.exist(error);
        should.exist(encoding);
        botan.decode('base64', encoding, function(error, decoding) {
          should.not.exist(error);
          should.exist(decoding);
          bytes.toString('base64').should.equal(decoding.toString('base64'));
          done();
        });
      });
    });
  });

  it('should decode hex synchronously', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      var encoding = botan.encodeSync('hex', bytes);
      should.exist(encoding);
      var decoding = botan.decodeSync('hex', encoding);
      should.exist(decoding);
      bytes.toString('hex').should.equal(decoding.toString('hex'));
      done();
    });
  });

  it('should decode hex', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      botan.encode('hex', bytes, function(error, encoding) {
        should.not.exist(error);
        should.exist(encoding);
        botan.decode('hex', encoding, function(error, decoding) {
          should.not.exist(error);
          should.exist(decoding);
          bytes.toString('hex').should.equal(decoding.toString('hex'));
          done();
        });
      });
    });
  });

  it('should fail to decode unsupported codec', function(done) {
    (function() { botan.decode('myrhh', 'gold', function(error, decoding) {}); }).should.throw();
    done();
  });

});

describe('Random functions', function() {

  it('should generate 4 digits', function(done) {
    botan.generateRandomDigits(4, function(error, digits) {
      should.not.exist(error);
      should.exist(digits);
      digits.length.should.equal(4);
      done();
    });
  });

  it('should generate 8 digits', function(done) {
    botan.generateRandomDigits(8, function(error, digits) {
      should.not.exist(error);
      should.exist(digits);
      digits.length.should.equal(8);
      done();
    });
  });

  it('should fail to generate 0 bytes', function(done) {
    (function() { botan.generateRandomDigits(0, function(error, bytes) {}); }).should.throw();
    done();
  });

  it('should generate 20 bytes in binary', function(done) {
    botan.generateRandomBytes('binary', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      bytes.length.should.equal(20);
      done();
    });
  });

  base64Length = function(bytes) {
    return (bytes + 2 - ((bytes + 2) % 3)) / 3 * 4;
  };

  it('should generate 20 bytes in base64', function(done) {
    botan.generateRandomBytes('base64', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      bytes.length.should.equal(base64Length(20));
      done();
    });
  });

  it('should generate 20 bytes in hex', function(done) {
    botan.generateRandomBytes('hex', 20, function(error, bytes) {
      should.not.exist(error);
      should.exist(bytes);
      bytes.length.should.equal(40);
      done();
    });
  });

  it('should fail to generate 0 bytes', function(done) {
    (function() { botan.generateRandomBytes('binary', 0, function(error, bytes) {}); }).should.throw();
    done();
  });

  it('should fail to generate 20 bytes of unsupported encoding', function(done) {
    (function() { botan.generateRandomBytes('myrhh', 20, function(error, bytes) {}); }).should.throw();
    done();
  });
*/
});
