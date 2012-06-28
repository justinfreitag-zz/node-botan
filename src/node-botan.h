#ifndef __NODE_BOTAN_H__
#define __NODE_BOTAN_H__

#include <node.h>
#include <v8.h>

#include <string>
#include <botan/botan.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>

namespace node_botan {

class Baton {
  public:
    v8::Persistent<v8::Function> callback;
    std::string *error;

    Baton(v8::Local<v8::Value> callback) {
      this->callback =
        v8::Persistent<v8::Function>::New(v8::Local<v8::Function>::Cast(callback));
      error = NULL;
    }

    ~Baton() {
      callback.Dispose();
      delete error;
    }
};

namespace pk {

  static const size_t DEFAULT_KEY_SIZE = 2048;

  static v8::Handle<v8::Value> Generate(const v8::Arguments &args);
  static void DoingGenerate(uv_work_t *request);
  static void AfterGenerate(uv_work_t *request);

  class GenerateBaton : public Baton {
    public:
      size_t keySize;
      Botan::RSA_PublicKey *publicKey;
      Botan::RSA_PrivateKey *privateKey;

      GenerateBaton(v8::Local<v8::Value> callback) : Baton(callback) {}
  };

  static v8::Handle<v8::Value> LoadPublicKey(const v8::Arguments &args);
  static void DoingLoadPublicKey(uv_work_t *request);
  static void AfterLoadPublicKey(uv_work_t *request);

  class LoadPublicKeyBaton : public Baton {
    public:
      std::string *publicKeyString;
      Botan::RSA_PublicKey *publicKey;

      LoadPublicKeyBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        publicKeyString = NULL;
      }

      ~LoadPublicKeyBaton() {
        delete publicKeyString;
      }
  };

  class PublicKey : public node::ObjectWrap {
    public:
      PublicKey(v8::Handle<v8::Object> target, Botan::RSA_PublicKey *publicKey);

    protected:
      static v8::Handle<v8::Value> Encrypt(const v8::Arguments &args);
      static void DoingEncrypt(uv_work_t *request);
      static void AfterEncrypt(uv_work_t *request);

      static v8::Handle<v8::Value> ToString(const v8::Arguments &args);
      static void DoingToString(uv_work_t *request);
      static void AfterToString(uv_work_t *request);

    private:
      ~PublicKey();
      Botan::RSA_PublicKey *publicKey;
  };

  class PublicKeyEncryptBaton : public Baton {
    public:
      Botan::RSA_PublicKey* publicKey;
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::MemoryRegion<Botan::byte> *out;

      PublicKeyEncryptBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
        out = NULL;
      }

      ~PublicKeyEncryptBaton() {
        delete in;
        delete out;
      }
  };

  class PublicKeyToStringBaton : public Baton {
    public:
      Botan::RSA_PublicKey *publicKey;
      std::string *publicKeyString;

      PublicKeyToStringBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        publicKeyString = NULL;
      }

      ~PublicKeyToStringBaton() {
        delete publicKeyString;
      }
  };

  static const std::string PBKDF_TYPE = "PBKDF2(SHA-256)";
  static const size_t IV_SIZE = 16;
  static const size_t PBKDF_SIZE = 32;
  static const uint32_t PBKDF_ITERATIONS = 50000;
  static const std::string CIPHER_TYPE = "AES-256/EAX";

  static v8::Handle<v8::Value> LoadPrivateKey(const v8::Arguments &args);
  static void DoingLoadPrivateKey(uv_work_t *request);
  static void AfterLoadPrivateKey(uv_work_t *request);

  class LoadPrivateKeyBaton : public Baton {
    public:
      Botan::OctetString *privateKeyString;
      std::string *salt;
      std::string *iv;
      std::string *passphrase;
      Botan::RSA_PrivateKey *privateKey;

      LoadPrivateKeyBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        privateKeyString = NULL;
        salt = NULL;
        iv = NULL;
        passphrase = NULL;
      }

      ~LoadPrivateKeyBaton() {
        delete privateKeyString;
        delete salt;
        delete iv;
        delete passphrase;
      }
  };

  static const std::string PADDING_TYPE = "EME1(SHA-512)";

  class PrivateKey : public node::ObjectWrap {
    public:
      PrivateKey(v8::Handle<v8::Object> target, Botan::RSA_PrivateKey *privateKey);

    protected:
      static v8::Handle<v8::Value> Decrypt(const v8::Arguments &args);
      static void DoingDecrypt(uv_work_t *request);
      static void AfterDecrypt(uv_work_t *request);

      static v8::Handle<v8::Value> ToString(const v8::Arguments &args);
      static void DoingToString(uv_work_t *request);
      static void AfterToString(uv_work_t *request);

    private:
      ~PrivateKey();
      Botan::RSA_PrivateKey *privateKey;
  };

  class PrivateKeyDecryptBaton : public Baton {
    public:
      Botan::RSA_PrivateKey *privateKey;
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::MemoryRegion<Botan::byte> *out;

      PrivateKeyDecryptBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
        out = NULL;
      }

      ~PrivateKeyDecryptBaton() {
        delete in;
        delete out;
      }
  };

  class PrivateKeyToStringBaton : public Baton {
    public:
      Botan::RSA_PrivateKey *privateKey;
      std::string *privateKeyString;
      std::string *salt;
      std::string *iv;
      std::string *passphrase;

      PrivateKeyToStringBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        privateKeyString = NULL;
        salt = NULL;
        iv = NULL;
        passphrase = NULL;
      }

      ~PrivateKeyToStringBaton() {
        delete privateKeyString;
        delete salt;
        delete iv;
        delete passphrase;
      }
  };

}

#define BASE64_LENGTH(length) \
    ((length - 1) / 3) * 4 + 4

namespace cipher {

  static const size_t IV_SIZE = 16;
  static const size_t IV_SIZE_BASE64 = BASE64_LENGTH(IV_SIZE);
  static const std::string IV_MAC_TYPE = "HMAC(SHA-256)";

  static v8::Handle<v8::Value> Encrypt(const v8::Arguments &args);
  static void DoingEncrypt(uv_work_t *request);
  static void AfterEncrypt(uv_work_t *request);

  class EncryptBaton : public Baton {
    public:
      std::string *cipherType;
      std::string *macType;
      Botan::SecureVector<Botan::byte> **in;
      size_t inLength;
      std::string **out;
      Botan::OctetString *key;
      std::string *keyString;
      std::string **mac;

      EncryptBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        cipherType = NULL;
        macType = NULL;
        in = NULL;
        out = NULL;
        key = NULL;
        keyString = NULL;
        mac = NULL;
      }

      ~EncryptBaton() {
        delete cipherType;
        delete macType;
        if (in) {
          size_t i = 0;
          for (; i < inLength; i++) delete in[i];
          delete[] in;
        }
        if (out) {
          size_t i = 0;
          for (; i < inLength; i++) delete out[i];
          delete[] out;
        }
        delete key;
        delete keyString;
        if (mac) {
          size_t i = 0;
          for (; i < inLength; i++) delete mac[i];
          delete[] mac;
        }
      }
  };

  static v8::Handle<v8::Value> Decrypt(const v8::Arguments &args);
  static void DoingDecrypt(uv_work_t *request);
  static void AfterDecrypt(uv_work_t *request);

  class DecryptBaton : public Baton {
    public:
      std::string *cipherType;
      std::string *macType;
      Botan::SecureVector<Botan::byte> **in;
      size_t inLength;
      Botan::SecureVector<Botan::byte> **out;
      Botan::OctetString *key;
      std::string *keyString;
      std::string **mac;

      DecryptBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        cipherType = NULL;
        macType = NULL;
        in = NULL;
        out = NULL;
        key = NULL;
        keyString = NULL;
        mac = NULL;
      }

      ~DecryptBaton() {
        delete cipherType;
        delete macType;
        if (in) {
          size_t i = 0;
          for (; i < inLength; i++) delete in[i];
          delete[] in;
        }
        if (out) {
          size_t i = 0;
          for (; i < inLength; i++) delete out[i];
          delete[] out;
        }
        delete key;
        delete keyString;
        if (mac) {
          size_t i = 0;
          for (; i < inLength; i++) delete mac[i];
          delete[] mac;
        }
      }
  };

  static v8::Handle<v8::Value> InitialiseEncryptor(const v8::Arguments &args);
  static void DoingInitialiseEncryptor(uv_work_t *request);
  static void AfterInitialiseEncryptor(uv_work_t *request);

  static const std::string DEFAULT_CIPHER_TYPE = "AES-256/EAX";

  class InitialiseEncryptorBaton : public Baton {
    public:
      std::string *cipherType;
      std::string *macType;
      std::string *keyString;
      Botan::MemoryRegion<Botan::byte> *key;
      std::string *iv;
      Botan::Pipe *pipe;

      InitialiseEncryptorBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        cipherType = NULL;
        macType = NULL;
        keyString = NULL;
        key = NULL;
        iv = NULL;
      }

      ~InitialiseEncryptorBaton() {
        delete cipherType;
        delete macType;
        delete keyString;
        delete key;
        delete iv;
      }
  };

  class Encryptor : public node::ObjectWrap {
    public:
      Encryptor(v8::Handle<v8::Object> target, Botan::Pipe *pipe);

    protected:
      static v8::Handle<v8::Value> Update(const v8::Arguments &args);
      static void DoingUpdate(uv_work_t *request);
      static void AfterUpdate(uv_work_t *request);

      static v8::Handle<v8::Value> Final(const v8::Arguments &args);
      static void DoingFinal(uv_work_t *request);
      static void AfterFinal(uv_work_t *request);

    private:
      ~Encryptor();
      Botan::Pipe *pipe;
  };

  class EncryptorUpdateBaton : public Baton {
    public:
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::MemoryRegion<Botan::byte> *out;
      Botan::Pipe *pipe;

      EncryptorUpdateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
        out = NULL;
      }

      ~EncryptorUpdateBaton() {
        delete in;
        delete out;
      }
  };

  class EncryptorFinalBaton : public Baton {
    public:
      Botan::MemoryRegion<Botan::byte> *out;
      std::string *mac;
      Botan::Pipe *pipe;

      EncryptorFinalBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        out = NULL;
        mac = NULL;
      }

      ~EncryptorFinalBaton() {
        delete out;
        delete mac;
      }
  };

  static v8::Handle<v8::Value> InitialiseDecryptor(const v8::Arguments &args);
  static void DoingInitialiseDecryptor(uv_work_t *request);
  static void AfterInitialiseDecryptor(uv_work_t *request);

  class InitialiseDecryptorBaton : public Baton {
    public:
      std::string *cipherType;
      std::string *macType;
      std::string *keyString;
      Botan::MemoryRegion<Botan::byte> *key;
      Botan::MemoryRegion<Botan::byte> *iv;
      Botan::Pipe *pipe;

      InitialiseDecryptorBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        cipherType = NULL;
        macType = NULL;
        keyString = NULL;
        key = NULL;
        iv = NULL;
      }

      ~InitialiseDecryptorBaton() {
        delete cipherType;
        delete macType;
        delete keyString;
        delete key;
        delete iv;
      }
  };

  class Decryptor : public node::ObjectWrap {
    public:
      Decryptor(v8::Handle<v8::Object> target, Botan::Pipe *pipe);

    protected:
      static v8::Handle<v8::Value> Update(const v8::Arguments &args);
      static void DoingUpdate(uv_work_t *request);
      static void AfterUpdate(uv_work_t *request);

      static v8::Handle<v8::Value> Final(const v8::Arguments &args);
      static void DoingFinal(uv_work_t *request);
      static void AfterFinal(uv_work_t *request);

    private:
      ~Decryptor();
      Botan::Pipe *pipe;
  };

  class DecryptorUpdateBaton : public Baton {
    public:
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::MemoryRegion<Botan::byte> *out;
      Botan::Pipe *pipe;

      DecryptorUpdateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
        out = NULL;
      }

      ~DecryptorUpdateBaton() {
        delete in;
        delete out;
      }
  };

  class DecryptorFinalBaton : public Baton {
    public:
      Botan::MemoryRegion<Botan::byte> *out;
      std::string *mac;
      Botan::Pipe *pipe;

      DecryptorFinalBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        out = NULL;
        mac = NULL;
      }

      ~DecryptorFinalBaton() {
        delete out;
        delete mac;
      }
  };

}

namespace codec {

  enum Type { base64, hex };

  static v8::Handle<v8::Value> EncodeSync(const v8::Arguments &args);

  static v8::Handle<v8::Value> Encode(const v8::Arguments &args);
  static void DoingEncode(uv_work_t *request);
  static void AfterEncode(uv_work_t *request);

  class EncodeBaton : public Baton {
    public:
      Type type;
      Botan::MemoryRegion<Botan::byte> *in;
      std::string *out;

      EncodeBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
        out = NULL;
      }

      ~EncodeBaton() {
        delete in;
        delete out;
      }
  };

  static v8::Handle<v8::Value> DecodeSync(const v8::Arguments &args);

  static v8::Handle<v8::Value> Decode(const v8::Arguments &args);
  static void DoingDecode(uv_work_t *request);
  static void AfterDecode(uv_work_t *request);

  class DecodeBaton : public Baton {
    public:
      Type type;
      std::string *in;
      Botan::MemoryRegion<Botan::byte> *out;

      DecodeBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
        out = NULL;
      }

      ~DecodeBaton() {
        delete in;
        delete out;
      }
  };

}

namespace mac {

  static v8::Handle<v8::Value> Generate(const v8::Arguments &args);
  static void DoingGenerate(uv_work_t *request);
  static void AfterGenerate(uv_work_t *request);

  class GenerateBaton : public Baton {
    public:
      std::string *type;
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::OctetString *key;
      std::string *mac;

      GenerateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        type = NULL;
        in = NULL;
        key = NULL;
        mac = NULL;
      }

      ~GenerateBaton() {
        delete type;
        delete in;
        delete key;
        delete mac;
      }
  };

  static v8::Handle<v8::Value> Initialise(const v8::Arguments &args);
  static void DoingInitialise(uv_work_t *request);
  static void AfterInitialise(uv_work_t *request);

  class InitialiseBaton : public Baton {
    public:
      std::string *type;
      Botan::OctetString *key;
      Botan::Pipe *pipe;

      InitialiseBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        type = NULL;
        key = NULL;
      }

      ~InitialiseBaton() {
        delete type;
        delete key;
      }
  };

  class Mac : public node::ObjectWrap {
    public:
      Mac(v8::Local<v8::Object> target, Botan::Pipe *pipe);

    protected:
      static v8::Handle<v8::Value> Update(const v8::Arguments &args);
      static void DoingUpdate(uv_work_t *request);
      static void AfterUpdate(uv_work_t *request);

      static v8::Handle<v8::Value> Final(const v8::Arguments &args);
      static void DoingFinal(uv_work_t *request);
      static void AfterFinal(uv_work_t *request);

    private:
      ~Mac();
      Botan::Pipe *pipe;
  };

  class MacUpdateBaton : public Baton {
    public:
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::Pipe *pipe;

      MacUpdateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
      }

      ~MacUpdateBaton() {
        delete in;
      }
  };

  class MacFinalBaton : public Baton {
    public:
      std::string *mac;
      Botan::Pipe *pipe;

      MacFinalBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        mac = NULL;
      }

      ~MacFinalBaton() {
        delete mac;
      }
  };

}

namespace hash {

  static v8::Handle<v8::Value> Generate(const v8::Arguments &args);
  static void DoingGenerate(uv_work_t *request);
  static void AfterGenerate(uv_work_t *request);

  class GenerateBaton : public Baton {
    public:
      std::string *type;
      Botan::MemoryRegion<Botan::byte> *in;
      std::string *hash;

      GenerateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        type = NULL;
        in = NULL;
        hash = NULL;
      }

     ~GenerateBaton() {
        delete type;
        delete in;
        delete hash;
      }
  };

  static v8::Handle<v8::Value> Initialise(const v8::Arguments &args);
  static void DoingInitialise(uv_work_t *request);
  static void AfterInitialise(uv_work_t *request);

  class InitialiseBaton : public Baton {
    public:
      std::string *type;
      Botan::Pipe *pipe;

      InitialiseBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        type = NULL;
      }

      ~InitialiseBaton() {
        delete type;
      }
  };

  class Hash : public node::ObjectWrap {
    public:
      Hash(v8::Local<v8::Object> target, Botan::Pipe *pipe);

    protected:
      static v8::Handle<v8::Value> Update(const v8::Arguments &args);
      static void DoingUpdate(uv_work_t *request);
      static void AfterUpdate(uv_work_t *request);

      static v8::Handle<v8::Value> Final(const v8::Arguments &args);
      static void DoingFinal(uv_work_t *request);
      static void AfterFinal(uv_work_t *request);

    private:
      ~Hash();
      Botan::Pipe *pipe;
  };

  class HashUpdateBaton : public Baton {
    public:
      Botan::MemoryRegion<Botan::byte> *in;
      Botan::Pipe *pipe;

      HashUpdateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        in = NULL;
      }

      ~HashUpdateBaton() {
        delete in;
      }
  };

  class HashFinalBaton : public Baton {
    public:
      std::string *hash;
      Botan::Pipe *pipe;

      HashFinalBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        hash = NULL;
      }

      ~HashFinalBaton() {
        delete hash;
      }
  };

}

namespace pbkdf {

  static const size_t KEY_SIZE = 64;
  static const size_t SALT_SIZE = 32;
  static const uint32_t DEFAULT_ITERATIONS = 30000;

  static v8::Handle<v8::Value> Generate(const v8::Arguments &args);
  static void DoingGenerate(uv_work_t *request);
  static void AfterGenerate(uv_work_t *request);

  class GenerateBaton : public Baton {
    public:
      std::string *type;
      std::string *passphrase;
      std::string *derivedKey;
      std::string *salt;
      uint32_t iterations;

      GenerateBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        type = NULL;
        passphrase = NULL;
        derivedKey = NULL;
        salt = NULL;
      }

      ~GenerateBaton() {
        delete type;
        delete passphrase;
        delete derivedKey;
        delete salt;
      }
  };

}

namespace rnd {

  static v8::Handle<v8::Value> GenerateDigits(const v8::Arguments &args);
  static void DoingGenerateDigits(uv_work_t *request);
  static void AfterGenerateDigits(uv_work_t *request);

  class GenerateDigitsBaton : public Baton {
    public:
      size_t digitsLength;
      std::string *digits;

      GenerateDigitsBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        digits = NULL;
      }

      ~GenerateDigitsBaton() {
        delete digits;
      }
  };

  static v8::Handle<v8::Value> GenerateBytes(const v8::Arguments &args);
  static void DoingGenerateBytes(uv_work_t *request);
  static void AfterGenerateBytes(uv_work_t *request);

  enum ByteType { binary, base64, hex };

  class GenerateBytesBaton : public Baton {
    public:
      ByteType type;
      size_t bytesLength;
      Botan::MemoryRegion<Botan::byte> *bytes;
      std::string *string;

      GenerateBytesBaton(v8::Local<v8::Value> callback) : Baton(callback) {
        bytes = NULL;
        string = NULL;
      }

      ~GenerateBytesBaton() {
        delete bytes;
        delete string;
      }
  };

}

void init(v8::Handle<v8::Object> target);

} // namespace node_botan

#endif
