#include "node-botan.h"

#include <node_buffer.h>
#include <memory>

#include <botan/base64.h>
#include <botan/hex.h>

#define TYPE_ERROR(message) \
  v8::Exception::TypeError(String::New(message))
#define THROW_TYPE_ERROR(message) \
  ThrowException(TYPE_ERROR(message))
#define BAD_ARGS \
  TYPE_ERROR("Bad argument/s")
#define THROW_BAD_ARGS \
  THROW_TYPE_ERROR("Bad argument/s")

namespace node_botan {

using namespace v8;
using namespace node;
using namespace Botan;

using namespace pk;
using namespace cipher;
using namespace mac;
using namespace codec;
using namespace hash;
using namespace pbkdf;
using namespace rnd;

SecureVector<byte> *toSecureVector(Local<Value> object) {
  SecureVector<byte> *secureVector = NULL;
  if (object->IsString()) {
    String::Utf8Value string(object->ToString());
    secureVector = new SecureVector<byte>((byte *) *string, string.length());
  }
  else if (Buffer::HasInstance(object)) {
    Local<Object> buffer = object->ToObject();
    secureVector = new SecureVector<byte>((byte *) Buffer::Data(buffer),
      Buffer::Length(buffer));
  }
  return secureVector;
}

SecureVector<byte> **toSecureVectors(Local<Value> object, size_t& length) {
  SecureVector<byte> **secureVectors = NULL;
  if (object->IsArray()) {
    Local<Array> array = Local<Array>::Cast(object);
    length = array->Length();
    secureVectors = new SecureVector<byte>*[length];
    size_t i = 0;
    for (; i < length; i++) {
      Local<Value> object = array->Get(i);
      secureVectors[i] = toSecureVector(object);
    }
  }
  else {
    secureVectors = new SecureVector<byte>*[1];
    secureVectors[0] = toSecureVector(object);
    length = 1;
  }
  return secureVectors;
}

std::string *toString(Local<Value> object) {
  String::Utf8Value string(object->ToString());
  return new std::string(*string);
}

OctetString *toOctetString(Local<Value> object) {
  OctetString *octetString = NULL;
  if (object->IsString()) {
    String::Utf8Value string(object->ToString());
    octetString = new OctetString((byte *) *string, string.length());
  }
  else if (Buffer::HasInstance(object)) {
    Local<Object> buffer = object->ToObject();
    octetString = new OctetString((byte *) Buffer::Data(buffer),
    Buffer::Length(buffer));
  }
  return octetString;
}

Handle<Value> pk::Generate(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !(args[0]->IsNumber() || args[0]->IsNull()) ||
    !args[1]->IsFunction()) return THROW_BAD_ARGS;

  GenerateBaton *baton = new GenerateBaton(args[1]);
  if (args[0]->IsNull())
    baton->keySize = DEFAULT_KEY_SIZE;
  else
    baton->keySize = args[0]->NumberValue();

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingGenerate, AfterGenerate);

  return scope.Close(Undefined());
}

void pk::DoingGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    baton->privateKey = new RSA_PrivateKey(rng, baton->keySize);
    baton->publicKey = dynamic_cast<RSA_PublicKey*>(baton->privateKey);
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void pk::AfterGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> publicKey = Null();
  Handle<Value> privateKey = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> publicKeyTemplate = ObjectTemplate::New();
    publicKeyTemplate->SetInternalFieldCount(1);
    publicKey = (new PublicKey(publicKeyTemplate->NewInstance(),
      baton->publicKey))->handle_;

    Handle<ObjectTemplate> privateKeyTemplate = ObjectTemplate::New();
    privateKeyTemplate->SetInternalFieldCount(1);
    privateKey = (new PrivateKey(privateKeyTemplate->NewInstance(),
      baton->privateKey))->handle_;
  }

  Handle<Value> argv[3] = {error, publicKey, privateKey};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> pk::LoadPublicKey(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsString() || !args[1]->IsFunction())
    return THROW_BAD_ARGS;

  LoadPublicKeyBaton *baton = new LoadPublicKeyBaton(args[1]);
  baton->publicKeyString = toString(args[0]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingLoadPublicKey, AfterLoadPublicKey);

  return scope.Close(Undefined());
}

void pk::DoingLoadPublicKey(uv_work_t *request) {
  LoadPublicKeyBaton *baton = static_cast<LoadPublicKeyBaton *>(request->data);

  try {
    SecureVector<byte> data((byte *) baton->publicKeyString->c_str(),
      baton->publicKeyString->length());
    std::auto_ptr<X509_PublicKey> *key = new std::auto_ptr<X509_PublicKey>(
      X509::load_key(data));
    baton->publicKey = dynamic_cast<RSA_PublicKey*>(key->get());
    AutoSeeded_RNG rng;
    if (!baton->publicKey->check_key(rng, true))
      baton->error = new std::string("public key failed verification");
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void pk::AfterLoadPublicKey(uv_work_t *request) {
  LoadPublicKeyBaton *baton = static_cast<LoadPublicKeyBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> publicKey = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> t = ObjectTemplate::New();
    t->SetInternalFieldCount(1);
    publicKey = (new PublicKey(t->NewInstance(), baton->publicKey))->handle_;
  }

  Handle<Value> argv[2] = {error, publicKey};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> pk::LoadPrivateKey(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 5 || !(Buffer::HasInstance(args[0]) || args[0]->IsString()) ||
    !args[1]->IsString() || !args[2]->IsString() || !args[3]->IsString() ||
    !args[4]->IsFunction()) return THROW_BAD_ARGS;

  LoadPrivateKeyBaton *baton = new LoadPrivateKeyBaton(args[4]);
  baton->privateKeyString = toOctetString(args[0]);
  baton->salt = toString(args[1]);
  baton->iv = toString(args[2]);
  baton->passphrase = toString(args[3]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingLoadPrivateKey, AfterLoadPrivateKey);

  return scope.Close(Undefined());
}

void pk::DoingLoadPrivateKey(uv_work_t *request) {
  LoadPrivateKeyBaton *baton = static_cast<LoadPrivateKeyBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    SecureVector<byte> salt = base64_decode(*baton->salt);
    std::auto_ptr<PBKDF> pbkdf(get_pbkdf(PBKDF_TYPE));
    OctetString key = pbkdf->derive_key(PBKDF_SIZE,
      *baton->passphrase, salt.begin(), PBKDF_SIZE, PBKDF_ITERATIONS);
    SecureVector<byte> ivString = base64_decode(*baton->iv);
    InitializationVector iv(ivString.begin(), IV_SIZE);
    Pipe pipe(new Chain(new Base64_Decoder, get_cipher(CIPHER_TYPE,
      key, iv, DECRYPTION)));
    pipe.process_msg(baton->privateKeyString->bits_of());

    BER_Decoder decoder(pipe.read_all());
    BER_Decoder sequence = decoder.start_cons(SEQUENCE);
    size_t version;
    sequence.decode(version);
    if (version)
      baton->error = new std::string("encountered unknown BER version");
    else {
      AlgorithmIdentifier algorithm;
      sequence.decode(algorithm);
      SecureVector<byte> privateKeyString;
      sequence.decode(privateKeyString, OCTET_STRING);
      baton->privateKey = new RSA_PrivateKey(algorithm, privateKeyString, rng);
    }
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void pk::AfterLoadPrivateKey(uv_work_t *request) {
  LoadPrivateKeyBaton *baton = static_cast<LoadPrivateKeyBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> privateKey = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> t = ObjectTemplate::New();
    t->SetInternalFieldCount(1);
    privateKey = (new PrivateKey(t->NewInstance(), baton->privateKey))->handle_;
  }

  Handle<Value> argv[2] = {error, privateKey};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> PublicKey::ToString(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 1 || !args[0]->IsFunction()) return THROW_BAD_ARGS;

  PublicKeyToStringBaton *baton = new PublicKeyToStringBaton(args[0]);
  baton->publicKey = (ObjectWrap::Unwrap<PublicKey>(args.This()))->publicKey;

  uv_work_t *request = new uv_work_t;
  request->data = baton;

  uv_queue_work(uv_default_loop(), request, DoingToString, AfterToString);

  return scope.Close(Undefined());
}

void PublicKey::DoingToString(uv_work_t *request) {
  PublicKeyToStringBaton *baton =
    static_cast<PublicKeyToStringBaton *>(request->data);

  try {
    baton->publicKeyString = new std::string(X509::PEM_encode(*baton->publicKey));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void PublicKey::AfterToString(uv_work_t *request) {
  PublicKeyToStringBaton *baton =
    static_cast<PublicKeyToStringBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> publicKeyString = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    publicKeyString = String::New(baton->publicKeyString->c_str());

  Handle<Value> argv[2] = {error, publicKeyString};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> PrivateKey::ToString(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsString() || !args[1]->IsFunction())
    return THROW_BAD_ARGS;

  PrivateKeyToStringBaton *baton = new PrivateKeyToStringBaton(args[1]);
  baton->privateKey = (ObjectWrap::Unwrap<PrivateKey>(args.This()))->privateKey;
  baton->passphrase = toString(args[0]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingToString, AfterToString);

  return scope.Close(Undefined());
}

void PrivateKey::DoingToString(uv_work_t *request) {
  PrivateKeyToStringBaton *baton =
    static_cast<PrivateKeyToStringBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    SecureVector<byte> salt = SecureVector<byte>(rng.random_vec(PBKDF_SIZE * 2));
    std::auto_ptr<PBKDF> pbkdf(get_pbkdf(PBKDF_TYPE));
    OctetString key = pbkdf->derive_key(PBKDF_SIZE,
      *baton->passphrase, salt.begin(), PBKDF_SIZE, PBKDF_ITERATIONS);
    InitializationVector iv(rng, IV_SIZE);
    Pipe pipe(new Chain(get_cipher(CIPHER_TYPE, key, iv, ENCRYPTION),
      new Base64_Encoder));
    pipe.process_msg(PKCS8::BER_encode(*baton->privateKey));

    baton->salt = new std::string(base64_encode(salt));
    baton->iv = new std::string(base64_encode(iv.bits_of()));
    baton->privateKeyString = new std::string(pipe.read_all_as_string());
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void PrivateKey::AfterToString(uv_work_t *request) {
  PrivateKeyToStringBaton *baton =
    static_cast<PrivateKeyToStringBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> privateKeyString = Null();
  Handle<Value> salt = Null();
  Handle<Value> iv = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    privateKeyString = String::New(baton->privateKeyString->c_str());
    salt = String::New(baton->salt->c_str());
    iv = String::New(baton->iv->c_str());
  }

  Handle<Value> argv[4] = {error, privateKeyString, salt, iv};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 4, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> PublicKey::Encrypt(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !Buffer::HasInstance(args[0]) ||
    !args[1]->IsFunction()) return THROW_BAD_ARGS;

  PublicKeyEncryptBaton *baton = new PublicKeyEncryptBaton(args[1]);
  baton->in = toSecureVector(args[0]);
  baton->publicKey = (ObjectWrap::Unwrap<PublicKey>(args.This()))->publicKey;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingEncrypt, AfterEncrypt);

  return scope.Close(Undefined());
}

void PublicKey::DoingEncrypt(uv_work_t *request) {
  PublicKeyEncryptBaton *baton =
    static_cast<PublicKeyEncryptBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    PK_Encryptor_EME op(*baton->publicKey, PADDING_TYPE);
    baton->out = new SecureVector<byte>(op.encrypt(baton->in->begin(),
      baton->in->size(), rng));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void PublicKey::AfterEncrypt(uv_work_t *request) {
  PublicKeyEncryptBaton *baton =
    static_cast<PublicKeyEncryptBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    out = Buffer::New((char *) baton->out->begin(), baton->out->size())->handle_;

  Handle<Value> argv[2] = {error, out};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> PrivateKey::Decrypt(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !Buffer::HasInstance(args[0]) ||
    !args[1]->IsFunction()) return THROW_BAD_ARGS;

  PrivateKeyDecryptBaton *baton = new PrivateKeyDecryptBaton(args[1]);
  baton->in = toSecureVector(args[0]);
  baton->privateKey = (ObjectWrap::Unwrap<PrivateKey>(args.This()))->privateKey;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingDecrypt, AfterDecrypt);

  return scope.Close(Undefined());
}

void PrivateKey::DoingDecrypt(uv_work_t *request) {
  PrivateKeyDecryptBaton *baton =
    static_cast<PrivateKeyDecryptBaton *>(request->data);

  try {
    PK_Decryptor_EME op(*baton->privateKey, PADDING_TYPE);
    baton->out = new SecureVector<byte>(op.decrypt(baton->in->begin(),
      baton->in->size()));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void PrivateKey::AfterDecrypt(uv_work_t *request) {
  PrivateKeyDecryptBaton *baton =
    static_cast<PrivateKeyDecryptBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    out = Buffer::New((char *) baton->out->begin(), baton->out->size())->handle_;

  Handle<Value> argv[2] = {error, out};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

PublicKey::PublicKey(Handle<Object> target, RSA_PublicKey* publicKey) {
  this->publicKey = publicKey;

  NODE_SET_METHOD(target, "encrypt", Encrypt);
  NODE_SET_METHOD(target, "toString", ToString);

  Wrap(target);
}

PublicKey::~PublicKey() {
  if (publicKey) delete publicKey;
}

PrivateKey::PrivateKey(Handle<Object> target, RSA_PrivateKey* privateKey) {
  this->privateKey = privateKey;

  NODE_SET_METHOD(target, "decrypt", Decrypt);
  NODE_SET_METHOD(target, "toString", ToString);

  Wrap(target);
}

PrivateKey::~PrivateKey() {
  if (privateKey) delete privateKey;
}

Handle<Value> cipher::Encrypt(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 5 || !(args[0]->IsNull() || args[0]->IsString()) ||
    !(args[1]->IsNull() || args[1]->IsString()) || !(args[2]->IsString() ||
    Buffer::HasInstance(args[2])) || !(args[3]->IsString() ||
    Buffer::HasInstance(args[3]) || args[3]->IsArray()) ||!args[4]->IsFunction())
    return THROW_BAD_ARGS;

  EncryptBaton *baton = new EncryptBaton(args[4]);
  if (args[0]->IsNull())
    baton->cipherType = new std::string(DEFAULT_CIPHER_TYPE);
  else
    baton->cipherType = toString(args[0]);
  if (args[1]->IsString())
    baton->macType = toString(args[1]);
  if (args[2]->IsString())
    baton->keyString = toString(args[2]);
  else
    baton->key = toOctetString(args[2]);
  baton->in = toSecureVectors(args[3], baton->inLength);
  baton->out = new std::string*[baton->inLength];
  memset(baton->out, 0, baton->inLength * sizeof(std::string*));
  if (baton->macType) {
    baton->mac = new std::string*[baton->inLength];
    memset(baton->mac, 0, baton->inLength * sizeof(std::string*));
  }

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingEncrypt, AfterEncrypt);

  return scope.Close(Undefined());
}

std::string *encryptSecureVector(SecureVector<byte> *secureVector,
  std::string *cipherType, OctetString *key, std::string *macType, std::string **mac) {
  AutoSeeded_RNG rng;
  InitializationVector iv(rng, cipher::IV_SIZE);
  Fanout_Filter *pipeOptions = NULL;
  if (macType)
    pipeOptions = new Fork(
      new Chain(get_cipher(*cipherType, *key, iv, ENCRYPTION)),
      new Chain(new MAC_Filter(*macType, *key), new Base64_Encoder));
  else
    pipeOptions = new Chain(get_cipher(*cipherType, *key, iv, ENCRYPTION));
  Pipe pipe(pipeOptions);
  pipe.process_msg(*secureVector);

  size_t ivRemainder = cipher::IV_SIZE % 3;
  if (ivRemainder) {
    OctetString ivRemainderString(rng, ivRemainder);
    iv = iv + ivRemainderString;
  }
  std::string *encryptedSecureVector = new std::string(base64_encode(iv.bits_of()));
  encryptedSecureVector->append(base64_encode(pipe.read_all(0)));
  if ((pipe.message_count() > 1) && (pipe.remaining(1) > 0))
    *mac = new std::string(pipe.read_all_as_string(1));

  return encryptedSecureVector;
}

void cipher::DoingEncrypt(uv_work_t *request) {
  EncryptBaton *baton = static_cast<EncryptBaton *>(request->data);

  try {
    if (baton->keyString)
      baton->key = new OctetString(base64_decode(*baton->keyString));
    size_t i = 0;
    for (; i < baton->inLength; i++) {
      if (baton->in[i]) {
        std::string *mac = NULL;
        baton->out[i] = encryptSecureVector(baton->in[i], baton->cipherType,
          baton->key, baton->macType, &mac);
        if (mac) baton->mac[i] = mac;
      }
    }
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void cipher::AfterEncrypt(uv_work_t *request) {
  EncryptBaton *baton = static_cast<EncryptBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    if (baton->inLength == 1) {
      if (baton->out[0]) {
        out = String::New(baton->out[0]->c_str());
        if (baton->mac)
          mac = String::New(baton->mac[0]->c_str());
      }
      else out = Null();
    }
    else {
      Local<Array> outArray = Array::New(baton->inLength);
      Local<Array> macArray;
      if (baton->macType) macArray = Array::New(baton->inLength);
      size_t i = 0;
      for (; i < baton->inLength; i++) {
        if (baton->out[i]) {
          outArray->Set(i, String::New(baton->out[i]->c_str()));
          if (baton->macType)
            macArray->Set(i, String::New(baton->mac[i]->c_str()));
        }
        else outArray->Set(i, Null());
      }
      out = outArray;
      if (baton->macType) mac = macArray;
    }
  }

  Handle<Value> argv[3] = {error, out, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> cipher::Decrypt(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 5 || !(args[0]->IsNull() || args[0]->IsString()) ||
    !(args[1]->IsNull() || args[1]->IsString()) || !(args[2]->IsString() ||
    Buffer::HasInstance(args[2])) || !(args[3]->IsString() || args[3]->IsArray() ||
    Buffer::HasInstance(args[3])) || !args[4]->IsFunction()) return THROW_BAD_ARGS;

  DecryptBaton *baton = new DecryptBaton(args[4]);
  if (args[0]->IsNull())
    baton->cipherType = new std::string(DEFAULT_CIPHER_TYPE);
  else
    baton->cipherType = toString(args[0]);
  if (args[1]->IsString())
    baton->macType = toString(args[1]);
  if (args[2]->IsString())
    baton->keyString = toString(args[2]);
  else
    baton->key = toOctetString(args[2]);
  baton->in = toSecureVectors(args[3], baton->inLength);
  baton->out = new SecureVector<byte>*[baton->inLength];
  memset(baton->out, 0, baton->inLength * sizeof(SecureVector<byte> *));
  if (baton->macType) {
    baton->mac = new std::string*[baton->inLength];
    memset(baton->mac, 0, baton->inLength * sizeof(std::string*));
  }

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingDecrypt, AfterDecrypt);

  return scope.Close(Undefined());
}

SecureVector<byte> *decryptSecureVector(SecureVector<byte>& secureVector,
  std::string *cipherType, OctetString *key, InitializationVector& iv,
    std::string *macType, std::string **mac) {
  Fanout_Filter *pipeOptions = NULL;
  if (macType)
    pipeOptions = new Chain(new Chain(new Base64_Decoder, get_cipher(
      *cipherType, *key, iv, DECRYPTION)), new Fork(0, new Chain(
        new MAC_Filter(*macType, *key), new Base64_Encoder)));
  else
    pipeOptions = new Chain(new Base64_Decoder, get_cipher(*cipherType, *key,
      iv, DECRYPTION));
  Pipe pipe(pipeOptions);
  pipe.process_msg(secureVector);

  SecureVector<byte> *decryptedSecureVector = new SecureVector<byte>(
    pipe.read_all(0));
  if ((pipe.message_count() > 1) && (pipe.remaining(1) > 0))
    *mac = new std::string(pipe.read_all_as_string(1));

  return decryptedSecureVector;
}

void cipher::DoingDecrypt(uv_work_t *request) {
  DecryptBaton *baton = static_cast<DecryptBaton *>(request->data);

  try {
    if (baton->keyString)
      baton->key = new OctetString(base64_decode(*baton->keyString));
    size_t i = 0;
    for (; i < baton->inLength; i++) {
      if (baton->in[i]) {
        std::string *mac = NULL;
        SecureVector<byte> ivString = base64_decode((char *) baton->in[i]->begin(),
          IV_SIZE_BASE64);
        ivString.resize(ivString.size() - (IV_SIZE % 3));
        InitializationVector iv(ivString);
        SecureVector<byte> in(*baton->in[i] + IV_SIZE_BASE64, baton->in[i]->size()
          - IV_SIZE_BASE64);
        baton->out[i] = decryptSecureVector(in, baton->cipherType, baton->key, iv,
          baton->macType, &mac);
        if (mac) baton->mac[i] = mac;
      }
    }
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void cipher::AfterDecrypt(uv_work_t *request) {
  DecryptBaton *baton = static_cast<DecryptBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    if (baton->inLength == 1) {
      if (baton->out[0]) {
        out = Buffer::New((char *) baton->out[0]->begin(),
          baton->out[0]->size())->handle_;
        if (baton->mac) mac = String::New(baton->mac[0]->c_str());
      }
      else out = Null();
    }
    else {
      Local<Array> outArray = Array::New(baton->inLength);
      Local<Array> macArray;
      if (baton->macType) macArray = Array::New(baton->inLength);
      size_t i = 0;
      for (; i < baton->inLength; i++) {
        if (baton->out[i]) {
          outArray->Set(i, Buffer::New((char *) baton->out[i]->begin(),
            baton->out[i]->size())->handle_);
          if (baton->macType)
            macArray->Set(i, String::New(baton->mac[i]->c_str()));
        }
        else outArray->Set(i, Null());
      }
      out = outArray;
      if (baton->macType) mac = macArray;
    }
  }

  Handle<Value> argv[3] = {error, out, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> cipher::InitialiseEncryptor(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 4 || !(args[0]->IsNull() || args[0]->IsString()) ||
    !(args[1]->IsNull() || args[1]->IsString()) || !(args[2]->IsString() ||
    Buffer::HasInstance(args[2])) || !args[3]->IsFunction()) return THROW_BAD_ARGS;

  InitialiseEncryptorBaton *baton = new InitialiseEncryptorBaton(args[3]);
  if (args[0]->IsNull())
    baton->cipherType = new std::string(DEFAULT_CIPHER_TYPE);
  else
    baton->cipherType = toString(args[0]);
  if (args[1]->IsString())
    baton->macType = toString(args[1]);
  if (args[2]->IsString())
    baton->keyString = toString(args[2]);
  else
    baton->key = toSecureVector(args[2]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingInitialiseEncryptor,
    AfterInitialiseEncryptor);

  return scope.Close(Undefined());
}

void cipher::DoingInitialiseEncryptor(uv_work_t *request) {
  InitialiseEncryptorBaton *baton =
    static_cast<InitialiseEncryptorBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    InitializationVector iv(rng, IV_SIZE);
    if (baton->keyString)
      baton->key = new SecureVector<byte>(base64_decode(*baton->keyString));
    SymmetricKey key(baton->key->begin(), baton->key->size());
    if (baton->macType)
      baton->pipe = new Pipe(new Fork(
        new Chain(get_cipher(*baton->cipherType, key, iv, ENCRYPTION)),
        new Chain(new MAC_Filter(*baton->macType, key), new Base64_Encoder)));
    else
      baton->pipe = new Pipe(get_cipher(*baton->cipherType, key, iv, ENCRYPTION));
    baton->iv = new std::string(base64_encode(iv.begin(), iv.length()));
    baton->pipe->start_msg();
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void cipher::AfterInitialiseEncryptor(uv_work_t *request) {
  InitialiseEncryptorBaton *baton =
    static_cast<InitialiseEncryptorBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> encryptor = Null();
  Handle<Value> iv = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> t = ObjectTemplate::New();
    t->SetInternalFieldCount(1);
    encryptor = (new Encryptor(t->NewInstance(), baton->pipe))->handle_;
    iv = String::New(baton->iv->c_str());
  }

  Handle<Value> argv[3] = {error, encryptor, iv};

  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Encryptor::Update(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 4 || !Buffer::HasInstance(args[0]) ||
    !(args[1]->IsNull() || args[1]->IsNumber()) || !(args[2]->IsNull() ||
    args[2]->IsNumber()) || !args[3]->IsFunction()) return THROW_BAD_ARGS;

  EncryptorUpdateBaton *baton = new EncryptorUpdateBaton(args[3]);
  Local<Object> in = args[0]->ToObject();
  size_t inPosition = 0;
  if (!args[1]->IsNull())
    inPosition = args[1]->NumberValue();
  size_t inLength;
  if (args[2]->IsNull())
    inLength = Buffer::Length(in);
  else
    inLength = args[2]->NumberValue();
  if ((inPosition + inLength) > Buffer::Length(in))
    return THROW_TYPE_ERROR("buffer too small");
  baton->in = new SecureVector<byte>((byte *) Buffer::Data(in) + inPosition,
    inLength);
  baton->pipe = (ObjectWrap::Unwrap<Encryptor>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingUpdate, AfterUpdate);

  return scope.Close(Undefined());
}

void Encryptor::DoingUpdate(uv_work_t *request) {
  EncryptorUpdateBaton *baton = static_cast<EncryptorUpdateBaton *>(request->data);

  try {
    baton->pipe->write(*baton->in);
    baton->out = new SecureVector<byte>(baton->pipe->read_all(0));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Encryptor::AfterUpdate(uv_work_t *request) {
  EncryptorUpdateBaton *baton = static_cast<EncryptorUpdateBaton *>(request->data);


  Handle<Value> error = Null();
  Handle<Value> out = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    out = Buffer::New((char *) baton->out->begin(), baton->out->size())->handle_;

  Handle<Value> argv[2] = {error, out};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Encryptor::Final(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 1 || !args[0]->IsFunction()) return THROW_BAD_ARGS;

  EncryptorFinalBaton *baton = new EncryptorFinalBaton(args[0]);
  baton->pipe = (ObjectWrap::Unwrap<Encryptor>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingFinal, AfterFinal);

  return scope.Close(Undefined());
}

void Encryptor::DoingFinal(uv_work_t *request) {
  EncryptorFinalBaton *baton = static_cast<EncryptorFinalBaton *>(request->data);

  try {
    baton->pipe->end_msg();
    baton->out = new SecureVector<byte>(baton->pipe->read_all(0));
    if ((baton->pipe->message_count() > 1) && (baton->pipe->remaining(1) > 0))
      baton->mac = new std::string(baton->pipe->read_all_as_string(1));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Encryptor::AfterFinal(uv_work_t *request) {
  EncryptorFinalBaton *baton = static_cast<EncryptorFinalBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    if (baton->out->size() > 0) {
      out = Buffer::New((char *) baton->out->begin(),
        baton->out->size())->handle_;
    }
    if (baton->mac)
      mac = String::New(baton->mac->c_str());
  }

  Handle<Value> argv[3] = {error, out, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Encryptor::Encryptor(Handle<Object> target, Pipe* pipe) {
  this->pipe = pipe;

  NODE_SET_METHOD(target, "update", Update);
  NODE_SET_METHOD(target, "final", Final);

  Wrap(target);
}

Encryptor::~Encryptor() {
  if (pipe) delete pipe;
}

Handle<Value> cipher::InitialiseDecryptor(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 5 || !(args[0]->IsNull() || args[0]->IsString()) ||
    !(args[1]->IsNull() || args[1]->IsString()) || !(args[2]->IsString() ||
    Buffer::HasInstance(args[2])) || !args[3]->IsString() ||
    !args[4]->IsFunction()) return THROW_BAD_ARGS;

  InitialiseDecryptorBaton *baton = new InitialiseDecryptorBaton(args[4]);
  if (args[0]->IsNull())
    baton->cipherType = new std::string(DEFAULT_CIPHER_TYPE);
  else
    baton->cipherType = toString(args[0]);
  if (args[1]->IsString())
    baton->macType = toString(args[1]);
  if (args[2]->IsString())
    baton->keyString = toString(args[2]);
  else
    baton->key = toSecureVector(args[2]);
  baton->iv = toSecureVector(args[3]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingInitialiseDecryptor,
    AfterInitialiseDecryptor);

  return scope.Close(Undefined());
}

void cipher::DoingInitialiseDecryptor(uv_work_t *request) {
  InitialiseDecryptorBaton *baton =
    static_cast<InitialiseDecryptorBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    InitializationVector iv(base64_decode((char *) baton->iv->begin(), baton->iv->size()));
    if (baton->keyString)
      baton->key = new SecureVector<byte>(base64_decode(*baton->keyString));
    SymmetricKey key(baton->key->begin(), baton->key->size());
    if (baton->macType)
      baton->pipe = new Pipe(get_cipher(*baton->cipherType, key, iv, DECRYPTION),
        new Fork(0, new Chain(new MAC_Filter(*baton->macType, key),
        new Base64_Encoder)));
    else
      baton->pipe = new Pipe(get_cipher(*baton->cipherType, key, iv, DECRYPTION));
    baton->pipe->start_msg();
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void cipher::AfterInitialiseDecryptor(uv_work_t *request) {
  InitialiseDecryptorBaton *baton =
    static_cast<InitialiseDecryptorBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> decryptor = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> t = ObjectTemplate::New();
    t->SetInternalFieldCount(1);
    decryptor = (new Decryptor(t->NewInstance(), baton->pipe))->handle_;
  }

  Handle<Value> argv[2] = {error, decryptor};

  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Decryptor::Update(const Arguments &args) {
  HandleScope scope;

  if (args.Length() < 4 || !Buffer::HasInstance(args[0]) || !(args[1]->IsNull() ||
    args[1]->IsNumber()) || !(args[2]->IsNull() || args[2]->IsNumber()) ||
    !args[3]->IsFunction()) return THROW_BAD_ARGS;

  DecryptorUpdateBaton *baton = new DecryptorUpdateBaton(args[3]);
  Local<Object> in = args[0]->ToObject();
  size_t inPosition = 0;
  if (!args[1]->IsNull())
    inPosition = args[1]->NumberValue();
  size_t inLength;
  if (args[2]->IsNull())
    inLength = Buffer::Length(in);
  else
    inLength = args[2]->NumberValue();
  if ((inPosition + inLength) > Buffer::Length(in))
    return THROW_TYPE_ERROR("buffer too small");
  baton->in = new SecureVector<byte>((byte *) Buffer::Data(in) + inPosition,
    inLength);
  baton->pipe = (ObjectWrap::Unwrap<Decryptor>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingUpdate, AfterUpdate);

  return scope.Close(Undefined());
}

void Decryptor::DoingUpdate(uv_work_t *request) {
  DecryptorUpdateBaton *baton = static_cast<DecryptorUpdateBaton *>(request->data);

  try {
    baton->pipe->write(*baton->in);
    baton->out = new SecureVector<byte>(baton->pipe->read_all(0));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Decryptor::AfterUpdate(uv_work_t *request) {
  DecryptorUpdateBaton *baton = static_cast<DecryptorUpdateBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else if (baton->out->size() > 0)
    out = Buffer::New((char *) baton->out->begin(), baton->out->size())->handle_;

  Handle<Value> argv[2] = {error, out};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Decryptor::Final(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 1 || !args[0]->IsFunction()) return THROW_BAD_ARGS;

  DecryptorFinalBaton *baton = new DecryptorFinalBaton(args[0]);
  baton->pipe = (ObjectWrap::Unwrap<Decryptor>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingFinal, AfterFinal);

  return scope.Close(Undefined());
}

void Decryptor::DoingFinal(uv_work_t *request) {
  DecryptorFinalBaton *baton = static_cast<DecryptorFinalBaton *>(request->data);

  try {
    Pipe *pipe = baton->pipe;
    pipe->end_msg();
    baton->out = new SecureVector<byte>(pipe->read_all(0));
    if ((baton->pipe->message_count() > 1) && (baton->pipe->remaining(1) > 0))
      baton->mac = new std::string(baton->pipe->read_all_as_string(1));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Decryptor::AfterFinal(uv_work_t *request) {
  DecryptorFinalBaton *baton = static_cast<DecryptorFinalBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    if (baton->out->size() > 0)
      out = Buffer::New((char *) baton->out->begin(), baton->out->size())->handle_;
    if (baton->mac)
      mac = String::New(baton->mac->c_str());
  }

  Handle<Value> argv[3] = {error, out, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Decryptor::Decryptor(Handle<Object> target, Pipe* pipe) {
  this->pipe = pipe;

  NODE_SET_METHOD(target, "update", Update);
  NODE_SET_METHOD(target, "final", Final);

  Wrap(target);
}

Decryptor::~Decryptor() {
  if (pipe) delete pipe;
}

Handle<Value> codec::EncodeSync(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsString() || !(Buffer::HasInstance(args[1]) ||
    args[1]->IsString())) return THROW_BAD_ARGS;

  Handle<Value> out;
  try {
    String::Utf8Value type(args[0]->ToString());
    if (args[1]->IsString()) {
      String::Utf8Value in(args[1]->ToString());
      if (strcmp(*type, "base64") == 0)
        out = String::New(base64_encode((byte *) *in, in.length()).c_str());
      else if (strcmp(*type, "hex") == 0)
        out = String::New(hex_encode((byte *) *in, in.length()).c_str());
      else
        return THROW_BAD_ARGS;
    }
    else {
      Local<Object> in = args[1]->ToObject();
      if (strcmp(*type, "base64") == 0)
        out = String::New(base64_encode((byte *) Buffer::Data(in),
          Buffer::Length(in)).c_str());
      else if (strcmp(*type, "hex") == 0)
        out = String::New(hex_encode((byte *) Buffer::Data(in),
          Buffer::Length(in)).c_str());
      else
        return THROW_BAD_ARGS;
    }
  }
  catch (std::exception &e) {
    return TYPE_ERROR(e.what());
  }

  return scope.Close(out);
}

Handle<Value> codec::Encode(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 3 || !args[0]->IsString() || !(Buffer::HasInstance(args[1]) ||
    args[1]->IsString()) || !args[2]->IsFunction()) return THROW_BAD_ARGS;

  EncodeBaton *baton = new EncodeBaton(args[2]);
  String::Utf8Value type(args[0]->ToString());
  if (strcmp(*type, "base64") == 0)
    baton->type = base64;
  else if (strcmp(*type, "hex") == 0)
    baton->type = hex;
  else
    return THROW_BAD_ARGS;
  baton->in = toSecureVector(args[1]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingEncode, AfterEncode);

  return scope.Close(Undefined());
}

void codec::DoingEncode(uv_work_t *request) {
  EncodeBaton *baton = static_cast<EncodeBaton *>(request->data);

  try {
    if (baton->type == base64)
      baton->out = new std::string(base64_encode(*baton->in));
    else
      baton->out = new std::string(hex_encode(*baton->in));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void codec::AfterEncode(uv_work_t *request) {
  EncodeBaton *baton = static_cast<EncodeBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    out = String::New(baton->out->c_str());

  Handle<Value> argv[2] = {error, out};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> codec::DecodeSync(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsString() || !args[1]->IsString())
    return THROW_BAD_ARGS;

  Handle<Value> out;
  try {
    String::Utf8Value type(args[0]->ToString());
    String::Utf8Value in(args[1]->ToString());
    if (strcmp(*type, "base64") == 0) {
      SecureVector<byte> decoded = base64_decode(*in, in.length());
      out = Buffer::New((char *) decoded.begin(), decoded.size())->handle_;
    }
    else if (strcmp(*type, "hex") == 0) {
      SecureVector<byte> decoded = hex_decode(*in, in.length());
      out = Buffer::New((char *) decoded.begin(), decoded.size())->handle_;
    }
    else
      return THROW_BAD_ARGS;
  }
  catch (std::exception &e) {
    return TYPE_ERROR(e.what());
  }

  return scope.Close(out);
}

Handle<Value> codec::Decode(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 3 || !args[0]->IsString() || !args[1]->IsString() ||
    !args[2]->IsFunction()) return THROW_BAD_ARGS;

  DecodeBaton *baton = new DecodeBaton(args[2]);
  String::Utf8Value type(args[0]->ToString());
  if (strcmp(*type, "base64") == 0)
    baton->type = base64;
  else if (strcmp(*type, "hex") == 0)
    baton->type = hex;
  else
    return THROW_BAD_ARGS;
  baton->in = toString(args[1]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingDecode, AfterDecode);

  return scope.Close(Undefined());
}

void codec::DoingDecode(uv_work_t *request) {
  DecodeBaton *baton = static_cast<DecodeBaton *>(request->data);

  try {
    if (baton->type == base64)
      baton->out = new SecureVector<byte>(base64_decode(*baton->in,
        baton->in->length()));
    else
      baton->out = new SecureVector<byte>(hex_decode(*baton->in, baton->in->length()));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void codec::AfterDecode(uv_work_t *request) {
  DecodeBaton *baton = static_cast<DecodeBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> out = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    out = Buffer::New((char *) baton->out->begin(), baton->out->size())->handle_;

  Handle<Value> argv[2] = {error, out};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> mac::Generate(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 5 || !args[0]->IsString() || !(Buffer::HasInstance(args[1]) ||
    args[1]->IsString()) || !(args[2]->IsNumber() || args[2]->IsNull()) ||
    !(Buffer::HasInstance(args[3]) || args[3]->IsString()) || !args[4]->IsFunction())
    return THROW_BAD_ARGS;

  GenerateBaton *baton = new GenerateBaton(args[4]);
  baton->type = toString(args[0]);
  if (args[1]->IsString()) {
    String::Utf8Value in(args[1]->ToString());
    size_t inLength;
    if (args[2]->IsNull())
      inLength = in.length();
    else {
      inLength = args[2]->NumberValue();
      if (inLength > (size_t) in.length())
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) *in, inLength);
  }
  else {
    Local<Object> in = args[1]->ToObject();
    size_t inLength;
    if (args[2]->IsNull())
      inLength = Buffer::Length(in);
    else {
      inLength = args[2]->NumberValue();
      if (inLength > Buffer::Length(in))
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) Buffer::Data(in), inLength);
  }
  baton->key = toOctetString(args[3]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingGenerate, AfterGenerate);

  return scope.Close(Undefined());
}

void mac::DoingGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  try {
    Pipe pipe(new MAC_Filter(*baton->type, *baton->key), new Base64_Encoder);
    pipe.process_msg(*baton->in);

    std::string mac = pipe.read_all_as_string();
    baton->mac = new std::string(mac);
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void mac::AfterGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    mac = String::New(baton->mac->c_str());

  Handle<Value> argv[2] = {error, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> mac::Initialise(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 3 || !args[0]->IsString() || !(args[1]->IsString() ||
    Buffer::HasInstance(args[1])) || !args[2]->IsFunction()) return THROW_BAD_ARGS;

  InitialiseBaton *baton = new InitialiseBaton(args[2]);
  baton->type = toString(args[0]);
  baton->key = toOctetString(args[1]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingInitialise, AfterInitialise);

  return scope.Close(Undefined());
}

void mac::DoingInitialise(uv_work_t *request) {
  InitialiseBaton *baton = static_cast<InitialiseBaton *>(request->data);

  try {
    baton->pipe = new Pipe(new MAC_Filter(*baton->type, *baton->key),
      new Base64_Encoder);
    baton->pipe->start_msg();
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void mac::AfterInitialise(uv_work_t *request) {
  InitialiseBaton *baton = static_cast<InitialiseBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> t = ObjectTemplate::New();
    t->SetInternalFieldCount(1);
    mac = (new Mac(t->NewInstance(), baton->pipe))->handle_;
  }

  Handle<Value> argv[2] = {error, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Mac::Update(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 3 || !(Buffer::HasInstance(args[0]) || args[0]->IsString()) ||
    !(args[1]->IsNumber() || args[1]->IsNull()) || !args[2]->IsFunction())
    return THROW_BAD_ARGS;

  MacUpdateBaton *baton = new MacUpdateBaton(args[2]);
  if (args[0]->IsString()) {
    String::Utf8Value in(args[0]->ToString());
    size_t inLength;
    if (args[1]->IsNull())
      inLength = in.length();
    else {
      inLength = args[1]->NumberValue();
      if (inLength > (size_t) in.length())
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) *in, inLength);
  }
  else {
    Local<Object> in = args[0]->ToObject();
    size_t inLength;
    if (args[1]->IsNull())
      inLength = Buffer::Length(in);
    else {
      inLength = args[1]->NumberValue();
      if (inLength > Buffer::Length(in))
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) Buffer::Data(in), inLength);
  }
  baton->pipe = (ObjectWrap::Unwrap<Mac>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingUpdate, AfterUpdate);

  return scope.Close(Undefined());
}

void Mac::DoingUpdate(uv_work_t *request) {
  MacUpdateBaton *baton = static_cast<MacUpdateBaton *>(request->data);

  try {
    baton->pipe->write(*baton->in);
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Mac::AfterUpdate(uv_work_t *request) {
  MacUpdateBaton *baton = static_cast<MacUpdateBaton *>(request->data);

  Handle<Value> error = Null();
  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());

  Handle<Value> argv[1] = {error};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 1, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Mac::Final(const Arguments &args) {
  HandleScope scope;

  if (args.Length() < 1 || !args[0]->IsFunction()) return THROW_BAD_ARGS;

  MacFinalBaton *baton = new MacFinalBaton(args[0]);
  baton->pipe = (ObjectWrap::Unwrap<Mac>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingFinal, AfterFinal);

  return scope.Close(Undefined());
}

void Mac::DoingFinal(uv_work_t *request) {
  MacFinalBaton *baton = static_cast<MacFinalBaton *>(request->data);

  try {
    baton->pipe->end_msg();
    baton->mac = new std::string(baton->pipe->read_all_as_string());
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Mac::AfterFinal(uv_work_t *request) {
  MacFinalBaton *baton = static_cast<MacFinalBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> mac = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    mac = String::New(baton->mac->c_str());

  Handle<Value> argv[2] = {error, mac};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Mac::Mac(Local<Object> target, Pipe* pipe) {
  this->pipe = pipe;

  NODE_SET_METHOD(target, "update", Update);
  NODE_SET_METHOD(target, "final", Final);

  Wrap(target);
}

Mac::~Mac() {
  if (pipe) delete pipe;
}

Handle<Value> hash::Generate(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 4 || !args[0]->IsString() || !(Buffer::HasInstance(args[1])
    || args[1]->IsString()) || !(args[2]->IsNumber() || args[2]->IsNull()) ||
    !args[3]->IsFunction()) return THROW_BAD_ARGS;

  GenerateBaton *baton = new GenerateBaton(args[3]);
  baton->type = toString(args[0]);
  if (args[1]->IsString()) {
    String::Utf8Value in(args[1]->ToString());
    size_t inLength;
    if (args[2]->IsNull())
      inLength = in.length();
    else {
      inLength = args[2]->NumberValue();
      if (inLength > (size_t) in.length())
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) *in, inLength);
  }
  else {
    Local<Object> in = args[1]->ToObject();
    size_t inLength;
    if (args[2]->IsNull())
      inLength = Buffer::Length(in);
    else {
      inLength = args[2]->NumberValue();
      if (inLength > Buffer::Length(in))
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) Buffer::Data(in), inLength);
  }

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingGenerate, AfterGenerate);

  return scope.Close(Undefined());
}

void hash::DoingGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  try {
    Pipe pipe(new Hash_Filter(*baton->type), new Base64_Encoder);
    pipe.process_msg(*baton->in);

    baton->hash = new std::string(pipe.read_all_as_string());
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void hash::AfterGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> hash = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    hash = String::New(baton->hash->c_str());

  Handle<Value> argv[2] = {error, hash};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> hash::Initialise(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsString() || !args[1]->IsFunction())
    return THROW_BAD_ARGS;

  InitialiseBaton *baton = new InitialiseBaton(args[1]);
  baton->type = toString(args[0]);

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingInitialise, AfterInitialise);

  return scope.Close(Undefined());
}

void hash::DoingInitialise(uv_work_t *request) {
  InitialiseBaton *baton = static_cast<InitialiseBaton *>(request->data);

  try {
    baton->pipe = new Pipe(new Hash_Filter(*baton->type), new Base64_Encoder);
    baton->pipe->start_msg();
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void hash::AfterInitialise(uv_work_t *request) {
  InitialiseBaton *baton = static_cast<InitialiseBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> hash = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    Handle<ObjectTemplate> t = ObjectTemplate::New();
    t->SetInternalFieldCount(1);
    hash = (new Hash(t->NewInstance(), baton->pipe))->handle_;
  }

  Handle<Value> argv[2] = {error, hash};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Hash::Update(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 3 || !(Buffer::HasInstance(args[0]) ||
    args[0]->IsString()) || !(args[1]->IsNumber() || args[1]->IsNull()) ||
    !args[2]->IsFunction()) return THROW_BAD_ARGS;

  HashUpdateBaton *baton = new HashUpdateBaton(args[2]);
  if (args[0]->IsString()) {
    String::Utf8Value in(args[0]->ToString());
    size_t inLength;
    if (args[1]->IsNull())
      inLength = in.length();
    else {
      inLength = args[1]->NumberValue();
      if (inLength > (size_t) in.length())
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) *in, inLength);
  }
  else {
    Local<Object> in = args[0]->ToObject();
    size_t inLength;
    if (args[1]->IsNull())
      inLength = Buffer::Length(in);
    else {
      inLength = args[1]->NumberValue();
      if (inLength > Buffer::Length(in))
        return THROW_TYPE_ERROR("length too large");
    }
    baton->in = new SecureVector<byte>((byte *) Buffer::Data(in), inLength);
  }
  baton->pipe = (ObjectWrap::Unwrap<Hash>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingUpdate, AfterUpdate);

  return scope.Close(Undefined());
}

void Hash::DoingUpdate(uv_work_t *request) {
  HashUpdateBaton *baton = static_cast<HashUpdateBaton *>(request->data);

  try {
    baton->pipe->write(*baton->in);
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Hash::AfterUpdate(uv_work_t *request) {
  HashUpdateBaton *baton = static_cast<HashUpdateBaton *>(request->data);

  Handle<Value> error = Null();
  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());

  Handle<Value> argv[1] = {error};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 1, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> Hash::Final(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 1 || !args[0]->IsFunction()) return THROW_BAD_ARGS;

  HashFinalBaton *baton = new HashFinalBaton(args[0]);
  baton->pipe = (ObjectWrap::Unwrap<Hash>(args.This()))->pipe;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingFinal, AfterFinal);

  return scope.Close(Undefined());
}

void Hash::DoingFinal(uv_work_t *request) {
  HashFinalBaton *baton = static_cast<HashFinalBaton *>(request->data);

  try {
    baton->pipe->end_msg();
    baton->hash = new std::string(baton->pipe->read_all_as_string());
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void Hash::AfterFinal(uv_work_t *request) {
  HashFinalBaton *baton = static_cast<HashFinalBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> hash = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    hash = String::New(baton->hash->c_str());

  Handle<Value> argv[2] = {error, hash};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Hash::Hash(Local<Object> target, Pipe* pipe) {
  this->pipe = pipe;

  NODE_SET_METHOD(target, "update", Update);
  NODE_SET_METHOD(target, "final", Final);

  Wrap(target);
}

Hash::~Hash() {
  if (pipe) delete pipe;
}

Handle<Value> pbkdf::Generate(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 5 || !args[0]->IsString() || !args[1]->IsString() ||
    !(args[2]->IsNull() || args[2]->IsString()) || !(args[3]->IsNull() ||
    args[3]->IsNumber()) || !args[4]->IsFunction()) return THROW_BAD_ARGS;

  GenerateBaton *baton = new GenerateBaton(args[4]);
  baton->type = toString(args[0]);
  baton->passphrase = toString(args[1]);
  if (!args[2]->IsNull())
    baton->salt = toString(args[2]);
  if (args[3]->IsNull())
    baton->iterations = DEFAULT_ITERATIONS;
  else
    baton->iterations = args[3]->NumberValue();

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingGenerate, AfterGenerate);

  return scope.Close(Undefined());
}

void pbkdf::DoingGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  try {
    SecureVector<byte> salt;
    if (!baton->salt) {
      AutoSeeded_RNG rng;
      salt = SecureVector<byte>(rng.random_vec(SALT_SIZE));
      baton->salt = new std::string(base64_encode(salt));
    }
    else
      salt = base64_decode(*baton->salt);

    std::auto_ptr<PBKDF> pbkdf(get_pbkdf(*baton->type));
    OctetString derivedKey = pbkdf->derive_key(KEY_SIZE,
      *baton->passphrase, salt.begin(), salt.size(), baton->iterations);
    baton->derivedKey = new std::string(base64_encode(derivedKey.bits_of()));
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void pbkdf::AfterGenerate(uv_work_t *request) {
  GenerateBaton *baton = static_cast<GenerateBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> derivedKey = Null();
  Handle<Value> salt = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else {
    derivedKey = String::New(baton->derivedKey->c_str());
    salt = String::New(baton->salt->c_str());
  }

  Handle<Value> argv[3] = {error, derivedKey, salt};
  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 3, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> rnd::GenerateDigits(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsNumber() || !args[1]->IsFunction())
    return THROW_BAD_ARGS;

  GenerateDigitsBaton *baton = new GenerateDigitsBaton(args[1]);
  baton->digitsLength = args[0]->NumberValue();
  if (baton->digitsLength <= 0) return THROW_BAD_ARGS;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingGenerateDigits,
      AfterGenerateDigits);

  return scope.Close(Undefined());
}

void rnd::DoingGenerateDigits(uv_work_t *request) {
  GenerateDigitsBaton *baton = static_cast<GenerateDigitsBaton *>(request->data);

  std::string digits;
  char buffer[4];

  try {
    AutoSeeded_RNG rng;
    while (digits.length() < baton->digitsLength) {
      sprintf(buffer, "%d", rng.next_byte());
      digits += buffer;
    }
    if (digits.length() > baton->digitsLength)
      digits.resize(baton->digitsLength);
    baton->digits = new std::string(digits);
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void rnd::AfterGenerateDigits(uv_work_t *request) {
  GenerateDigitsBaton *baton = static_cast<GenerateDigitsBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> digits = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else
    digits = String::New(baton->digits->c_str());

  Handle<Value> argv[2] = {error, digits};

  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

Handle<Value> rnd::GenerateBytes(const Arguments &args) {
  HandleScope scope;

  if (args.Length() != 3 || !args[0]->IsString() || !args[1]->IsNumber() ||
    !args[2]->IsFunction()) return THROW_BAD_ARGS;

  GenerateBytesBaton *baton = new GenerateBytesBaton(args[2]);
  String::Utf8Value type(args[0]->ToString());
  if (strcmp(*type, "binary") == 0)
    baton->type = binary;
  else if (strcmp(*type, "base64") == 0)
    baton->type = base64;
  else if (strcmp(*type, "hex") == 0)
    baton->type = hex;
  else
    return THROW_BAD_ARGS;
  baton->bytesLength = args[1]->NumberValue();
  if (baton->bytesLength <= 0) return THROW_BAD_ARGS;

  uv_work_t *request = new uv_work_t;
  request->data = baton;
  uv_queue_work(uv_default_loop(), request, DoingGenerateBytes, AfterGenerateBytes);

  return scope.Close(Undefined());
}

void rnd::DoingGenerateBytes(uv_work_t *request) {
  GenerateBytesBaton *baton = static_cast<GenerateBytesBaton *>(request->data);

  try {
    AutoSeeded_RNG rng;
    SecureVector<byte> bytes = rng.random_vec(baton->bytesLength);
    switch (baton->type) {
      case binary:
        baton->bytes = new SecureVector<byte>(bytes);
        break;
      case base64:
        baton->string = new std::string(base64_encode(bytes));
        break;
      case hex:
        baton->string = new std::string(hex_encode(bytes));
    }
  }
  catch (std::exception &e) {
    baton->error = new std::string(e.what());
  }
}

void rnd::AfterGenerateBytes(uv_work_t *request) {
  GenerateBytesBaton *baton = static_cast<GenerateBytesBaton *>(request->data);

  Handle<Value> error = Null();
  Handle<Value> bytes = Null();

  if (baton->error)
    error = TYPE_ERROR(baton->error->c_str());
  else if (baton->bytes)
    bytes = Buffer::New((char *) baton->bytes->begin(),
      baton->bytes->size())->handle_;
  else if (baton->string)
    bytes = String::New(baton->string->c_str());

  Handle<Value> argv[2] = {error, bytes};

  TryCatch try_catch;
  baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);
  if (try_catch.HasCaught()) FatalException(try_catch);

  delete baton;
  delete request;
}

void init(Handle<Object> target) {
  Botan::LibraryInitializer init("thread_safe=true");

  NODE_SET_METHOD(target, "generateKeys", pk::Generate);
  NODE_SET_METHOD(target, "loadPublicKey", pk::LoadPublicKey);
  NODE_SET_METHOD(target, "loadPrivateKey", pk::LoadPrivateKey);
  NODE_SET_METHOD(target, "encrypt", cipher::Encrypt);
  NODE_SET_METHOD(target, "decrypt", cipher::Decrypt);
  NODE_SET_METHOD(target, "initialiseEncryptor", cipher::InitialiseEncryptor);
  NODE_SET_METHOD(target, "initialiseDecryptor", cipher::InitialiseDecryptor);
  NODE_SET_METHOD(target, "encodeSync", codec::EncodeSync);
  NODE_SET_METHOD(target, "encode", codec::Encode);
  NODE_SET_METHOD(target, "decodeSync", codec::DecodeSync);
  NODE_SET_METHOD(target, "decode", codec::Decode);
  NODE_SET_METHOD(target, "generateMac", mac::Generate);
  NODE_SET_METHOD(target, "initialiseMac", mac::Initialise);
  NODE_SET_METHOD(target, "generateHash", hash::Generate);
  NODE_SET_METHOD(target, "initialiseHash", hash::Initialise);
  NODE_SET_METHOD(target, "generatePbkdf", pbkdf::Generate);
  NODE_SET_METHOD(target, "generateRandomDigits", rnd::GenerateDigits);
  NODE_SET_METHOD(target, "generateRandomBytes", rnd::GenerateBytes);
}

} // namespace node_botan

NODE_MODULE(botan, node_botan::init);

