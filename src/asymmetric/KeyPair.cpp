#include <libcryptosec/asymmetric/KeyPair.h>

#include <libcryptosec/asymmetric/RSAPrivateKey.h>
#include <libcryptosec/asymmetric/DSAPrivateKey.h>
#include <libcryptosec/asymmetric/ECDSAPrivateKey.h>
#include <libcryptosec/asymmetric/RSAPublicKey.h>
#include <libcryptosec/asymmetric/DSAPublicKey.h>
#include <libcryptosec/asymmetric/ECDSAPublicKey.h>
#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/OperationException.h>
#include <libcryptosec/Macros.h>

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>

#include <string.h>

KeyPair::KeyPair() :
	key(nullptr), keyId(), engine(nullptr)
{
}

//TODO Este construtor deve é obsoleto. Devem ser usados os construtores das classes especializadas RSAKeyPair, DSAKeyPair e ECDSAKeyPair
KeyPair::KeyPair(AsymmetricKey::Algorithm algorithm, int length) :
		key(nullptr), keyId(), engine(nullptr)
{
	RSA *rsa = NULL;
	BIGNUM *rsa_f4 = NULL;
	DSA *dsa = NULL;

	switch (algorithm)
	{
		case AsymmetricKey::RSA:
			rsa = RSA_new();
			rsa_f4 = BN_new();
			BN_is_word(rsa_f4, RSA_F4);
			if (RSA_generate_key_ex(rsa, length, rsa_f4, NULL) == 0)
			{
				BN_free(rsa_f4);
				break;
			}
			BN_free(rsa_f4);
			this->key = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(this->key, rsa);
			break;
		case AsymmetricKey::DSA:
			dsa = DSA_new();
			if (DSA_generate_parameters_ex(dsa, length, NULL, 0, NULL, NULL, NULL) == 0)
			{
				break;
			}
			if (DSA_generate_key(dsa) == 0)
			{
				break;
			}
			this->key = EVP_PKEY_new();
			EVP_PKEY_assign_DSA(this->key, dsa);
			break;
		case AsymmetricKey::EC:
			break;
	}
	THROW_OPERATION_ERROR_IF(this->key == NULL);
}

KeyPair::KeyPair(const Engine& engine, const std::string& keyId) :
		keyId(keyId), engine(engine)
{
	// TODO: esse cast é ok?
	ENGINE *eng = (ENGINE*) this->engine.getEngine();

	if (!ENGINE_init(eng)) {
		throw EngineException(EngineException::INIT_FAILED, "KeyPair::KeyPair", true);
	}

	// TODO: rever essa questão do User Interface UI_OpenSSL();
	// this->key = ENGINE_load_public_key(eng, keyId.c_str(), UI_OpenSSL(), NULL);
	this->key = ENGINE_load_private_key(eng, keyId.c_str(), NULL, NULL);
	ENGINE_finish(eng);
	if (!this->key) {
		throw EngineException(EngineException::KEY_NOT_FOUND, "KeyPair::KeyPair", true);
	}
}

KeyPair::KeyPair(const std::string& pemEncoded, const ByteArray& passphrase) :
		engine(nullptr)
{
	BIO *buffer = NULL;
	unsigned int numberOfBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException("KeyPair::KeyPair");
	}

	numberOfBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfBytes != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException("KeyPair::KeyPair");
	}

	this->key = PEM_read_bio_PrivateKey(buffer, NULL, KeyPair::passphraseCallBack, (void *)&passphrase);
	if (this->key == NULL) {
		BIO_free(buffer);
		/* TODO: how to know if is the passphrase wrong ??? */
		throw EncodeException("KeyPair::KeyPair");
	}

	BIO_free(buffer);
}

KeyPair::KeyPair(const std::string& pemEncoded) :
		engine(nullptr)
{
	DECODE_PEM(this->key, pemEncoded, PEM_read_bio_PrivateKey);
}

KeyPair::KeyPair(const ByteArray& derEncoded) :
		engine(nullptr)
{
	DECODE_DER(this->key, derEncoded, d2i_PrivateKey_bio);
}

KeyPair::KeyPair(const KeyPair &keyPair) :
		key(keyPair.key),
		keyId(keyPair.keyId),
		engine(keyPair.engine)
{
	if (this->key) {
		EVP_PKEY_up_ref(this->key);
	}
}

KeyPair::KeyPair(KeyPair&& keyPair) :
		key(keyPair.key),
		keyId(keyPair.keyId),
		engine(keyPair.engine)
{
	keyPair.key = nullptr;
	keyPair.engine = nullptr;
}

KeyPair::~KeyPair()
{
	if (this->key) {
		EVP_PKEY_free(this->key);
		this->key = NULL;
	}
}

KeyPair& KeyPair::operator=(const KeyPair& keyPair) {
	if (&keyPair == this) {
		return *this;
	}

	this->key = keyPair.key;
	EVP_PKEY_up_ref(this->key);
	this->keyId = keyPair.keyId;
	this->engine = keyPair.engine;

	return *this;
}

KeyPair& KeyPair::operator=(KeyPair&& keyPair) {
	if (&keyPair == this) {
		return *this;
	}

	this->key = std::move(keyPair.key);
	this->keyId = std::move(keyPair.keyId);
	this->engine = std::move(keyPair.engine);

	keyPair.key = nullptr;

	return *this;
}

PublicKey* KeyPair::getPublicKey() const
{
	std::string keyTemp = this->getPublicKeyPemEncoded();
	switch (this->getAlgorithm()) {
	case AsymmetricKey::RSA:
		return new RSAPublicKey(keyTemp);
	case AsymmetricKey::DSA:
		return new DSAPublicKey(keyTemp);
	case AsymmetricKey::EC:
		return new ECDSAPublicKey(keyTemp);
	}

	THROW_DECODE_ERROR_IF(true);
}

PrivateKey* KeyPair::getPrivateKey() const
{
	EVP_PKEY *pkey = NULL;

	if (this->engine.getEngine()) {
		pkey = ENGINE_load_private_key((ENGINE*) this->engine.getEngine(), this->keyId.c_str(), NULL, NULL);
		THROW_DECODE_ERROR_IF(pkey == NULL);

		try {
			return new PrivateKey(pkey);
		} catch (...) {
			EVP_PKEY_free(pkey);
			throw;
		}
	} else {
		switch (this->getAlgorithm())
		{
			case AsymmetricKey::RSA:
				return new RSAPrivateKey(this->key);
			case AsymmetricKey::DSA:
				return new DSAPrivateKey(this->key);
			case AsymmetricKey::EC:
				return new ECDSAPrivateKey(this->key);
		}
		THROW_DECODE_ERROR_IF(true);
	}
}

std::string KeyPair::getPemEncoded(const EVP_CIPHER* cipher, const ByteArray* passphraseData) const
{
	ENCODE_ENCRYPTED_PEM_AND_RETURN(
			this->key,
			PEM_write_bio_PrivateKey,
			cipher,
			(cipher ? KeyPair::passphraseCallBack : NULL),
			(cipher ? (void *) passphraseData : NULL)
	);
}

std::string KeyPair::getPemEncoded(const SymmetricKey& passphrase, SymmetricCipher::OperationMode mode) const
{
	const EVP_CIPHER *cipher = NULL;

	try {
		cipher = SymmetricCipher::getCipher(passphrase.getAlgorithm(), mode);
	} catch (...) {
		throw;
	}

	const ByteArray& passphraseData = passphrase.getEncoded();
	return this->getPemEncoded(cipher, &passphraseData);
}

std::string KeyPair::getPemEncoded() const
{
	return this->getPemEncoded(NULL, NULL);
}

ByteArray KeyPair::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->key, i2d_PrivateKey_bio);
}

AsymmetricKey::Algorithm KeyPair::getAlgorithm() const
{
	AsymmetricKey::Algorithm type;

	switch (EVP_PKEY_base_id(this->key))
	{
		case EVP_PKEY_RSA: /* TODO: confirmar porque tem estes dois tipos */
		case EVP_PKEY_RSA2:
			type = AsymmetricKey::RSA;
			break;
		case EVP_PKEY_DSA: /* TODO: confirmar porque tem estes quatro tipos. São mesmo diferentes ??? */
		case EVP_PKEY_DSA1:
		case EVP_PKEY_DSA2:
		case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			type = AsymmetricKey::DSA;
			break;
		case EVP_PKEY_EC:
			type = AsymmetricKey::EC;
			break;
		default:
			THROW_DECODE_ERROR_IF(true);
	}
	return type;
}

int KeyPair::getSize() const
{
	int ret = 0;

	/* TODO: this function will be right only for RSA, DSA and EC.
	 * The others algorithms (DH) must be used individual functions
	 */
	ret = EVP_PKEY_size(this->key);
	THROW_DECODE_ERROR_IF(ret == 0);
	return ret;
}

int KeyPair::getSizeBits() const
{
	int ret = 0;

	/* TODO: this function will be right only for RSA, DSA and EC.
	 * The others algorithms (DH) must be used individual functions
	 */
	ret = EVP_PKEY_bits(this->key);
	THROW_DECODE_ERROR_IF(ret == 0);
	return ret;
}

int KeyPair::passphraseCallBack(char *buf, int size, int rwflag, void *u)
{
    ByteArray* passphrase = (ByteArray*) u;
    int length = passphrase->getSize();
    if (length > 0) {
        if (length > size) {
            length = size;
        }
        memcpy(buf, passphrase->getConstDataPointer(), length);
    }
    return length;
}

std::string KeyPair::getPublicKeyPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->key, PEM_write_bio_PUBKEY);
}

const EVP_PKEY* KeyPair::getEvpPkey() const
{
	return this->key;
}
		
const Engine& KeyPair::getEngine() const
{
	return this->engine;
}
	
const std::string& KeyPair::getKeyId() const
{
	return this->keyId;
}
