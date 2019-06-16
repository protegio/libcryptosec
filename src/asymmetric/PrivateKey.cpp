#include <libcryptosec/asymmetric/PrivateKey.h>

#include <libcryptosec/asymmetric/AsymmetricKey.h>
#include <libcryptosec/SymmetricCipher.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/DecodeException.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string>

#include <string.h>

PrivateKey::PrivateKey(const EVP_PKEY *key) :
		AsymmetricKey(key)
{
}

PrivateKey::PrivateKey(const ByteArray &derEncoded) :
		AsymmetricKey()
{
	/* DER format support only RSA, DSA and EC. DH isn't supported */
	EVP_PKEY *key = NULL;
	DECODE_DER(key, derEncoded, d2i_PrivateKey_bio);
	this->setEvpPkey(key);
}

PrivateKey::PrivateKey(const std::string& pemEncoded) : AsymmetricKey()
{
	EVP_PKEY *key = NULL;
	DECODE_PEM(key, pemEncoded, PEM_read_bio_PrivateKey);
	this->setEvpPkey(key);
}

PrivateKey::PrivateKey(const std::string& pemEncoded, const ByteArray& passphrase) :
		AsymmetricKey()
{
	BIO *buffer = BIO_new(BIO_s_mem());
	THROW_DECODE_ERROR_IF(buffer == NULL);

	unsigned int numberOfWrittenBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	THROW_DECODE_ERROR_AND_FREE_IF(numberOfWrittenBytes != pemEncoded.size(),
			BIO_free_all(buffer);
	);

	EVP_PKEY *key = PEM_read_bio_PrivateKey(buffer, NULL, PrivateKey::passphraseCallBack, (void *) &passphrase);
	THROW_DECODE_ERROR_AND_FREE_IF(key == NULL,
			BIO_free_all(buffer);
	);

	BIO_free_all(buffer);
	this->setEvpPkey(key);
}

PrivateKey::~PrivateKey()
{
}

std::string PrivateKey::getPemEncoded() const
{
	ENCODE_ENCRYPTED_PEM_AND_RETURN(this->evpPkey, PEM_write_bio_PrivateKey, NULL, NULL, NULL);
}

// TODO: symmetric key should be a password
std::string PrivateKey::getPemEncoded(const SymmetricKey& symmetricKey, SymmetricCipher::OperationMode mode) const
{
	const EVP_CIPHER *cipher = SymmetricCipher::getCipher(symmetricKey.getAlgorithm(), mode);
	const ByteArray& passphraseData = symmetricKey.getEncoded();
	ENCODE_ENCRYPTED_PEM_AND_RETURN(this->evpPkey, PEM_write_bio_PrivateKey, cipher,
			PrivateKey::passphraseCallBack, (void *) &passphraseData);
}

ByteArray PrivateKey::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->evpPkey, i2d_PrivateKey_bio);
}

int PrivateKey::passphraseCallBack(char *buf, int size, int rwflag, void *u)
{
    ByteArray* passphrase = (ByteArray*) u;
    int length = passphrase->getSize();
    if (length > 0) {
        if (length > size) {
            length = size;
        }
        memcpy(buf, passphrase->getDataPointer(), length);
    }
    return length;
}
