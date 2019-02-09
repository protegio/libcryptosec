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
	EVP_PKEY *key = NULL;
	BIO *buffer = NULL;
	unsigned int numberOfWrittenBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	THROW_DECODE_ERROR_IF(buffer == NULL);

	numberOfWrittenBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	THROW_DECODE_ERROR_AND_FREE_IF(numberOfWrittenBytes != pemEncoded.size(),
			BIO_free_all(buffer);
	);

	key = PEM_read_bio_PrivateKey(buffer, NULL, PrivateKey::passphraseCallBack, (void *) &passphrase);
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
	unsigned char *data = NULL;

	BIO *buffer = BIO_new(BIO_s_mem());
	THROW_ENCODE_ERROR_IF(buffer == NULL);

	int wrote = PEM_write_bio_PrivateKey(buffer, this->evpPkey, NULL, NULL, 0, NULL, NULL);
	THROW_ENCODE_ERROR_AND_FREE_IF(wrote <= 0,
			BIO_free_all(buffer);
	);

	int ndata = BIO_get_mem_data(buffer, &data);
	THROW_ENCODE_ERROR_AND_FREE_IF(ndata <= 0,
			BIO_free_all(buffer);
	);

	// TODO: improve this
	ByteArray retTemp(data, ndata);
	std::string ret = retTemp.toString();

	BIO_free_all(buffer);

	return ret;
}

std::string PrivateKey::getPemEncoded(const SymmetricKey& symmetricKey, SymmetricCipher::OperationMode mode) const
{
	const EVP_CIPHER *cipher = NULL;
	unsigned char *data = NULL;

	BIO *buffer = BIO_new(BIO_s_mem());
	THROW_ENCODE_ERROR_IF(buffer == NULL);

	try {
		cipher = SymmetricCipher::getCipher(symmetricKey.getAlgorithm(), mode);
	} catch (...) {
		BIO_free_all(buffer);
		throw;
	}

	const ByteArray& passphraseData = symmetricKey.getEncoded();
	int wrote = PEM_write_bio_PrivateKey(buffer, this->evpPkey, cipher, NULL, 0, PrivateKey::passphraseCallBack, (void *) &passphraseData);
	THROW_ENCODE_ERROR_AND_FREE_IF(wrote <= 0,
			BIO_free_all(buffer);
	);

	int ndata = BIO_get_mem_data(buffer, &data);
	THROW_ENCODE_ERROR_AND_FREE_IF(ndata <= 0,
			BIO_free_all(buffer);
	);

	// TODO: improve this
	ByteArray retTemp(data, ndata);
	std::string ret = retTemp.toString();

	BIO_free_all(buffer);

	return ret;
}

ByteArray PrivateKey::getDerEncoded() const
{
	unsigned char *data = 0;

	BIO *buffer = BIO_new(BIO_s_mem());
	THROW_ENCODE_ERROR_IF(buffer == NULL);

	int wrote = i2d_PrivateKey_bio(buffer, this->evpPkey);
	THROW_ENCODE_ERROR_AND_FREE_IF(wrote <= 0,
			BIO_free_all(buffer);
	);

	int ndata = BIO_get_mem_data(buffer, &data);
	THROW_ENCODE_ERROR_AND_FREE_IF(ndata <= 0,
			BIO_free_all(buffer);
	);

	ByteArray ret(data, ndata);
	BIO_free_all(buffer);

	return ret;
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
