#include <libcryptosec/PrivateKey.h>

PrivateKey::PrivateKey(EVP_PKEY *key) : AsymmetricKey(key)
{
}

PrivateKey::PrivateKey(const ByteArray &derEncoded) : AsymmetricKey()
{
	/* DER format support only RSA, DSA and EC. DH isn't supported */
	EVP_PKEY *key = NULL;
	BIO *buffer = NULL;
	unsigned int numberOfWrittenBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::PrivateKey");
	}

	numberOfWrittenBytes = BIO_write(buffer, derEncoded.getConstDataPointer(), derEncoded.getSize());
	if (numberOfWrittenBytes != derEncoded.getSize()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PrivateKey::PrivateKey");
	}

	/* TODO: will the second parameter work fine ? */
	key = d2i_PrivateKey_bio(buffer, NULL);
	if (key == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "PrivateKey::PrivateKey");
	}
	BIO_free(buffer);

	this->setEvpPkey(key);
}

PrivateKey::PrivateKey(const std::string &pemEncoded) : AsymmetricKey()
{
	EVP_PKEY *key = NULL;
	BIO *buffer = NULL;
	unsigned int numberOfWrittenBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::PrivateKey");
	}

	numberOfWrittenBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfWrittenBytes != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PrivateKey::PrivateKey");
	}

	key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);
	if (key == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "PrivateKey::PrivateKey");
	}
	BIO_free(buffer);

	this->setEvpPkey(key);
}

PrivateKey::PrivateKey(const std::string& pemEncoded, const ByteArray& passphrase) : AsymmetricKey()
{
	EVP_PKEY *key = NULL;
	BIO *buffer = NULL;
	unsigned int numberOfWrittenBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::PrivateKey");
	}

	numberOfWrittenBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfWrittenBytes != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PrivateKey::PrivateKey");
	}

	key = PEM_read_bio_PrivateKey(buffer, NULL, PrivateKey::passphraseCallBack, (void *)&passphrase);
	if (key == NULL) {
		BIO_free(buffer);
		/* TODO: how to know if is the passphrase wrong ??? */
		throw EncodeException(EncodeException::PEM_DECODE, "PrivateKey::PrivateKey");
	}
	BIO_free(buffer);

	this->setEvpPkey(key);
}

PrivateKey::~PrivateKey()
{
}

std::string PrivateKey::getPemEncoded()
{
	ByteArray *retTemp = NULL;
	BIO *buffer = NULL;
	std::string ret;
	unsigned char *data = NULL;
	int ndata = 0, wrote = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::getPemEncoded");
	}

	wrote = PEM_write_bio_PrivateKey(buffer, this->evpPkey, NULL, NULL, 0, NULL, NULL);
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "PrivateKey::getPemEncoded");
	}

	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PrivateKey::getPemEncoded");
	}

	// TODO: improve this
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;

	BIO_free(buffer);

	return ret;
}

std::string PrivateKey::getPemEncoded(const SymmetricKey& symmetricKey, SymmetricCipher::OperationMode mode)
{
	ByteArray *retTemp = NULL;
	const ByteArray *passphraseData = NULL;
	BIO *buffer = NULL;
	const EVP_CIPHER *cipher = NULL;
	unsigned char *data = NULL;
	int ndata = 0, wrote = 0;
	std::string ret;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::getPemEncoded");
	}

	try {
		cipher = SymmetricCipher::getCipher(symmetricKey.getAlgorithm(), mode);
	} catch (...) {
		BIO_free(buffer);
		throw;
	}

	passphraseData = symmetricKey.getEncoded();
	wrote = PEM_write_bio_PrivateKey(buffer, this->evpPkey, cipher, NULL, 0,
			PrivateKey::passphraseCallBack, (void *) passphraseData);

	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "PrivateKey::getPemEncoded");
	}

	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PrivateKey::getPemEncoded");
	}

	// TODO: improve this
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;

	BIO_free(buffer);

	return ret;
}

ByteArray* PrivateKey::getDerEncoded()
{
	ByteArray *ret = NULL;
	BIO *buffer = NULL;
	int ndata = 0, wrote = 0;
	unsigned char *data = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::getDerEncoded");
	}

	wrote = i2d_PrivateKey_bio(buffer, this->evpPkey);
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "PrivateKey::getDerEncoded");
	}

	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PrivateKey::getDerEncoded");
	}

	ret = new ByteArray(data, ndata);
	BIO_free(buffer);

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
