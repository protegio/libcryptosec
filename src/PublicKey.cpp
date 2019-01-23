#include <libcryptosec/PublicKey.h>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/pem.h>

PublicKey::PublicKey(EVP_PKEY* evpPkey) : AsymmetricKey(evpPkey)
{
	//TODO: testar se é mesmo uma chave publica
}

PublicKey::PublicKey(const ByteArray& derEncoded) : AsymmetricKey()
{
	BIO *buffer = NULL;
	EVP_PKEY *key = NULL;
	unsigned int numberOfWrittenBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::PublicKey");
	}

	numberOfWrittenBytes = BIO_write(buffer, derEncoded.getConstDataPointer(), derEncoded.getSize());

	if (numberOfWrittenBytes != derEncoded.getSize()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PublicKey::PublicKey");
	}

	key = d2i_PUBKEY_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (key == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "PublicKey::PublicKey");
	}
	BIO_free(buffer);

	this->setEvpPkey(key);
}

PublicKey::PublicKey(const std::string& pemEncoded) : AsymmetricKey()
{
	BIO *buffer = NULL;
	EVP_PKEY *key = NULL;
	unsigned int numberOfWrittenBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::PublicKey");
	}

	numberOfWrittenBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfWrittenBytes != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PublicKey::PublicKey");
	}

	key = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);
	if (key == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "PublicKey::PublicKey");
	}
	BIO_free(buffer);

	this->setEvpPkey(key);
}

PublicKey::~PublicKey()
{
	/* super class is going to destroy the allocated objects */
}

std::string PublicKey::getPemEncoded()
{
	ByteArray *retTemp = NULL;
	BIO *buffer = NULL;
	std::string ret;
	unsigned char *data = NULL;
	int ndata, wrote;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::getPemEncoded");
	}

	wrote = PEM_write_bio_PUBKEY(buffer, this->getEvpPkey());
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "PublicKey::getPemEncoded");
	}

	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PublicKey::getPemEncoded");
	}

	// TODO: Improve this
	retTemp = new ByteArray(data, ndata);	// Copy buffer's data to a ByteArray
	BIO_free(buffer);  						// Free buffer
	ret = retTemp->toString();				// Convert to string
	delete retTemp;							// Free ByteArray

	return ret;
}

ByteArray* PublicKey::getDerEncoded()
{
	ByteArray *ret = NULL;
	BIO *buffer = NULL;
	unsigned char *data = NULL;
	int ndata, wrote;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::getDerEncoded");
	}

	wrote = i2d_PUBKEY_bio(buffer, this->evpPkey);
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "PublicKey::getDerEncoded");
	}

	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PublicKey::getDerEncoded");
	}

	ret = new ByteArray(data, ndata);	// Copy buffer's data to a ByteArray
	BIO_free(buffer);					// Free buffer

	return ret;
}

ByteArray* PublicKey::getKeyIdentifier()
{
	throw std::exception();
/*  TODO: como transformar a chave em um array de bits?
	ByteArray ret;
	unsigned int size;
	X509_PUBKEY *pubkey = NULL;
	
	if(X509_PUBKEY_set(&pubkey, this->key) == 0)
	{
		throw EncodeException(EncodeException::UNKNOWN, "PublicKey::getKeyIdentifier");
	}
			
	ret = ByteArray(EVP_MAX_MD_SIZE);
	EVP_Digest(pubkey->public_key->data, pubkey->public_key->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);
	ret = ByteArray(ret.getDataPointer(), size);

	X509_PUBKEY_free(pubkey);
	
	return ret;
*/
	//return ByteArray(digest, digestLen);

	/*	ByteArray der = this->getDerEncoded();
	MessageDigest md(MessageDigest::SHA1);
	
	MessageDigest::loadMessageDigestAlgorithms();
	
	return md.doFinal(der);*/
}
