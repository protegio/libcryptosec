#include <libcryptosec/asymmetric/PublicKey.h>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/DecodeException.h>

#include <openssl/pem.h>

PublicKey::PublicKey(const EVP_PKEY* evpPkey) :
		AsymmetricKey(evpPkey)
{
	//TODO: testar se é mesmo uma chave publica
}

PublicKey::PublicKey(const ByteArray& derEncoded) :
		AsymmetricKey()
{
	EVP_PKEY *key = NULL;
	DECODE_DER(key, derEncoded, d2i_PUBKEY_bio);
	this->setEvpPkey(key);
}

PublicKey::PublicKey(const std::string& pemEncoded) :
		AsymmetricKey()
{
	EVP_PKEY *pkey = NULL;
	DECODE_PEM(pkey, pemEncoded, PEM_read_bio_PUBKEY);
	this->setEvpPkey(pkey);
}

PublicKey::~PublicKey()
{
	/* super class is going to destroy the allocated objects */
}

std::string PublicKey::getPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->evpPkey, PEM_write_bio_PUBKEY);
}

ByteArray PublicKey::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->evpPkey, i2d_PUBKEY_bio);
}

ByteArray PublicKey::getKeyIdentifier() const
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
