#include <libcryptosec/AsymmetricKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

#include <openssl/bio.h>

AsymmetricKey::AsymmetricKey()
	: evpPkey(NULL)
{
}

AsymmetricKey::AsymmetricKey(EVP_PKEY *evpPkey)
	: evpPkey(evpPkey)
{
	if (evpPkey == NULL) {
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "AsymmetricKey::AsymmetricKey");
	}

	this->evpPkey = evpPkey;
	EVP_PKEY_up_ref(this->evpPkey);

	// Checks if it's a asymmetric key and throws an exception otherwise
	this->getAlgorithm();
}

AsymmetricKey::~AsymmetricKey()
{
	if (this->evpPkey) {
		EVP_PKEY_free(this->evpPkey);
	}
}

void AsymmetricKey::setEvpPkey(EVP_PKEY* evpPkey) {

	if (evpPkey == NULL) {
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE,
				"AsymmetricKey::AsymmetricKey");
	}

	if (this->evpPkey != NULL) {
		EVP_PKEY_free(this->evpPkey);
	}

	this->evpPkey = evpPkey;
	EVP_PKEY_up_ref(evpPkey);

	// Checks if it's a asymmetric key and throws an exception otherwise
	this->getAlgorithm();
}

AsymmetricKey::Algorithm AsymmetricKey::getAlgorithm()
{
	AsymmetricKey::Algorithm type;
	switch (EVP_PKEY_base_id(this->evpPkey))
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
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "AsymmetricKey::getAlgorithm");
	}
	return type;
}

int AsymmetricKey::getSize()
{
	int ret = EVP_PKEY_size(this->evpPkey);
	if (ret == 0) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "AsymmetricKey::getSize");
	}
	return ret;
}

int AsymmetricKey::getSizeBits()
{
	int ret = EVP_PKEY_bits(this->evpPkey);
	if (ret == 0) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "AsymmetricKey::getSizeBits");
	}
	return ret;
}

EVP_PKEY* AsymmetricKey::getEvpPkey()
{
	return this->evpPkey;
}

bool AsymmetricKey::operator==(AsymmetricKey& key) throw()
{
	return EVP_PKEY_cmp(this->evpPkey, key.evpPkey) == 0;
}



