#include <libcryptosec/asymmetric/AsymmetricKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/Macros.h>

#include <openssl/bio.h>

AsymmetricKey::AsymmetricKey()
	: evpPkey(NULL)
{
}

AsymmetricKey::AsymmetricKey(const EVP_PKEY *evpPkey)
	: evpPkey((EVP_PKEY*) evpPkey)
{
	THROW_DECODE_ERROR_IF(this->evpPkey == NULL);

	int rc = EVP_PKEY_up_ref(this->evpPkey);
	THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
			this->evpPkey = NULL;
	);

	// Checks if it's a asymmetric key and throws an exception if it's not.
	this->getAlgorithm();
}

AsymmetricKey::~AsymmetricKey()
{
	if (this->evpPkey) {
		EVP_PKEY_free(this->evpPkey);
	}
}

void AsymmetricKey::setEvpPkey(const EVP_PKEY* evpPkey)
{
	THROW_ENCODE_ERROR_IF(evpPkey == NULL);

	int rc = EVP_PKEY_up_ref((EVP_PKEY*) evpPkey);
	THROW_ENCODE_ERROR_IF(rc == 0);

	if (this->evpPkey != NULL) {
		EVP_PKEY_free(this->evpPkey);
	}

	this->evpPkey = (EVP_PKEY*) evpPkey;

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
			THROW_DECODE_ERROR_IF(true);
	}
	return type;
}

int AsymmetricKey::getSize() const
{
	int ret = EVP_PKEY_size(this->evpPkey);
	THROW_DECODE_ERROR_IF(ret == 0);
	return ret;
}

int AsymmetricKey::getSizeBits() const
{
	int ret = EVP_PKEY_bits(this->evpPkey);
	THROW_DECODE_ERROR_IF(ret == 0);
	return ret;
}

EVP_PKEY* AsymmetricKey::getSslObject() const
{
	int rc = EVP_PKEY_up_ref(this->evpPkey);
	THROW_ENCODE_ERROR_IF(rc == 0);
	return this->evpPkey;
}

const EVP_PKEY* AsymmetricKey::getEvpPkey() const
{
	return this->evpPkey;
}

bool AsymmetricKey::operator==(const AsymmetricKey& key) const
{
	return EVP_PKEY_cmp(this->evpPkey, key.evpPkey) == 0;
}



