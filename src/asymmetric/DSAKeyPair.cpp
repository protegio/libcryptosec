#include <libcryptosec/asymmetric/DSAKeyPair.h>

#include <libcryptosec/exception/AsymmetricKeyException.h>

#include <openssl/dsa.h>
#include <openssl/evp.h>

DSAKeyPair::DSAKeyPair(int length)
{
	DSA *dsa;
	this->key = NULL;
	this->engine = NULL;
	dsa = DSA_new();

	if (DSA_generate_parameters_ex(dsa, length, NULL, 0, NULL, NULL, NULL) == 0)
	{
		DSA_free(dsa);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "DSAKeyPair::DSAKeyPair");
	}

	if (DSA_generate_key(dsa) == 0)
	{
		DSA_free(dsa);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "DSAKeyPair::DSAKeyPair");
	}

	this->key = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(this->key, dsa);

	if (!this->key)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "DSAKeyPair::DSAKeyPair");
	}
}

DSAKeyPair::~DSAKeyPair()
{
}

AsymmetricKey::Algorithm DSAKeyPair::getAlgorithm() const
{
	return AsymmetricKey::DSA;
}
