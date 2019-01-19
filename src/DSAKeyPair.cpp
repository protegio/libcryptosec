#include <libcryptosec/DSAKeyPair.h>

#include <openssl/crypto.h>

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
	if (this->key)
	{
		EVP_PKEY_free(this->key);
		this->key = NULL;
	}
	if (this->engine)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
	}
}

PublicKey* DSAKeyPair::getPublicKey()
{
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new DSAPublicKey(keyTemp);
	return ret;
}

PrivateKey* DSAKeyPair::getPrivateKey()
{
	PrivateKey *ret;
	EVP_PKEY *pkey;
	ret = NULL;
	if (engine)
	{
		pkey = ENGINE_load_private_key(this->engine, this->keyId.c_str(), NULL, NULL);
		if (!pkey)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "DSAKeyPair::getPrivateKey");
		}
		try
		{
			ret = new PrivateKey(pkey);
		}
		catch (...)
		{
			EVP_PKEY_free(pkey);
			throw;
		}
	}
	else
	{
		ret = new DSAPrivateKey(this->key);
		if (ret == NULL)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAKeyPair::getPrivateKey");
		}
		EVP_PKEY_up_ref(this->key);
	}
	return ret;
}

AsymmetricKey::Algorithm DSAKeyPair::getAlgorithm()
{
	return AsymmetricKey::DSA;
}
