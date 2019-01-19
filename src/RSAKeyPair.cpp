#include <libcryptosec/RSAKeyPair.h>

RSAKeyPair::RSAKeyPair(int length)
{
	RSA *rsa;
	BIGNUM *rsa_f4;
	this->key = NULL;
	this->engine = NULL;
	rsa = RSA_new();
	rsa_f4 = BN_new();
	BN_is_word(rsa_f4, RSA_F4);
	if (RSA_generate_key_ex(rsa, length, rsa_f4, NULL) == 0)
	{
		RSA_free(rsa);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "RSAKeyPair::RSAKeyPair");
	}
	this->key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(this->key, rsa);
	if (!this->key)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "RSAKeyPair::RSAKeyPair");
	}
}

RSAKeyPair::~RSAKeyPair()
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

PublicKey* RSAKeyPair::getPublicKey()
{
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new RSAPublicKey(keyTemp);
	return ret;
}

PrivateKey* RSAKeyPair::getPrivateKey()
{
	PrivateKey *ret;
	EVP_PKEY *pkey;
	ret = NULL;
	if (engine)
	{
		pkey = ENGINE_load_private_key(this->engine, this->keyId.c_str(), NULL, NULL);
		if (!pkey)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "RSAKeyPair::getPrivateKey");
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
		ret = new RSAPrivateKey(this->key);
		if (ret == NULL)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAKeyPair::getPrivateKey");
		}
		EVP_PKEY_up_ref(this->key);
	}
	return ret;
}

AsymmetricKey::Algorithm RSAKeyPair::getAlgorithm()
{
	return AsymmetricKey::RSA;
}
