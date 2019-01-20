#include <libcryptosec/RSAKeyPair.h>

RSAKeyPair::RSAKeyPair(int length)
{
	RSA *rsa = NULL;
	BIGNUM *rsa_f4 = NULL;
	this->key = NULL;
	this->engine = NULL;

	rsa = RSA_new();
	if (!rsa)
		goto err0;

	rsa_f4 = BN_new();
	if (!rsa_f4)
		goto err1;

	if(BN_set_word(rsa_f4, RSA_F4) == 0)
		goto err2;

	if (RSA_generate_key_ex(rsa, length, rsa_f4, NULL) == 0)
		goto err2;

	this->key = EVP_PKEY_new();
	if (!this->key)
		goto err2;

	if(EVP_PKEY_assign_RSA(this->key, rsa) == 0)
		goto err3;

	return;

err3:
	EVP_PKEY_free(this->key);
	this->key = 0;

err2:
	BN_free(rsa_f4);

err1:
	RSA_free(rsa);

err0:
	throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "RSAKeyPair::RSAKeyPair");
}

RSAKeyPair::~RSAKeyPair()
{
	if (this->key) {
		EVP_PKEY_free(this->key);
		this->key = NULL;
	}

	if (this->engine) {
		ENGINE_free(this->engine);
		this->engine = NULL;
	}
}

PublicKey* RSAKeyPair::getPublicKey()
{
	PublicKey *ret = NULL;
	std::string keyTemp;

	// TODO: that's a lasy method to create a RSAPublicKey object
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new RSAPublicKey(keyTemp);

	return ret;
}

PrivateKey* RSAKeyPair::getPrivateKey()
{
	PrivateKey *ret = NULL;
	EVP_PKEY *pkey = NULL;

	if (this->engine) {
		pkey = ENGINE_load_private_key(this->engine, this->keyId.c_str(), NULL, NULL);
		if (!pkey) {
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "RSAKeyPair::getPrivateKey");
		}

		try	{
			ret = new PrivateKey(pkey);
		} catch (...) {
			EVP_PKEY_free(pkey);
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "RSAKeyPair::getPrivateKey");
		}
	} else {
		ret = new RSAPrivateKey(this->key);
		if (ret == NULL) {
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAKeyPair::getPrivateKey");
		}

		// TODO: shouldn't the EVP_PKEY_up_ref be in the PrivateKey class?
		EVP_PKEY_up_ref(this->key);
	}

	return ret;
}

AsymmetricKey::Algorithm RSAKeyPair::getAlgorithm()
{
	return AsymmetricKey::RSA;
}
