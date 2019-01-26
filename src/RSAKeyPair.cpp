#include <libcryptosec/RSAKeyPair.h>

#include <libcryptosec/exception/AsymmetricKeyException.h>

#include <openssl/evp.h>

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
}

AsymmetricKey::Algorithm RSAKeyPair::getAlgorithm() const
{
	return AsymmetricKey::RSA;
}
