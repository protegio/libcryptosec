#include <libcryptosec/asymmetric/RSAKeyPair.h>

#include <libcryptosec/exception/OperationException.h>

#include <openssl/evp.h>

RSAKeyPair::RSAKeyPair(int length)
{
	this->key = NULL;
	this->engine = NULL;

	RSA *rsa = RSA_new();
	THROW_OPERATION_ERROR_IF(rsa == NULL);

	BIGNUM *rsa_f4 = BN_new();
	THROW_OPERATION_ERROR_AND_FREE_IF(rsa_f4 == NULL,
			RSA_free(rsa);
	);

	int rc = BN_set_word(rsa_f4, RSA_F4);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			RSA_free(rsa);
			BN_free(rsa_f4);
	);

	rc = RSA_generate_key_ex(rsa, length, rsa_f4, NULL);
	BN_free(rsa_f4);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			RSA_free(rsa);
	);

	this->key = EVP_PKEY_new();
	THROW_OPERATION_ERROR_AND_FREE_IF(this->key == NULL,
			RSA_free(rsa);
	);

	rc = EVP_PKEY_assign_RSA(this->key, rsa);
	THROW_OPERATION_ERROR_AND_FREE_IF(this->key == NULL,
			RSA_free(rsa);
			EVP_PKEY_free(this->key);
			this->key = NULL;
	);
}

RSAKeyPair::~RSAKeyPair()
{
}

AsymmetricKey::Algorithm RSAKeyPair::getAlgorithm() const
{
	return AsymmetricKey::RSA;
}
