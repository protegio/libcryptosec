#include <libcryptosec/asymmetric/RSAPublicKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/Macros.h>

RSAPublicKey::RSAPublicKey(const EVP_PKEY *key) :
		PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}

RSAPublicKey::RSAPublicKey(const ByteArray& derEncoded) :
		PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}

RSAPublicKey::RSAPublicKey(const std::string& pemEncoded) :
		PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}

RSAPublicKey::~RSAPublicKey()
{
}
