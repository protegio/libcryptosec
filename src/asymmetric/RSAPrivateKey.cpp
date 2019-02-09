#include <libcryptosec/asymmetric/RSAPrivateKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/DecodeException.h>

RSAPrivateKey::RSAPrivateKey(const EVP_PKEY* key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}

RSAPrivateKey::RSAPrivateKey(const ByteArray& derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}
RSAPrivateKey::RSAPrivateKey(const std::string& pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}

RSAPrivateKey::RSAPrivateKey(const std::string& pemEncoded, const ByteArray& passphrase) : PrivateKey(pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	THROW_DECODE_ERROR_IF(algorithm != AsymmetricKey::RSA);
}

RSAPrivateKey::~RSAPrivateKey()
{
}
