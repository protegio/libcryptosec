#include <libcryptosec/RSAPrivateKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

RSAPrivateKey::RSAPrivateKey(EVP_PKEY* key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::RSAPrivateKey(const ByteArray& derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}
RSAPrivateKey::RSAPrivateKey(const std::string& pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::RSAPrivateKey(const std::string& pemEncoded, const ByteArray& passphrase) : PrivateKey(pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::~RSAPrivateKey()
{
}
