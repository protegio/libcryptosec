#include <libcryptosec/RSAPublicKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

RSAPublicKey::RSAPublicKey(const EVP_PKEY *key) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::RSAPublicKey(ByteArray &derEncoded) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::RSAPublicKey(std::string &pemEncoded)	 : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::~RSAPublicKey()
{
}
