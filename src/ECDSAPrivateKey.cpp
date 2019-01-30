#include <libcryptosec/ECDSAPrivateKey.h>

#include <libcryptosec/exception/AsymmetricKeyException.h>

ECDSAPrivateKey::ECDSAPrivateKey(const EVP_PKEY* key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::ECDSAPrivateKey(const ByteArray& derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}
ECDSAPrivateKey::ECDSAPrivateKey(const std::string& pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::ECDSAPrivateKey(const std::string& pemEncoded, const ByteArray& passphrase) : PrivateKey (pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::~ECDSAPrivateKey()
{
}
