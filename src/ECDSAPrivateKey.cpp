#include <libcryptosec/ECDSAPrivateKey.h>

ECDSAPrivateKey::ECDSAPrivateKey(EVP_PKEY *key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::ECDSAPrivateKey(ByteArray &derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}
ECDSAPrivateKey::ECDSAPrivateKey(std::string &pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::ECDSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase) : PrivateKey (pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::~ECDSAPrivateKey()
{
}
