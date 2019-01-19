#include <libcryptosec/RSAPrivateKey.h>

RSAPrivateKey::RSAPrivateKey(EVP_PKEY *key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::RSAPrivateKey(ByteArray &derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}
RSAPrivateKey::RSAPrivateKey(std::string &pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::RSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase) : PrivateKey(pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::~RSAPrivateKey()
{
}
