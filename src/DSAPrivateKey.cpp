#include <libcryptosec/DSAPrivateKey.h>

DSAPrivateKey::DSAPrivateKey(EVP_PKEY *key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::DSAPrivateKey(ByteArray &derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}
DSAPrivateKey::DSAPrivateKey(std::string &pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::DSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase) : PrivateKey (pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::~DSAPrivateKey()
{
}
