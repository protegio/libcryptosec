#include <libcryptosec/DSAPrivateKey.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

DSAPrivateKey::DSAPrivateKey(const EVP_PKEY *key) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::DSAPrivateKey(const ByteArray &derEncoded) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}
DSAPrivateKey::DSAPrivateKey(const std::string& pemEncoded) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::DSAPrivateKey(const std::string& pemEncoded, const ByteArray& passphrase) : PrivateKey (pemEncoded, passphrase)
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
