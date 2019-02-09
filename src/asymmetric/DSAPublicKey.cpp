#include <libcryptosec/asymmetric/DSAPublicKey.h>

#include <libcryptosec/exception/AsymmetricKeyException.h>

DSAPublicKey::DSAPublicKey(const EVP_PKEY *key) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPublicKey::DSAPublicKey");
	}
}

DSAPublicKey::DSAPublicKey(ByteArray &derEncoded) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPublicKey::DSAPublicKey");
	}
}

DSAPublicKey::DSAPublicKey(std::string &pemEncoded) : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPublicKey::DSAPublicKey");
	}
}

DSAPublicKey::~DSAPublicKey()
{
}
